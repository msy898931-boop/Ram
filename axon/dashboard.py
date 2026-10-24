# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 msy898931-boop
# AXON commercial module. See LICENSE-COMMERCIAL. Converts to
# Apache-2.0 four years after publication.
"""AXON dashboard — a live view of the governance layer.

Runs on the standard library alone, like everything else here. It serves a
single page and a small JSON API over a real ledger, so what you see is the
actual audit trail rather than a mock-up:

    GET /                     the dashboard page
    GET /api/summary          cost, risk, integrity, activity, runs
    GET /api/records          the raw ledger records
    GET /api/policies         available Shield packs
    GET /api/shield?pack=...  run the enforcement check for a pack
    GET /api/explain?...      why one action resolves the way it does

Read-only by construction: there is no route that mutates a ledger. The
dashboard is a viewer for the artifact the agent produced, which is the
right shape for something an auditor or an on-call engineer will open.
"""

from __future__ import annotations

import json
import mimetypes
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .core.audit import AuditLedger
from .observe import Observer
from .security.auth import (
    Authenticator,
    AuthError,
    Principal,
    RateLimited,
    RateLimiter,
    ReplayDetected,
    ReplayGuard,
)
from .security.canary import CanarySet
from .security.headers import headers_for
from .security.oidc import OIDCError, OIDCVerifier
from .security.tls import TLSConfig, is_loopback, wrap_server
from .shield import Shield, available_packs, check_pack, load_pack

STATIC_DIR = Path(__file__).resolve().parent / "static"
INDEX = STATIC_DIR / "dashboard.html"


class DashboardState:
    """Holds the ledger and exposes the read-only queries the API serves."""

    def __init__(
        self,
        ledger_path: str | Path,
        public_key: bytes | None = None,
        authenticator: Authenticator | None = None,
        rate_limiter: RateLimiter | None = None,
        replay_guard: ReplayGuard | None = None,
        canaries: CanarySet | None = None,
        oidc: OIDCVerifier | None = None,
        tls: TLSConfig | None = None,
    ):
        self.ledger_path = Path(ledger_path)
        self.public_key = public_key
        # Authentication defaults to *off* only because the default bind is
        # 127.0.0.1. Any non-loopback bind requires a token set, enforced in
        # `serve()` rather than left to the operator's memory.
        self.authenticator = authenticator if authenticator is not None else Authenticator(enabled=False)
        self.oidc = oidc
        self.tls = tls
        self.rate_limiter = rate_limiter if rate_limiter is not None else RateLimiter(capacity=120, refill_per_sec=20.0)
        self.replay_guard = replay_guard if replay_guard is not None else ReplayGuard()
        self.canaries = canaries if canaries is not None else CanarySet()

    @property
    def auth_required(self) -> bool:
        return self.authenticator.enabled or (self.oidc is not None and self.oidc.enabled)

    def _authenticate(self, header: str | None) -> Principal:
        """Layer 1, with federation in front of the local token store.

        A local token is checked first: it is the cheaper path (no JWKS fetch)
        and an operator who minted one expects it to work even when the IdP is
        unreachable. OIDC is the fallback, and only if it is configured.
        """
        if self.authenticator.enabled:
            try:
                return self.authenticator.authenticate(header)
            except AuthError:
                if self.oidc is None or not self.oidc.enabled:
                    raise
        if self.oidc is not None and self.oidc.enabled:
            return self.oidc.authenticate(header)
        raise AuthError("no authenticator is enabled")

    def _observer(self) -> Observer:
        # Re-read on every request so the dashboard reflects a running agent
        # without needing a restart.
        return Observer(AuditLedger(self.ledger_path))

    def summary(self) -> dict:
        return self._observer().summary(self.public_key)

    def records(self, limit: int = 500) -> list[dict]:
        from dataclasses import asdict

        obs = self._observer()
        recs = obs.ledger.records()[-limit:]
        return [asdict(r) for r in recs]

    def shield_check(self, pack: str) -> dict:
        try:
            return {"pack": pack, **check_pack(pack).as_dict()}
        except FileNotFoundError as exc:
            return {"pack": pack, "ok": False, "error": str(exc)}

    def explain(self, actor: str, action: str, target: str, pack: str) -> dict:
        try:
            engine = load_pack(pack)
        except FileNotFoundError:
            return {"error": f"unknown pack '{pack}'"}
        return {"pack": pack, **Shield(engine).explain(actor, action, target)}


def _parse_limit(query: dict, default: int = 500, ceiling: int = 1000) -> int:
    """Clamp a caller-supplied limit instead of trusting it.

    The previous code did `int(...)` on raw input, so `?limit=abc` raised and
    became a 500, and `?limit=999999999` was honoured. Clamping keeps a
    scraper from asking the server to serialise an unbounded number of records
    in one request.
    """
    raw = query.get("limit", [str(default)])[0]
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return default
    return max(1, min(value, ceiling))


def make_handler(state: DashboardState):
    class Handler(BaseHTTPRequestHandler):
        server_version = "AXON-Dashboard"

        def log_message(self, *args):  # keep the console quiet by default
            pass

        def _send(self, code: int, body: bytes, content_type: str,
                  extra: dict | None = None) -> None:
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            # Layer 4: every response carries the hardening headers, including
            # error responses — an injected error page is still a page.
            secure = bool(getattr(self.server, "secure", False))
            for name, value in headers_for(secure).items():
                self.send_header(name, value)
            # Caller-supplied headers must be written before end_headers();
            # sending them afterwards silently drops them.
            for name, value in (extra or {}).items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(body)

        def _json(self, payload: dict, code: int = 200, extra: dict | None = None) -> None:
            self._send(code, json.dumps(payload, indent=2).encode(),
                       "application/json", extra=extra)

        def _authorise(self, route: str, query: dict) -> Principal | None:
            """Layers 1-3, applied before the router.

            Returns the principal, or sends a refusal and returns None. The
            caller must treat None as "response already sent".
            """
            state_ = self.server.state  # type: ignore[attr-defined]

            # Layer 1 — authentication. `/healthz` is the only unauthenticated
            # route: a liveness probe that disclosed the ledger would defeat
            # the point of authenticating the ledger routes.
            if state_.auth_required and route != "/healthz":
                try:
                    principal = state_._authenticate(self.headers.get("Authorization"))
                except (AuthError, OIDCError):
                    # A browser hitting `/` gets a page explaining what is
                    # required; an API client gets JSON. Both refuse.
                    if route == "/" and "text/html" in (self.headers.get("Accept") or ""):
                        self._send(
                            401,
                            b"<!doctype html><meta charset=utf-8>"
                            b"<title>AXON - authentication required</title>"
                            b"<body style=\"font-family:system-ui;max-width:34rem;margin:4rem auto\">"
                            b"<h1>Authentication required</h1>"
                            b"<p>This dashboard exposes the audit ledger, so it is not "
                            b"served anonymously.</p>"
                            b"<p>Send a bearer token:</p>"
                            b"<pre>curl -H 'Authorization: Bearer &lt;token&gt;' "
                            b"/api/summary</pre>"
                            b"<p>Tokens are issued with <code>axon token create</code>.</p>",
                            "text/html; charset=utf-8",
                            extra={"WWW-Authenticate": 'Bearer realm="axon"'},
                        )
                        return None
                    self._json({"error": "unauthorized"}, 401,
                               extra={"WWW-Authenticate": 'Bearer realm="axon"'})
                    return None
            else:
                try:
                    principal = state_._authenticate(self.headers.get("Authorization"))
                except (AuthError, OIDCError):
                    principal = Principal(name="anonymous", role="viewer", scopes=set())

            # Layer 2 — rate limiting, keyed on the authenticated principal so
            # one caller cannot exhaust another's budget.
            try:
                state_.rate_limiter.check(f"principal:{principal.name}")
            except RateLimited as exc:
                self._json({"error": "rate limited", "detail": str(exc)}, 429,
                           extra={"Retry-After": "1"})
                return None

            # Layer 3 — replay defence, when the caller signed the request.
            nonce = self.headers.get("X-AXON-Nonce")
            if nonce:
                stamp = self.headers.get("X-AXON-Timestamp")
                try:
                    timestamp = float(stamp or "")
                except ValueError:
                    self._json({"error": "bad or missing X-AXON-Timestamp"}, 400)
                    return None
                try:
                    state_.replay_guard.check(nonce, timestamp)
                except ReplayDetected as exc:
                    self._json({"error": "replay rejected", "detail": str(exc)}, 409)
                    return None
            return principal

        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            route = parsed.path.rstrip("/") or "/"
            query = parse_qs(parsed.query)

            try:
                if self._authorise(route, query) is None:
                    return

                if route == "/":
                    if not INDEX.exists():
                        self._send(500, b"dashboard.html missing", "text/plain")
                        return
                    self._send(200, INDEX.read_bytes(), "text/html; charset=utf-8")
                elif route == "/api/summary":
                    self._json(state.summary())
                elif route == "/api/records":
                    limit = _parse_limit(query)
                    self._json({"records": state.records(limit)})
                elif route == "/api/policies":
                    self._json({"packs": available_packs()})
                elif route == "/api/shield":
                    pack = query.get("pack", ["production"])[0]
                    self._json(state.shield_check(pack))
                elif route == "/api/explain":
                    self._json(state.explain(
                        query.get("actor", ["*"])[0],
                        query.get("action", [""])[0],
                        query.get("target", [""])[0],
                        query.get("pack", ["production"])[0],
                    ))
                elif route == "/healthz":
                    self._json({"ok": True})
                else:
                    # Serve static assets (css/js) if present, else 404.
                    asset = (STATIC_DIR / route.lstrip("/")).resolve()
                    if asset.is_file() and STATIC_DIR in asset.parents:
                        ctype = mimetypes.guess_type(asset.name)[0] or "application/octet-stream"
                        self._send(200, asset.read_bytes(), ctype)
                    else:
                        self._json({"error": "not found", "path": route}, 404)
            except Exception:  # never take the dashboard down on one bad request
                # The detail is deliberately not echoed: an exception message
                # can name internal paths, and the dashboard is reachable by
                # anyone who holds a token.
                self._json({"error": "internal error"}, 500)

    return Handler


def serve(
    ledger_path: str | Path,
    host: str = "127.0.0.1",
    port: int = 8080,
    public_key: bytes | None = None,
    block: bool = True,
    authenticator: Authenticator | None = None,
    canaries: CanarySet | None = None,
    allow_unauthenticated_public: bool = False,
    secure: bool = False,
    oidc: OIDCVerifier | None = None,
    tls: TLSConfig | None = None,
) -> ThreadingHTTPServer:
    """Start the dashboard. Returns the server so callers can stop it.

    Binding to anything other than loopback *requires* an authenticator. This
    is a deliberate refusal rather than a warning: an operator who exposes the
    audit ledger to the network without a token has a data breach, not a
    misconfiguration, and a printed warning would not have stopped it.

    `secure=True` claims the traffic is encrypted (it controls HSTS and the
    cookie/transport posture). Passing a `TLSConfig` makes that true by
    wrapping the socket here; passing `secure=True` with no `TLSConfig` is
    only honest when TLS is terminated by something in front of us, so the
    caller has to say which one it is.
    """
    loopback = is_loopback(host)
    if not loopback and authenticator is None and oidc is None and not allow_unauthenticated_public:
        raise AuthError(
            f"refusing to bind {host!r} without an authenticator; pass an "
            "Authenticator or an OIDCVerifier, or set "
            "allow_unauthenticated_public=True to override"
        )

    state = DashboardState(
        ledger_path,
        public_key=public_key,
        authenticator=authenticator,
        canaries=canaries,
        oidc=oidc,
        tls=tls,
    )
    httpd = ThreadingHTTPServer((host, port), make_handler(state))
    # The handler reads these off the server; there is one server per state, so
    # this keeps the handler closure-free and the state injectable for tests.
    httpd.state = state  # type: ignore[attr-defined]
    # TLS must be in place before the first connection is accepted, so the
    # wrap happens here rather than after serve_forever starts.
    httpd.secure = bool(secure or tls)  # type: ignore[attr-defined]
    if tls is not None:
        wrap_server(httpd, tls)
    if block:
        httpd.serve_forever()
    else:
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd
