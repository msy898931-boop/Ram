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
from .shield import Shield, available_packs, check_pack, load_pack

STATIC_DIR = Path(__file__).resolve().parent / "static"
INDEX = STATIC_DIR / "dashboard.html"


class DashboardState:
    """Holds the ledger and exposes the read-only queries the API serves."""

    def __init__(self, ledger_path: str | Path, public_key: bytes | None = None):
        self.ledger_path = Path(ledger_path)
        self.public_key = public_key

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


def make_handler(state: DashboardState):
    class Handler(BaseHTTPRequestHandler):
        server_version = "AXON-Dashboard"

        def log_message(self, *args):  # keep the console quiet by default
            pass

        def _send(self, code: int, body: bytes, content_type: str) -> None:
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, payload: dict, code: int = 200) -> None:
            self._send(code, json.dumps(payload, indent=2).encode(), "application/json")

        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            route = parsed.path.rstrip("/") or "/"
            query = parse_qs(parsed.query)

            try:
                if route == "/":
                    if not INDEX.exists():
                        self._send(500, b"dashboard.html missing", "text/plain")
                        return
                    self._send(200, INDEX.read_bytes(), "text/html; charset=utf-8")
                elif route == "/api/summary":
                    self._json(state.summary())
                elif route == "/api/records":
                    limit = int(query.get("limit", ["500"])[0])
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
            except Exception as exc:  # never take the dashboard down on one bad request
                self._json({"error": str(exc)}, 500)

    return Handler


def serve(
    ledger_path: str | Path,
    host: str = "127.0.0.1",
    port: int = 8080,
    public_key: bytes | None = None,
    block: bool = True,
) -> ThreadingHTTPServer:
    """Start the dashboard. Returns the server so callers can stop it."""
    state = DashboardState(ledger_path, public_key=public_key)
    httpd = ThreadingHTTPServer((host, port), make_handler(state))
    if block:
        httpd.serve_forever()
    else:
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd
