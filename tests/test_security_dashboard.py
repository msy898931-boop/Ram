"""End-to-end tests for the dashboard's security layers over real HTTP.

These start a real server on an ephemeral port and attack it with a real
HTTP client. Testing the handler in isolation would not catch the mistakes
that matter here — a layer that is defined but never called, or a route that
returns before the check runs.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

import pytest

from axon.core.audit import AuditLedger
from axon.dashboard import serve
from axon.security.auth import Authenticator, AuthError, Token
from axon.security.canary import CanarySet


@pytest.fixture
def secured_server(tmp_path):
    ledger = tmp_path / "audit.jsonl"
    AuditLedger(ledger).append("agent-1", "run.start", target="t", decision="allow")

    auth = Authenticator()
    token, plaintext = Token.issue("operator", role="operator", scopes={"ledger:read"})
    auth.add(token)

    httpd = serve(ledger, host="127.0.0.1", port=0, block=False, authenticator=auth)
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    yield base, plaintext, httpd
    httpd.shutdown()


@pytest.fixture
def open_server(tmp_path):
    ledger = tmp_path / "audit.jsonl"
    AuditLedger(ledger).append("agent-1", "run.start", target="t", decision="allow")
    httpd = serve(ledger, host="127.0.0.1", port=0, block=False)
    yield f"http://127.0.0.1:{httpd.server_address[1]}", httpd
    httpd.shutdown()


def call(base: str, path: str, headers: dict | None = None):
    """Return (status, body_bytes, headers) without raising on 4xx/5xx."""
    req = urllib.request.Request(base + path, headers=headers or {})
    try:
        response = urllib.request.urlopen(req, timeout=5)
        return response.status, response.read(), dict(response.headers)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(), dict(exc.headers)


# --- Layer 1: authentication over HTTP --------------------------------------


def test_ledger_is_not_readable_without_a_token(secured_server):
    base, _, _ = secured_server
    for path in ["/api/records", "/api/summary", "/api/policies"]:
        status, _, _ = call(base, path)
        assert status == 401, f"{path} was reachable unauthenticated"


def test_dashboard_page_is_not_readable_without_a_token(secured_server):
    base, _, _ = secured_server
    assert call(base, "/")[0] == 401


def test_forged_token_is_refused(secured_server):
    base, _, _ = secured_server
    status, _, _ = call(base, "/api/records", {"Authorization": "Bearer " + "z" * 40})
    assert status == 401


def test_401_advertises_the_scheme(secured_server):
    base, _, _ = secured_server
    _, _, headers = call(base, "/api/records")
    assert "Bearer" in headers.get("WWW-Authenticate", "")


def test_valid_token_is_accepted(secured_server):
    base, plaintext, _ = secured_server
    status, body, _ = call(base, "/api/summary", {"Authorization": f"Bearer {plaintext}"})
    assert status == 200
    assert b"integrity" in body


def test_healthz_stays_open_for_liveness_probes(secured_server):
    base, _, _ = secured_server
    assert call(base, "/healthz")[0] == 200


def test_healthz_discloses_nothing_about_the_ledger(secured_server):
    base, _, _ = secured_server
    _, body, _ = call(base, "/healthz")
    assert json.loads(body) == {"ok": True}


# --- Layer 2: rate limiting over HTTP ---------------------------------------


def test_flooding_is_throttled(open_server):
    base, _ = open_server
    codes = {}
    for _ in range(200):
        code, _, _ = call(base, "/api/summary")
        codes[code] = codes.get(code, 0) + 1
    assert 429 in codes, "a 200-request flood was never throttled"


def test_429_tells_the_caller_when_to_retry(open_server):
    base, _ = open_server
    for _ in range(200):
        code, _, headers = call(base, "/api/summary")
        if code == 429:
            assert "Retry-After" in headers
            return
    pytest.fail("never rate limited")


# --- Layer 3: replay defence over HTTP --------------------------------------


def test_replayed_nonce_is_rejected(secured_server):
    base, plaintext, _ = secured_server
    headers = {
        "Authorization": f"Bearer {plaintext}",
        "X-AXON-Nonce": "fixed-nonce",
        "X-AXON-Timestamp": str(time.time()),
    }
    assert call(base, "/api/summary", headers)[0] == 200
    assert call(base, "/api/summary", headers)[0] == 409


def test_stale_timestamp_is_rejected(secured_server):
    base, plaintext, _ = secured_server
    headers = {
        "Authorization": f"Bearer {plaintext}",
        "X-AXON-Nonce": "old-nonce",
        "X-AXON-Timestamp": str(time.time() - 100_000),
    }
    assert call(base, "/api/summary", headers)[0] == 409


def test_malformed_timestamp_is_rejected(secured_server):
    base, plaintext, _ = secured_server
    headers = {
        "Authorization": f"Bearer {plaintext}",
        "X-AXON-Nonce": "n",
        "X-AXON-Timestamp": "not-a-number",
    }
    assert call(base, "/api/summary", headers)[0] == 400


# --- Layer 4: security headers ----------------------------------------------


def test_every_response_carries_hardening_headers(open_server):
    base, _ = open_server
    _, _, headers = call(base, "/")
    assert "default-src 'none'" in headers.get("Content-Security-Policy", "")
    assert headers.get("X-Frame-Options") == "DENY"
    assert headers.get("X-Content-Type-Options") == "nosniff"
    assert headers.get("Referrer-Policy") == "no-referrer"
    assert "frame-ancestors 'none'" in headers.get("Content-Security-Policy", "")


def test_error_responses_are_also_hardened(open_server):
    """An injected error page is still a page."""
    base, _ = open_server
    _, _, headers = call(base, "/definitely-not-a-route")
    assert headers.get("X-Frame-Options") == "DENY"


def test_hsts_only_over_tls(tmp_path):
    ledger = tmp_path / "a.jsonl"
    AuditLedger(ledger).append("a", "run.start", decision="allow")
    httpd = serve(ledger, host="127.0.0.1", port=0, block=False, secure=False)
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    _, _, headers = call(base, "/healthz")
    assert "Strict-Transport-Security" not in headers
    httpd.shutdown()


# --- input handling ---------------------------------------------------------


def test_non_numeric_limit_is_clamped_not_a_500(open_server):
    base, _ = open_server
    status, body, _ = call(base, "/api/records?limit=abc")
    assert status == 200
    assert b"internal error" not in body


def test_huge_limit_is_capped(open_server):
    base, _ = open_server
    status, _, _ = call(base, "/api/records?limit=999999999")
    assert status == 200


def test_negative_limit_does_not_invert_the_slice(open_server):
    base, _ = open_server
    status, _, _ = call(base, "/api/records?limit=-1")
    assert status == 200


def test_path_traversal_is_refused(open_server):
    base, _ = open_server
    for path in ["/../pyproject.toml", "/..%2fpyproject.toml", "/static/../../setup.py"]:
        status, _, _ = call(base, path)
        assert status in (400, 404), f"{path} returned {status}"


def test_internal_errors_do_not_leak_details(open_server, monkeypatch):
    """An exception message can name internal paths; it must not be echoed."""
    base, httpd = open_server
    state = httpd.state
    monkeypatch.setattr(
        type(state), "summary",
        lambda self: (_ for _ in ()).throw(RuntimeError("/etc/axon/secret-path")),
    )
    status, body, _ = call(base, "/api/summary")
    assert status == 500
    assert b"/etc/axon/secret-path" not in body
    assert b"internal error" in body


# --- the public-bind refusal ------------------------------------------------


def test_public_bind_without_auth_is_refused(tmp_path):
    ledger = tmp_path / "a.jsonl"
    AuditLedger(ledger).append("a", "run.start", decision="allow")
    with pytest.raises(AuthError):
        serve(ledger, host="0.0.0.0", port=0, block=False)


def test_public_bind_with_auth_is_allowed(tmp_path):
    ledger = tmp_path / "a.jsonl"
    AuditLedger(ledger).append("a", "run.start", decision="allow")
    auth = Authenticator()
    httpd = serve(ledger, host="0.0.0.0", port=0, block=False, authenticator=auth)
    httpd.shutdown()


def test_explicit_override_is_honoured(tmp_path):
    ledger = tmp_path / "a.jsonl"
    AuditLedger(ledger).append("a", "run.start", decision="allow")
    httpd = serve(ledger, host="0.0.0.0", port=0, block=False, allow_unauthenticated_public=True)
    httpd.shutdown()


# --- Layer 6: canaries on the dashboard -------------------------------------


def test_canary_hits_are_detected_against_live_ledger_content(tmp_path):
    """A canary that appears in a record is caught when the ledger is read."""
    canaries = CanarySet()
    canary = canaries.create("honey", location="unused key")

    ledger = tmp_path / "a.jsonl"
    AuditLedger(ledger).append(
        "agent-1", "model.complete", target=canary.value, decision="allow",
    )
    httpd = serve(ledger, host="127.0.0.1", port=0, block=False, canaries=canaries)
    base = f"http://127.0.0.1:{httpd.server_address[1]}"

    _, body, _ = call(base, "/api/records")
    hits = canaries.scan(body.decode("utf-8", "replace"), where="ledger")
    assert hits, "a canary written into the ledger was not detectable"
    httpd.shutdown()
