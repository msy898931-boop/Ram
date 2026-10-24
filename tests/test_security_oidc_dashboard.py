"""End-to-end tests: the dashboard accepting federated (OIDC) tokens.

The unit tests prove the verifier is correct in isolation. These prove the
dashboard actually calls it — the failure this guards against is a verifier
that works perfectly and is never wired into the request path.

A real JWKS is published by a real HTTP server, and tokens are real signed
JWTs, so the whole federation path is exercised rather than stubbed.
"""

from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from axon.core.audit import AuditLedger
from axon.dashboard import serve
from axon.security.auth import Authenticator, Token
from axon.security.oidc import JWKSet, OIDCVerifier

cryptography = pytest.importorskip("cryptography")

from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import padding, rsa  # noqa: E402

ISSUER = "https://idp.example.com"
AUDIENCE = "axon-dashboard"


def _b64(data: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


@pytest.fixture(scope="module")
def rsa_key():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = private.private_numbers().public_numbers
    return private, numbers.n, numbers.e


def _jwk(n: int, e: int, kid: str = "idp-key-1") -> dict:
    return {
        "kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256",
        "n": _b64(n.to_bytes((n.bit_length() + 7) // 8, "big")),
        "e": _b64(e.to_bytes((e.bit_length() + 7) // 8, "big")),
    }


def make_token(private, claims: dict, kid: str = "idp-key-1") -> str:
    header = {"alg": "RS256", "typ": "JWT", "kid": kid}
    h = _b64(json.dumps(header, separators=(",", ":")).encode())
    p = _b64(json.dumps(claims, separators=(",", ":")).encode())
    signature = private.sign(f"{h}.{p}".encode(), padding.PKCS1v15(), hashes.SHA256())
    return f"{h}.{p}.{_b64(signature)}"


def claims(**overrides) -> dict:
    now = int(time.time())
    base = {
        "iss": ISSUER, "aud": AUDIENCE, "sub": "u1", "exp": now + 300,
        "iat": now, "preferred_username": "sso-operator",
        "roles": ["operator"], "scope": "ledger:read",
    }
    base.update(overrides)
    return base


@pytest.fixture
def federated_server(tmp_path, rsa_key):
    """A dashboard whose only authenticator is a real OIDC verifier."""
    private, n, e = rsa_key
    ledger = tmp_path / "audit.jsonl"
    AuditLedger(ledger).append("agent-1", "run.start", target="t", decision="allow")

    verifier = OIDCVerifier(
        issuer=ISSUER, audience=AUDIENCE,
        jwks=JWKSet.from_dict({"keys": [_jwk(n, e)]}),
    )
    httpd = serve(ledger, host="127.0.0.1", port=0, block=False, oidc=verifier)
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    yield base, private, httpd
    httpd.shutdown()
    httpd.server_close()


def call(base: str, path: str, headers: dict | None = None):
    request = urllib.request.Request(base + path, headers=headers or {})
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, response.read(), dict(response.headers)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(), dict(exc.headers)


def test_federated_token_authenticates(federated_server):
    base, private, _ = federated_server
    token = make_token(private, claims())
    status, body, _ = call(base, "/api/summary", {"Authorization": f"Bearer {token}"})
    assert status == 200
    # The summary is the real ledger summary, so the token reached the router.
    payload = json.loads(body)
    assert {"cost", "risk", "integrity", "activity", "runs"} <= set(payload)


def test_missing_token_is_refused(federated_server):
    base, _, _ = federated_server
    status, _, headers = call(base, "/api/summary")
    assert status == 401
    assert "WWW-Authenticate" in headers


def test_forged_token_is_refused(federated_server):
    """Signed by a different key, claiming the IdP's kid."""
    base, _, _ = federated_server
    attacker = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    status, _, _ = call(base, "/api/summary",
                        {"Authorization": f"Bearer {make_token(attacker, claims())}"})
    assert status == 401


def test_token_for_another_audience_is_refused(federated_server):
    base, private, _ = federated_server
    token = make_token(private, claims(aud="a-different-app"))
    status, _, _ = call(base, "/api/summary", {"Authorization": f"Bearer {token}"})
    assert status == 401


def test_expired_federated_token_is_refused(federated_server):
    base, private, _ = federated_server
    token = make_token(private, claims(exp=int(time.time()) - 3600))
    status, _, _ = call(base, "/api/summary", {"Authorization": f"Bearer {token}"})
    assert status == 401


def test_healthz_stays_open_for_federated_deployments(federated_server):
    base, _, _ = federated_server
    status, body, _ = call(base, "/healthz")
    assert status == 200
    assert json.loads(body)["ok"] is True


def test_malformed_token_is_a_401_not_a_500(federated_server):
    base, _, _ = federated_server
    for bad in ("garbage", "a.b.c", "!!!.@@@.###"):
        status, _, _ = call(base, "/api/summary", {"Authorization": f"Bearer {bad}"})
        assert status == 401, bad


def test_local_token_still_works_alongside_federation(tmp_path, rsa_key):
    """Both authenticators configured: a local token must not stop working."""
    private, n, e = rsa_key
    ledger = tmp_path / "audit.jsonl"
    AuditLedger(ledger).append("agent-1", "run.start", target="t", decision="allow")

    auth = Authenticator()
    token, plaintext = Token.issue("local-operator", role="operator", scopes={"ledger:read"})
    auth.add(token)
    verifier = OIDCVerifier(
        issuer=ISSUER, audience=AUDIENCE,
        jwks=JWKSet.from_dict({"keys": [_jwk(n, e)]}),
    )
    httpd = serve(ledger, host="127.0.0.1", port=0, block=False,
                  authenticator=auth, oidc=verifier)
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    try:
        # The local token works.
        status, _, _ = call(base, "/api/summary", {"Authorization": f"Bearer {plaintext}"})
        assert status == 200
        # And so does a federated one.
        status, _, _ = call(base, "/api/summary",
                            {"Authorization": f"Bearer {make_token(private, claims())}"})
        assert status == 200
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_federated_only_deployment_refuses_an_unrelated_bearer_token(federated_server):
    base, _, _ = federated_server
    status, _, _ = call(base, "/api/summary", {"Authorization": "Bearer not-a-jwt-at-all"})
    assert status == 401


def test_public_bind_accepts_an_oidc_verifier_as_the_authenticator(tmp_path, rsa_key):
    """The non-loopback refusal must be satisfied by federation alone."""
    _private, n, e = rsa_key
    ledger = tmp_path / "audit.jsonl"
    AuditLedger(ledger).append("agent-1", "run.start", target="t", decision="allow")
    verifier = OIDCVerifier(
        issuer=ISSUER, audience=AUDIENCE,
        jwks=JWKSet.from_dict({"keys": [_jwk(n, e)]}),
    )
    httpd = serve(ledger, host="0.0.0.0", port=0, block=False, oidc=verifier)
    try:
        assert httpd.state.auth_required is True
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_oidc_from_a_live_jwks_endpoint(tmp_path, rsa_key):
    """The full path: discovery is skipped, but the JWKS is fetched over HTTP."""
    private, n, e = rsa_key

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = json.dumps({"keys": [_jwk(n, e)]}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    jwks_httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=jwks_httpd.serve_forever, daemon=True).start()

    ledger = tmp_path / "audit.jsonl"
    AuditLedger(ledger).append("agent-1", "run.start", target="t", decision="allow")
    verifier = OIDCVerifier(
        issuer=ISSUER, audience=AUDIENCE,
        jwks_uri=f"http://127.0.0.1:{jwks_httpd.server_address[1]}/jwks",
    )
    httpd = serve(ledger, host="127.0.0.1", port=0, block=False, oidc=verifier)
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    try:
        status, _, _ = call(base, "/api/summary",
                            {"Authorization": f"Bearer {make_token(private, claims())}"})
        assert status == 200
    finally:
        httpd.shutdown()
        httpd.server_close()
        jwks_httpd.shutdown()
        jwks_httpd.server_close()
