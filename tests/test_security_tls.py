"""Adversarial tests for the TLS layer.

These drive a real TLS handshake over a real socket against a real
certificate, because the failure mode being defended against — "the operator
believes traffic is encrypted" — cannot be observed any other way. A test
that only asserted `TLSConfig` was constructed would pass while the server
still spoke plaintext.

Certificates are generated with `openssl` at session scope. `cryptography` is
not required to run the suite.
"""

from __future__ import annotations

import http.client
import shutil
import socket
import ssl
import subprocess
import tempfile
from pathlib import Path

import pytest

from axon.dashboard import serve
from axon.security.auth import Authenticator, Token
from axon.security.tls import (
    TLSConfig,
    TLSError,
    build_context,
    is_loopback,
    verify_pair,
    wrap_server,
)

OPENSSL = shutil.which("openssl")
pytestmark = pytest.mark.skipif(OPENSSL is None, reason="openssl is required to make test certificates")


@pytest.fixture(scope="module")
def certs() -> tuple[str, str]:
    """A real self-signed certificate with a SAN for localhost."""
    with tempfile.TemporaryDirectory() as tmp:
        cert = Path(tmp) / "cert.pem"
        key = Path(tmp) / "key.pem"
        subprocess.run(
            [
                OPENSSL, "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", str(key), "-out", str(cert),
                "-days", "1", "-nodes", "-subj", "/CN=localhost",
                "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
            ],
            check=True, capture_output=True,
        )
        # The temp dir is removed on exit, so keep the files alive by copying
        # them into a directory pytest owns for the module's lifetime.
        keep = Path(tempfile.mkdtemp(prefix="axon-tls-"))
        (keep / "cert.pem").write_bytes(cert.read_bytes())
        (keep / "key.pem").write_bytes(key.read_bytes())
        yield str(keep / "cert.pem"), str(keep / "key.pem")
        shutil.rmtree(keep, ignore_errors=True)


def _ledger(tmp_path: Path) -> str:
    from axon.core.audit import AuditLedger

    path = tmp_path / "audit.jsonl"
    ledger = AuditLedger(path)
    ledger.append(actor="tester", action="tool.read", target="/tmp/x", decision="allow")
    return str(path)


def _client_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


# --------------------------------------------------------------------------
# Context construction
# --------------------------------------------------------------------------


def test_missing_certificate_file_is_refused_before_startup():
    with pytest.raises(TLSError, match="not found"):
        TLSConfig(certfile="/nonexistent/cert.pem", keyfile="/nonexistent/key.pem")


def test_certificate_and_key_must_both_be_supplied(certs):
    cert, _ = certs
    with pytest.raises(TLSError, match="both"):
        TLSConfig(certfile=cert, keyfile="")


def test_context_refuses_protocols_below_tls12(certs):
    cert, key = certs
    context = build_context(TLSConfig(certfile=cert, keyfile=key))
    assert context.minimum_version >= ssl.TLSVersion.TLSv1_2


def test_mismatched_key_is_rejected(certs, tmp_path):
    """A key that does not belong to the certificate must fail at load time.

    This is the misconfiguration that produces a server which starts and then
    fails every handshake with an opaque alert.
    """
    cert, _ = certs
    other_key = tmp_path / "other.key"
    other_cert = tmp_path / "other.crt"
    subprocess.run(
        [OPENSSL, "req", "-x509", "-newkey", "rsa:2048", "-keyout", str(other_key),
         "-out", str(other_cert), "-days", "1", "-nodes", "-subj", "/CN=other"],
        check=True, capture_output=True,
    )
    with pytest.raises(TLSError, match="could not load"):
        build_context(TLSConfig(certfile=cert, keyfile=str(other_key)))


def test_verify_pair_reports_a_fingerprint(certs):
    cert, key = certs
    fingerprint = verify_pair(cert, key)
    # 32 bytes rendered as 32 colon-separated pairs.
    assert len(fingerprint.split(":")) == 32
    assert all(len(part) == 2 for part in fingerprint.split(":"))


def test_verify_pair_rejects_a_non_certificate_file(tmp_path, certs):
    _, key = certs
    junk = tmp_path / "junk.pem"
    junk.write_text("not a certificate\n")
    with pytest.raises(TLSError):
        verify_pair(str(junk), key)


# --------------------------------------------------------------------------
# A real handshake
# --------------------------------------------------------------------------


def test_dashboard_speaks_tls_and_refuses_plaintext(tmp_path, certs):
    """The whole point of the layer: the socket must not speak HTTP in clear."""
    cert, key = certs
    auth = Authenticator()
    token, plaintext = Token.issue("operator", role="operator", scopes={"ledger:read"})
    auth.add(token)

    httpd = serve(
        _ledger(tmp_path), host="127.0.0.1", port=0, block=False,
        authenticator=auth, tls=TLSConfig(certfile=cert, keyfile=key),
    )
    try:
        port = httpd.server_address[1]

        # Plain HTTP against a TLS socket must not produce a response.
        with pytest.raises((ssl.SSLError, ConnectionResetError, http.client.HTTPException, OSError)):
            with socket.create_connection(("127.0.0.1", port), timeout=3) as raw:
                raw.sendall(b"GET /api/summary HTTP/1.1\r\nHost: x\r\n\r\n")
                raw.recv(1024)

        # Over TLS, the same request authenticates and succeeds.
        context = _client_context()
        conn = http.client.HTTPSConnection("127.0.0.1", port, context=context, timeout=5)
        conn.request("GET", "/api/summary", headers={"Authorization": f"Bearer {plaintext}"})
        response = conn.getresponse()
        assert response.status == 200
        conn.close()
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_tls_server_still_enforces_authentication(tmp_path, certs):
    """Encryption is not authorisation: no token must still be a 401."""
    cert, key = certs
    auth = Authenticator()
    token, _ = Token.issue("operator", role="operator")
    auth.add(token)

    httpd = serve(
        _ledger(tmp_path), host="127.0.0.1", port=0, block=False,
        authenticator=auth, tls=TLSConfig(certfile=cert, keyfile=key),
    )
    try:
        port = httpd.server_address[1]
        conn = http.client.HTTPSConnection("127.0.0.1", port, context=_client_context(), timeout=5)
        conn.request("GET", "/api/summary")
        assert conn.getresponse().status == 401
        conn.close()
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_https_client_with_verification_accepts_the_certificate(tmp_path, certs):
    """A verifying client must succeed, which proves the chain is well-formed."""
    cert, key = certs
    auth = Authenticator()
    token, _plaintext = Token.issue("operator", role="operator")
    auth.add(token)

    httpd = serve(
        _ledger(tmp_path), host="127.0.0.1", port=0, block=False,
        authenticator=auth, tls=TLSConfig(certfile=cert, keyfile=key),
    )
    try:
        port = httpd.server_address[1]
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(cert)
        context.check_hostname = True
        conn = http.client.HTTPSConnection("localhost", port, context=context, timeout=5)
        conn.request("GET", "/healthz")
        assert conn.getresponse().status == 200
        conn.close()
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_tls_configuration_makes_the_transport_layer_enforce(tmp_path, certs):
    """`serve` must mark the server secure when TLS is configured."""
    cert, key = certs
    httpd = serve(
        _ledger(tmp_path), host="127.0.0.1", port=0, block=False,
        tls=TLSConfig(certfile=cert, keyfile=key),
    )
    try:
        assert httpd.secure is True
        assert httpd.state.tls is not None
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_hsts_is_sent_when_tls_is_active(tmp_path, certs):
    cert, key = certs
    httpd = serve(
        _ledger(tmp_path), host="127.0.0.1", port=0, block=False,
        tls=TLSConfig(certfile=cert, keyfile=key),
    )
    try:
        port = httpd.server_address[1]
        conn = http.client.HTTPSConnection("127.0.0.1", port, context=_client_context(), timeout=5)
        conn.request("GET", "/healthz")
        response = conn.getresponse()
        assert response.status == 200
        assert "Strict-Transport-Security" in response.headers
        conn.close()
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_wrap_server_requires_a_bound_socket(certs):
    """`wrap_server` is called after bind; a non-socket must not be silently accepted."""
    cert, key = certs

    class Fake:
        socket = object()

    with pytest.raises((AttributeError, TypeError, ValueError)):
        wrap_server(Fake(), TLSConfig(certfile=cert, keyfile=key))


def test_is_loopback_classifies_hosts():
    assert is_loopback("127.0.0.1")
    assert is_loopback("localhost")
    assert not is_loopback("0.0.0.0")
    assert not is_loopback("10.0.0.5")
