# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 msy898931-boop
# Part of the AXON open core. See NOTICE for the license map.
"""Adversarial tests for OIDC/JWT verification.

Every token here is a real token: signed with a real RSA key or a real HMAC
secret, and verified through the same code path the dashboard uses. The
attack cases are the ones that have shipped as CVEs in other libraries —
`alg: none`, and RS256 re-signed as HS256 using the public key as the secret
— so they are tested explicitly rather than assumed.

`cryptography` is used to *generate* keys and, where available, to
cross-check that our hand-rolled RSA verifier agrees with a mature one. The
suite does not require it: keys fall back to a small generated modulus.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import ClassVar

import pytest

from axon.security.oidc import (
    ALLOWED_ALGORITHMS,
    JWKSet,
    OIDCError,
    OIDCVerifier,
    b64url_encode,
    decode_jwt,
    discovery_url,
    rsa_verify,
)

try:  # optional: used to generate keys and to cross-check our verifier
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa

    HAVE_CRYPTOGRAPHY = True
except ImportError:  # pragma: no cover - exercised on a bare install
    HAVE_CRYPTOGRAPHY = False

ISSUER = "https://idp.example.com"


# --------------------------------------------------------------------------
# Key material
# --------------------------------------------------------------------------


def _generate_rsa():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = private.private_numbers().public_numbers
    return private, numbers.n, numbers.e


def _jwk_from(private, n: int, e: int, kid: str = "key-1", alg: str = "RS256") -> dict:
    return {
        "kty": "RSA",
        "kid": kid,
        "use": "sig",
        "alg": alg,
        "n": b64url_encode(n.to_bytes((n.bit_length() + 7) // 8, "big")),
        "e": b64url_encode(e.to_bytes((e.bit_length() + 7) // 8, "big")),
    }


def _sign_rs256(private, signing_input: bytes) -> bytes:
    return private.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())


def make_token(
    private,
    claims: dict,
    kid: str = "key-1",
    alg: str = "RS256",
    header_extra: dict | None = None,
    sign_input=None,
) -> str:
    """Build a signed JWT. `sign_input` overrides what is signed, for attacks."""
    header = {"alg": alg, "typ": "JWT"}
    if kid:
        header["kid"] = kid
    header.update(header_extra or {})
    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = b64url_encode(json.dumps(claims, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}".encode() if sign_input is None else sign_input
    signature = _sign_rs256(private, signing_input)
    return f"{h}.{p}.{b64url_encode(signature)}"


def base_claims(**overrides) -> dict:
    now = int(time.time())
    claims = {
        "iss": ISSUER,
        "sub": "user-123",
        "aud": "axon-dashboard",
        "exp": now + 300,
        "iat": now,
        "nbf": now - 5,
        "preferred_username": "operator",
        "roles": ["operator"],
        "scope": "ledger:read ledger:write",
    }
    claims.update(overrides)
    return claims


@pytest.fixture(scope="module")
def keypair():
    if not HAVE_CRYPTOGRAPHY:
        pytest.skip("cryptography is required to generate RSA test keys")
    private, n, e = _generate_rsa()
    return private, n, e


@pytest.fixture
def verifier(keypair) -> OIDCVerifier:
    _, n, e = keypair
    return OIDCVerifier(
        issuer=ISSUER,
        audience="axon-dashboard",
        jwks=JWKSet.from_dict({"keys": [_jwk_from(keypair[0], n, e)]}),
    )


# --------------------------------------------------------------------------
# Happy path
# --------------------------------------------------------------------------


def test_valid_token_authenticates(verifier, keypair):
    token = make_token(keypair[0], base_claims())
    principal = verifier.verify(token)
    assert principal.name == "operator"
    assert "ledger:read" in principal.scopes
    assert "operator" in principal.scopes


def test_authenticate_matches_the_local_authenticator_contract(verifier, keypair):
    token = make_token(keypair[0], base_claims())
    principal = verifier.authenticate(f"Bearer {token}")
    assert principal.name == "operator"


def test_our_rsa_verifier_agrees_with_cryptography(keypair):
    """Cross-check the hand-rolled PKCS#1 v1.5 path against a mature one."""
    private, n, e = keypair
    message = b"the quick brown fox"
    signature = private.sign(message, padding.PKCS1v15(), hashes.SHA256())
    assert rsa_verify(message, signature, n, e, "RS256") is True
    # And it must reject a signature over a different message.
    assert rsa_verify(b"different", signature, n, e, "RS256") is False


# --------------------------------------------------------------------------
# Algorithm confusion — the historical CVE class
# --------------------------------------------------------------------------


def test_alg_none_is_refused(verifier, keypair):
    """A token that declares its own signature unnecessary is an attack."""
    h = b64url_encode(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    p = b64url_encode(json.dumps(base_claims()).encode())
    token = f"{h}.{p}."
    with pytest.raises(OIDCError, match="not accepted"):
        verifier.verify(token)


def test_alg_none_with_a_forged_signature_is_refused(verifier):
    h = b64url_encode(json.dumps({"alg": "none"}).encode())
    p = b64url_encode(json.dumps(base_claims()).encode())
    with pytest.raises(OIDCError):
        verifier.verify(f"{h}.{p}.{b64url_encode(b'anything')}")


def test_rs256_token_cannot_be_replayed_as_hs256_using_the_public_key(keypair):
    """The classic confusion attack: sign HS256 with the RSA public key bytes.

    A verifier that trusts the token's `alg` will treat the public modulus as
    an HMAC secret and accept the forgery. Here the key set holds an RSA key,
    so an HS256 token has no matching key and is refused.
    """
    _, n, e = keypair
    h = b64url_encode(json.dumps({"alg": "HS256", "kid": "key-1"}).encode())
    p = b64url_encode(json.dumps(base_claims()).encode())
    signing_input = f"{h}.{p}".encode()
    public_bytes = n.to_bytes((n.bit_length() + 7) // 8, "big")
    forged = hmac.new(public_bytes, signing_input, hashlib.sha256).digest()
    token = f"{h}.{p}.{b64url_encode(forged)}"

    v = OIDCVerifier(
        issuer=ISSUER,
        audience="axon-dashboard",
        jwks=JWKSet.from_dict({"keys": [_jwk_from(keypair[0], n, e)]}),
    )
    with pytest.raises(OIDCError):
        v.verify(token)


def test_hs256_is_accepted_when_the_operator_opts_in():
    """Symmetric verification is legitimate when the key really is symmetric."""
    secret = b"a-shared-secret-value"
    jwks = JWKSet.from_dict({"keys": [{"kty": "oct", "kid": "sym", "k": b64url_encode(secret)}]})
    v = OIDCVerifier(issuer=ISSUER, audience="axon-dashboard", jwks=jwks)
    h = b64url_encode(json.dumps({"alg": "HS256", "kid": "sym"}).encode())
    p = b64url_encode(json.dumps(base_claims()).encode())
    signing_input = f"{h}.{p}".encode()
    signature = hmac.new(secret, signing_input, hashlib.sha256).digest()
    principal = v.verify(f"{h}.{p}.{b64url_encode(signature)}")
    assert principal.name == "operator"


def test_hmac_token_signed_with_the_wrong_secret_is_refused():
    jwks = JWKSet.from_dict({"keys": [{"kty": "oct", "kid": "sym", "k": b64url_encode(b"right")}]})
    v = OIDCVerifier(issuer=ISSUER, jwks=jwks)
    h = b64url_encode(json.dumps({"alg": "HS256", "kid": "sym"}).encode())
    p = b64url_encode(json.dumps(base_claims()).encode())
    signature = hmac.new(b"wrong", f"{h}.{p}".encode(), hashlib.sha256).digest()
    with pytest.raises(OIDCError, match="signature does not verify"):
        v.verify(f"{h}.{p}.{b64url_encode(signature)}")


def test_algorithm_must_be_in_the_allow_list(keypair):
    """An operator who allows only RS256 must not accept HS256 at all."""
    _, n, e = keypair
    v = OIDCVerifier(
        issuer=ISSUER, jwks=JWKSet.from_dict({"keys": [_jwk_from(keypair[0], n, e)]}),
        algorithms=("RS256",),
    )
    h = b64url_encode(json.dumps({"alg": "HS256", "kid": "key-1"}).encode())
    p = b64url_encode(json.dumps(base_claims()).encode())
    with pytest.raises(OIDCError, match="not accepted"):
        v.verify(f"{h}.{p}.{b64url_encode(b'x')}")


def test_unsupported_algorithm_in_the_config_is_rejected_at_construction(keypair):
    _, n, e = keypair
    with pytest.raises(OIDCError, match="not allowed"):
        OIDCVerifier(
            issuer=ISSUER,
            jwks=JWKSet.from_dict({"keys": [_jwk_from(keypair[0], n, e)]}),
            algorithms=("PS256",),
        )


# --------------------------------------------------------------------------
# Signature and key handling
# --------------------------------------------------------------------------


def test_signature_over_different_claims_is_refused(verifier, keypair):
    """Take a valid token, swap the payload, keep the signature."""
    private = keypair[0]
    good = make_token(private, base_claims())
    h, _, sig = good.split(".")
    tampered_payload = b64url_encode(json.dumps(base_claims(sub="attacker")).encode())
    with pytest.raises(OIDCError, match="signature does not verify"):
        verifier.verify(f"{h}.{tampered_payload}.{sig}")


def test_unknown_kid_is_refused(verifier, keypair):
    token = make_token(keypair[0], base_claims(), kid="some-other-key")
    with pytest.raises(OIDCError, match="no key matches"):
        verifier.verify(token)


def test_token_without_kid_is_refused_when_several_keys_exist(keypair):
    _, n, e = keypair
    jwks = JWKSet.from_dict({"keys": [
        _jwk_from(keypair[0], n, e, kid="a"),
        _jwk_from(keypair[0], n, e, kid="b"),
    ]})
    v = OIDCVerifier(issuer=ISSUER, jwks=jwks)
    token = make_token(keypair[0], base_claims(), kid="")
    with pytest.raises(OIDCError, match="no key matches"):
        v.verify(token)


def test_token_without_kid_is_accepted_when_the_set_is_unambiguous(keypair):
    _, n, e = keypair
    v = OIDCVerifier(issuer=ISSUER, jwks=JWKSet.from_dict({"keys": [_jwk_from(keypair[0], n, e)]}))
    assert v.verify(make_token(keypair[0], base_claims(), kid="")).name == "operator"


def test_signature_from_a_different_key_is_refused(verifier):
    """A token signed by an attacker's key, with the victim's kid."""
    attacker, _n, _e = _generate_rsa()
    token = make_token(attacker, base_claims(), kid="key-1")
    with pytest.raises(OIDCError, match="signature does not verify"):
        verifier.verify(token)


def test_a_verification_key_is_never_used_for_signing(keypair):
    """`use: enc` keys must not verify a signature."""
    _, n, e = keypair
    jwks = JWKSet.from_dict({"keys": [{**_jwk_from(keypair[0], n, e), "use": "enc"}]})
    v = OIDCVerifier(issuer=ISSUER, jwks=jwks)
    with pytest.raises(OIDCError):
        v.verify(make_token(keypair[0], base_claims()))


# --------------------------------------------------------------------------
# Claim checks
# --------------------------------------------------------------------------


def test_wrong_issuer_is_refused(verifier, keypair):
    token = make_token(keypair[0], base_claims(iss="https://evil.example.com"))
    with pytest.raises(OIDCError, match="issuer"):
        verifier.verify(token)


def test_wrong_audience_is_refused(verifier, keypair):
    token = make_token(keypair[0], base_claims(aud="some-other-app"))
    with pytest.raises(OIDCError, match="audience"):
        verifier.verify(token)


def test_audience_as_a_list_is_accepted(verifier, keypair):
    token = make_token(keypair[0], base_claims(aud=["other", "axon-dashboard"]))
    assert verifier.verify(token).name == "operator"


def test_expired_token_is_refused(verifier, keypair):
    token = make_token(keypair[0], base_claims(exp=int(time.time()) - 3600))
    with pytest.raises(OIDCError, match="expired"):
        verifier.verify(token)


def test_token_without_exp_is_refused(verifier, keypair):
    claims = base_claims()
    del claims["exp"]
    with pytest.raises(OIDCError, match="no exp"):
        verifier.verify(make_token(keypair[0], claims))


def test_not_yet_valid_token_is_refused(verifier, keypair):
    token = make_token(keypair[0], base_claims(nbf=int(time.time()) + 3600))
    with pytest.raises(OIDCError, match="not valid yet"):
        verifier.verify(token)


def test_token_issued_in_the_future_is_refused(verifier, keypair):
    token = make_token(keypair[0], base_claims(iat=int(time.time()) + 3600))
    with pytest.raises(OIDCError, match="issued in the future"):
        verifier.verify(token)


def test_expiry_leeway_absorbs_clock_skew(verifier, keypair):
    """A token that expired seconds ago is accepted within the leeway."""
    token = make_token(keypair[0], base_claims(exp=int(time.time()) - 10))
    assert verifier.verify(token).name == "operator"


def test_roles_and_scopes_map_onto_the_principal(verifier, keypair):
    token = make_token(keypair[0], base_claims(roles=["auditor"], scope="ledger:read"))
    principal = verifier.verify(token)
    assert principal.role == "auditor"
    assert principal.scopes == {"ledger:read", "auditor"}


# --------------------------------------------------------------------------
# Malformed input — must be a 401, never a 500
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "token",
    [
        "",
        "not-a-jwt",
        "only.two",
        "a.b.c.d",
        "!!!.@@@.###",
        "eyJhbGciOiJSUzI1NiJ9..",
    ],
)
def test_malformed_tokens_raise_oidc_error_not_a_crash(verifier, token):
    with pytest.raises(OIDCError):
        verifier.verify(token)


def test_header_that_is_not_json_is_refused(verifier):
    token = f"{b64url_encode(b'not json')}.{b64url_encode(b'{}')}.{b64url_encode(b'x')}"
    with pytest.raises(OIDCError, match="not JSON"):
        verifier.verify(token)


def test_decode_jwt_rejects_a_non_string():
    with pytest.raises(OIDCError):
        decode_jwt(None)


def test_jwk_missing_modulus_is_rejected():
    with pytest.raises(OIDCError, match="missing 'n' or 'e'"):
        JWKSet.from_dict({"keys": [{"kty": "RSA", "kid": "k", "n": "AQAB"}]})


def test_empty_jwks_is_rejected():
    with pytest.raises(OIDCError, match="no keys"):
        JWKSet.from_dict({"keys": []})


def test_unsupported_key_type_does_not_break_the_set(keypair):
    """An EC key alongside an RSA key must not stop the RSA key working."""
    _, n, e = keypair
    jwks = JWKSet.from_dict({"keys": [
        {"kty": "EC", "kid": "ec-1", "crv": "P-256", "x": "a", "y": "b"},
        _jwk_from(keypair[0], n, e, kid="rsa-1"),
    ]})
    v = OIDCVerifier(issuer=ISSUER, jwks=jwks)
    assert v.verify(make_token(keypair[0], base_claims(), kid="rsa-1")).name == "operator"


def test_rsa_verify_rejects_a_short_signature():
    assert rsa_verify(b"msg", b"\x00\x01", 3233, 17, "RS256") is False


def test_rsa_verify_rejects_an_unknown_algorithm():
    assert rsa_verify(b"msg", b"sig", 3233, 17, "ES256") is False


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------


def test_verifier_requires_an_issuer(keypair):
    with pytest.raises(OIDCError, match="issuer is required"):
        OIDCVerifier(issuer="")


def test_verifier_requires_keys_or_a_uri():
    with pytest.raises(OIDCError, match="JWKSet or a jwks_uri"):
        OIDCVerifier(issuer=ISSUER)


def test_disabled_verifier_refuses_to_verify(keypair):
    _, n, e = keypair
    v = OIDCVerifier(issuer=ISSUER, jwks=JWKSet.from_dict({"keys": [_jwk_from(keypair[0], n, e)]}),
                     enabled=False)
    with pytest.raises(OIDCError, match="disabled"):
        v.verify(make_token(keypair[0], base_claims()))


def test_discovery_url_has_no_double_slash():
    assert discovery_url("https://idp.example.com/") == \
        "https://idp.example.com/.well-known/openid-configuration"


def test_none_is_not_in_the_allow_list():
    assert "none" not in ALLOWED_ALGORITHMS
    assert "RS256" in ALLOWED_ALGORITHMS


# --------------------------------------------------------------------------
# JWKS fetching, rotation, and the refetch rate limit
# --------------------------------------------------------------------------


class _JWKSHandler(BaseHTTPRequestHandler):
    document: ClassVar[dict] = {}
    hits = 0
    lock = threading.Lock()

    def do_GET(self):
        with _JWKSHandler.lock:
            _JWKSHandler.hits += 1
        body = json.dumps(_JWKSHandler.document).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture
def jwks_server(keypair):
    """A real HTTP server publishing a JWKS, so rotation is exercised for real."""
    _, n, e = keypair
    _JWKSHandler.document = {"keys": [_jwk_from(keypair[0], n, e, kid="rotating-1")]}
    _JWKSHandler.hits = 0
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _JWKSHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}/jwks"
    httpd.shutdown()
    httpd.server_close()


def test_jwks_is_fetched_over_http_and_cached(jwks_server, keypair):
    v = OIDCVerifier(issuer=ISSUER, jwks_uri=jwks_server)
    token = make_token(keypair[0], base_claims(), kid="rotating-1")
    assert v.verify(token).name == "operator"
    assert v.verify(token).name == "operator"
    # The second verification must come from the cache, not a second fetch.
    assert _JWKSHandler.hits == 1


def test_key_rotation_is_picked_up(jwks_server, keypair):
    """A new kid triggers one refetch, so a rotating IdP keeps working."""
    v = OIDCVerifier(issuer=ISSUER, jwks_uri=jwks_server, min_refetch_interval=0.0)
    assert v.verify(make_token(keypair[0], base_claims(), kid="rotating-1")).name == "operator"

    new_private, n, e = _generate_rsa()
    _JWKSHandler.document = {"keys": [_jwk_from(new_private, n, e, kid="rotating-2")]}
    token = make_token(new_private, base_claims(), kid="rotating-2")
    assert v.verify(token).name == "operator"


def test_unknown_kid_does_not_cause_unbounded_fetches(jwks_server, keypair):
    """The refetch rate limit: a flood of bad kids must not become a DoS."""
    v = OIDCVerifier(issuer=ISSUER, jwks_uri=jwks_server)
    v.verify(make_token(keypair[0], base_claims(), kid="rotating-1"))
    before = _JWKSHandler.hits
    for _ in range(20):
        with pytest.raises(OIDCError):
            v.verify(make_token(keypair[0], base_claims(), kid="does-not-exist"))
    # At most one extra refetch inside the minimum interval.
    assert _JWKSHandler.hits - before <= 1


def test_unreachable_jwks_uri_is_an_oidc_error():
    v = OIDCVerifier(issuer=ISSUER, jwks_uri="http://127.0.0.1:9/jwks")
    with pytest.raises(OIDCError, match="could not reach"):
        v.verify("eyJhbGciOiJSUzI1NiIsImtpZCI6ImsifQ.eyJpc3MiOiJ4In0.c2ln")


def test_jwks_returning_a_non_object_is_refused(keypair):
    class Bad(BaseHTTPRequestHandler):
        def do_GET(self):
            body = b"[1,2,3]"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Bad)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        v = OIDCVerifier(issuer=ISSUER, jwks_uri=f"http://127.0.0.1:{httpd.server_address[1]}/j")
        with pytest.raises(OIDCError):
            v.verify("a.b.c")
    finally:
        httpd.shutdown()
        httpd.server_close()


# --------------------------------------------------------------------------
# Discovery
# --------------------------------------------------------------------------


@pytest.fixture
def discovery_server(keypair):
    _, n, e = keypair
    state = {"issuer": ISSUER}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            port = self.server.server_address[1]
            if self.path.endswith("openid-configuration"):
                body = json.dumps({
                    "issuer": state["issuer"],
                    "jwks_uri": f"http://127.0.0.1:{port}/jwks",
                }).encode()
            else:
                body = json.dumps({"keys": [_jwk_from(keypair[0], n, e, kid="disc-1")]}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    issuer = f"http://127.0.0.1:{httpd.server_address[1]}"
    state["issuer"] = issuer
    yield issuer, state, keypair
    httpd.shutdown()
    httpd.server_close()


def test_discovery_finds_the_jwks_uri(discovery_server):
    issuer, _, keypair = discovery_server
    v = OIDCVerifier.from_discovery(issuer, audience="axon-dashboard")
    token = make_token(keypair[0], base_claims(iss=issuer), kid="disc-1")
    assert v.verify(token).name == "operator"


def test_discovery_rejects_a_mismatched_issuer(discovery_server):
    """A document claiming a different issuer must not be trusted."""
    issuer, state, _ = discovery_server
    state["issuer"] = "https://evil.example.com"
    try:
        with pytest.raises(OIDCError, match="declares issuer"):
            OIDCVerifier.from_discovery(issuer)
    finally:
        state["issuer"] = issuer
