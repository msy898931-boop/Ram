# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 msy898931-boop
# Part of the AXON open core. See NOTICE for the license map.
"""Layer 2: OIDC/SSO bearer tokens — federation instead of local tokens.

Why this exists next to the local token store: `axon token create` is the
right answer for one operator on one box, and the wrong answer for an
organisation. An enterprise already has an identity provider, already has an
offboarding process, and already has a rule that nobody gets a credential
that is not tied to a person. Asking them to copy tokens into a YAML file
undoes all three. Federation means the dashboard trusts the IdP's signature,
so revocation happens where revocation already happens.

Threat model: an attacker presents a token the dashboard should not accept.
The defences, in the order they matter:

  alg confusion  — a token signed with `alg: none`, or an RS256 token
                   re-signed as HS256 using the public key as the HMAC
                   secret. Both are historical CVEs in real libraries, so
                   the algorithm is taken from an allow-list and the key type
                   must agree with it.
  forgery        — a token whose signature does not verify against the IdP's
                   published key. Verified with RSA PKCS#1 v1.5 over SHA-256,
                   implemented here because the package must install in an
                   air-gapped environment with no native crypto stack.
  replay after
  revocation     — `exp`, `nbf`, and `iat` are all enforced, with a small
                   leeway for clock skew, so a token cannot outlive its
                   lifetime.
  audience       — a token minted for a different application is refused, so
                   a token stolen from a sibling service is not accepted here.
  key rotation   — an unknown `kid` triggers one refetch, rate-limited, so a
                   rotating IdP keeps working and a caller cannot force an
                   unbounded number of JWKS fetches.

What this does not do: it does not talk to the IdP's introspection endpoint,
so a token revoked before its `exp` is still accepted until it expires. That
is the standard trade-off for stateless verification; shorten `exp` if that
window matters.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

from .auth import AuthError, Principal

# Only these are accepted. `none` is deliberately absent: a token that
# carries its own "no signature needed" instruction is an attack, not a token.
ALLOWED_ALGORITHMS = ("RS256", "RS384", "RS512", "HS256", "HS384", "HS512")

_RSA_ALGORITHMS = {"RS256": hashlib.sha256, "RS384": hashlib.sha384, "RS512": hashlib.sha512}
_HMAC_ALGORITHMS = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}

# DER prefixes for DigestInfo, per RFC 8017 section 9.2. The signature is
# PKCS#1 v1.5 over these bytes; getting them wrong yields a verifier that
# rejects valid tokens, so they are written out rather than derived.
_DIGEST_INFO_PREFIX = {
    "RS256": bytes.fromhex("3031300d060960864801650304020105000420"),
    "RS384": bytes.fromhex("3041300d060960864801650304020205000430"),
    "RS512": bytes.fromhex("3051300d060960864801650304020305000440"),
}

_DEFAULT_LEEWAY = 60.0
_JWKS_TTL = 300.0
_MIN_REFETCH_INTERVAL = 5.0


class OIDCError(AuthError):
    """A federated token was not acceptable. Subclasses AuthError so the
    dashboard's existing 401 path handles it without special-casing."""


# --------------------------------------------------------------------------
# base64url and JWT decoding
# --------------------------------------------------------------------------


def b64url_decode(segment: str) -> bytes:
    """Decode base64url, restoring the padding that JWT strips.

    A caller-supplied segment can be any length and contain any character, so
    this raises `OIDCError` rather than letting a `binascii.Error` escape as a
    500 from inside request handling.
    """
    if not isinstance(segment, str) or not segment:
        raise OIDCError("empty token segment")
    padding = "=" * (-len(segment) % 4)
    try:
        return base64.urlsafe_b64decode(segment + padding)
    except (binascii.Error, ValueError) as exc:
        raise OIDCError(f"malformed base64url segment: {exc}") from exc


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


@dataclass(frozen=True)
class JWT:
    header: dict[str, Any]
    claims: dict[str, Any]
    signature: bytes
    signing_input: bytes


def decode_jwt(token: str) -> JWT:
    """Split and parse a JWT. Does not verify anything — see `OIDCVerifier`."""
    if not isinstance(token, str):
        raise OIDCError("token must be a string")
    parts = token.split(".")
    if len(parts) != 3:
        raise OIDCError("a JWT must have three dot-separated segments")
    header_raw, payload_raw, signature_raw = parts
    try:
        header = json.loads(b64url_decode(header_raw))
        claims = json.loads(b64url_decode(payload_raw))
    except json.JSONDecodeError as exc:
        raise OIDCError(f"token header or payload is not JSON: {exc}") from exc
    if not isinstance(header, dict) or not isinstance(claims, dict):
        raise OIDCError("token header and payload must be JSON objects")
    # An empty signature segment is decoded to b"" rather than refused here,
    # so the `alg` allow-list is what rejects `alg: none` — the refusal then
    # names the actual problem instead of reporting a malformed segment.
    signature = b64url_decode(signature_raw) if signature_raw else b""
    return JWT(
        header=header,
        claims=claims,
        signature=signature,
        signing_input=f"{header_raw}.{payload_raw}".encode("ascii"),
    )


# --------------------------------------------------------------------------
# RSA verification (PKCS#1 v1.5), in pure Python
# --------------------------------------------------------------------------


def _int_from_b64url(segment: str) -> int:
    return int.from_bytes(b64url_decode(segment), "big")


def rsa_verify(message: bytes, signature: bytes, modulus: int, exponent: int, alg: str) -> bool:
    """Verify an RS256/384/512 signature. Returns False rather than raising.

    Every failure is a "no": a malformed key, a short signature, a signature
    at or above the modulus, or padding that does not match. The caller turns
    that into a single `OIDCError` with no detail, so a probe learns nothing
    from which check failed.
    """
    if alg not in _RSA_ALGORITHMS:
        return False
    if modulus <= 0 or exponent <= 0:
        return False
    key_size = (modulus.bit_length() + 7) // 8
    if len(signature) != key_size:
        return False
    value = int.from_bytes(signature, "big")
    if value >= modulus:
        return False

    # The raw RSA operation: signature^e mod n, left-padded to the key size.
    try:
        recovered = pow(value, exponent, modulus).to_bytes(key_size, "big")
    except (ValueError, OverflowError):
        return False

    digest = _RSA_ALGORITHMS[alg](message).digest()
    digest_info = _DIGEST_INFO_PREFIX[alg] + digest
    padding_len = key_size - len(digest_info) - 3
    if padding_len < 8:
        return False
    expected = b"\x00\x01" + b"\xff" * padding_len + b"\x00" + digest_info
    return hmac.compare_digest(recovered, expected)


# --------------------------------------------------------------------------
# JWKS
# --------------------------------------------------------------------------


@dataclass
class JWK:
    kid: str
    kty: str
    alg: str | None = None
    use: str | None = None
    n: int | None = None
    e: int | None = None
    k: bytes | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> JWK:
        if not isinstance(data, dict):
            raise OIDCError("JWK entry must be an object")
        kty = str(data.get("kty", ""))
        kid = str(data.get("kid", ""))
        key = cls(kid=kid, kty=kty, alg=data.get("alg"), use=data.get("use"))
        if kty == "RSA":
            if not data.get("n") or not data.get("e"):
                raise OIDCError(f"RSA key {kid!r} is missing 'n' or 'e'")
            key.n = _int_from_b64url(str(data["n"]))
            key.e = _int_from_b64url(str(data["e"]))
        elif kty == "oct":
            if not data.get("k"):
                raise OIDCError(f"symmetric key {kid!r} is missing 'k'")
            key.k = b64url_decode(str(data["k"]))
        else:
            # An unsupported key type is kept so that a set containing EC keys
            # alongside RSA keys still verifies the RSA ones; it simply never
            # matches a request.
            pass
        return key

    def verifies(self, jwt: JWT) -> bool:
        alg = str(jwt.header.get("alg", ""))
        if self.use not in (None, "", "sig"):
            return False
        if self.alg and self.alg != alg:
            return False
        if alg in _RSA_ALGORITHMS and self.kty == "RSA":
            assert self.n is not None and self.e is not None
            return rsa_verify(jwt.signing_input, jwt.signature, self.n, self.e, alg)
        if alg in _HMAC_ALGORITHMS and self.kty == "oct":
            assert self.k is not None
            expected = hmac.new(self.k, jwt.signing_input, _HMAC_ALGORITHMS[alg]).digest()
            return hmac.compare_digest(expected, jwt.signature)
        # Reaching here means the token's algorithm and the key's type disagree.
        # That is exactly the alg-confusion case, so it is a refusal.
        return False


class JWKSet:
    """A parsed JWKS, indexed by `kid`."""

    def __init__(self, keys: list[JWK] | None = None):
        self.keys = list(keys or [])

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> JWKSet:
        if not isinstance(data, dict):
            raise OIDCError("JWKS must be an object")
        raw = data.get("keys")
        if not isinstance(raw, list) or not raw:
            raise OIDCError("JWKS contains no keys")
        return cls([JWK.from_dict(entry) for entry in raw])

    def candidates(self, kid: str | None) -> list[JWK]:
        """Keys that could have signed this token.

        A token with a `kid` gets exactly the matching keys. A token without
        one is only accepted when the set is unambiguous: guessing among
        several keys would turn a missing field into a weaker check.
        """
        if kid:
            return [k for k in self.keys if k.kid == kid]
        return self.keys if len(self.keys) == 1 else []


def fetch_json(url: str, timeout: float = 5.0) -> dict[str, Any]:
    """GET a JSON document. Used for discovery and JWKS."""
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            if response.status != 200:
                raise OIDCError(f"{url} returned HTTP {response.status}")
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.URLError as exc:
        raise OIDCError(f"could not reach {url}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise OIDCError(f"{url} did not return JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise OIDCError(f"{url} did not return a JSON object")
    return payload


def discovery_url(issuer: str) -> str:
    """RFC 8414 well-known path. The issuer must not carry a trailing slash."""
    return f"{issuer.rstrip('/')}/.well-known/openid-configuration"


# --------------------------------------------------------------------------
# The verifier
# --------------------------------------------------------------------------


@dataclass
class OIDCVerifier:
    """Verifies federated bearer tokens against an IdP's published keys."""

    issuer: str
    audience: str | None = None
    jwks: JWKSet | None = None
    jwks_uri: str | None = None
    algorithms: tuple[str, ...] = ALLOWED_ALGORITHMS
    leeway: float = _DEFAULT_LEEWAY
    require_exp: bool = True
    roles_claim: str = "roles"
    scope_claim: str = "scope"
    enabled: bool = True
    # How long to wait between JWKS refetches. Configurable so a deployment
    # with a fast-rotating IdP can shorten it, and so tests need not sleep.
    min_refetch_interval: float = _MIN_REFETCH_INTERVAL
    _fetched_at: float = field(default=0.0, repr=False)
    _jwks: JWKSet | None = field(default=None, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def __post_init__(self) -> None:
        if not self.issuer:
            raise OIDCError("an issuer is required")
        for alg in self.algorithms:
            if alg not in ALLOWED_ALGORITHMS:
                raise OIDCError(f"algorithm {alg!r} is not allowed")
        if not self.algorithms:
            raise OIDCError("at least one algorithm must be allowed")
        if self.jwks is None and not self.jwks_uri:
            raise OIDCError("supply either a JWKSet or a jwks_uri")

    @classmethod
    def from_discovery(cls, issuer: str, audience: str | None = None, **kwargs) -> OIDCVerifier:
        """Read the IdP's discovery document and take `jwks_uri` from it.

        The issuer in the document must equal the one we asked about: an
        attacker who can redirect the discovery URL should not be able to
        point us at their own keys.
        """
        document = fetch_json(discovery_url(issuer))
        declared = document.get("issuer")
        if declared and str(declared).rstrip("/") != issuer.rstrip("/"):
            raise OIDCError(
                f"discovery document declares issuer {declared!r}, expected {issuer!r}"
            )
        uri = document.get("jwks_uri")
        if not uri:
            raise OIDCError("discovery document has no jwks_uri")
        return cls(issuer=issuer, audience=audience, jwks_uri=str(uri), **kwargs)

    def _keys(self, kid: str | None, now: float) -> list[JWK]:
        """Return candidate keys, refetching when a rotation is suspected.

        The refetch is rate-limited. Without that limit, a caller sending
        tokens with random `kid` values would turn every request into an
        outbound HTTP call — a denial of service with the IdP as the victim.

        The rate limit is what makes rotation work at all. A rotating IdP
        hands out a `kid` we have never seen; if we refused to refetch until
        the TTL expired, the new token would be rejected for up to a full
        TTL after every rotation. So an unknown `kid` refetches immediately,
        but no more often than `_MIN_REFETCH_INTERVAL`.
        """
        if self.jwks is not None:
            return self.jwks.candidates(kid)

        fetched_at = self._fetched_at
        stale = self._jwks is None or now - fetched_at > _JWKS_TTL
        may_refetch = now - fetched_at > self.min_refetch_interval
        if stale and may_refetch:
            self._refetch(now)

        if self._jwks is None:
            return []
        found = self._jwks.candidates(kid)
        if not found and may_refetch:
            # A `kid` we have never seen is what a rotation looks like, so we
            # refetch once. A `kid` that is simply wrong lands here too and is
            # refused immediately afterwards.
            self._refetch(now)
            found = self._jwks.candidates(kid)
        return found

    def _refetch(self, now: float) -> None:
        with self._lock:
            # Re-check under the lock: a burst of concurrent requests with the
            # same unknown kid must not each trigger their own fetch.
            if now - self._fetched_at <= self.min_refetch_interval and self._jwks is not None:
                return
            document = fetch_json(self.jwks_uri or "")
            self._jwks = JWKSet.from_dict(document)
            self._fetched_at = now

    def verify(self, token: str) -> Principal:
        """Verify a token and map its claims onto a Principal."""
        if not self.enabled:
            raise OIDCError("OIDC verification is disabled")

        jwt = decode_jwt(token)

        alg = str(jwt.header.get("alg", ""))
        if not alg:
            raise OIDCError("token header has no alg")
        if alg not in self.algorithms:
            # Covers `none` and any algorithm the operator did not opt into.
            raise OIDCError(f"algorithm {alg!r} is not accepted")

        now = time.time()
        kid = jwt.header.get("kid")
        keys = self._keys(str(kid) if kid else None, now)
        if not keys:
            raise OIDCError("no key matches this token")

        if not any(key.verifies(jwt) for key in keys):
            raise OIDCError("signature does not verify")

        claims = jwt.claims
        issuer = str(claims.get("iss", ""))
        if issuer.rstrip("/") != self.issuer.rstrip("/"):
            raise OIDCError("token issuer does not match")

        if self.audience is not None:
            aud = claims.get("aud")
            audiences = [aud] if isinstance(aud, str) else list(aud or [])
            if self.audience not in audiences:
                raise OIDCError("token audience does not include this application")

        self._check_times(claims, now)

        name = str(
            claims.get("preferred_username")
            or claims.get("email")
            or claims.get("sub")
            or "unknown"
        )
        scopes = self._claim_as_set(claims, self.scope_claim, separator=" ")
        roles = self._claim_as_set(claims, self.roles_claim)
        return Principal(name=name, role=next(iter(roles), "viewer"), scopes=scopes | roles)

    def _check_times(self, claims: dict[str, Any], now: float) -> None:
        exp = claims.get("exp")
        if exp is None:
            if self.require_exp:
                raise OIDCError("token has no exp")
        else:
            if not isinstance(exp, (int, float)):
                raise OIDCError("exp is not a number")
            if now > float(exp) + self.leeway:
                raise OIDCError("token has expired")

        nbf = claims.get("nbf")
        if isinstance(nbf, (int, float)) and now + self.leeway < float(nbf):
            raise OIDCError("token is not valid yet")

        iat = claims.get("iat")
        if isinstance(iat, (int, float)) and now + self.leeway < float(iat):
            raise OIDCError("token was issued in the future")

    @staticmethod
    def _claim_as_set(claims: dict[str, Any], name: str, separator: str | None = None) -> set[str]:
        value = claims.get(name)
        if value is None:
            return set()
        if isinstance(value, str):
            return set(value.split(separator)) if separator else {value}
        if isinstance(value, (list, tuple)):
            return {str(item) for item in value}
        return {str(value)}

    def authenticate(self, header: str | None) -> Principal:
        """Same contract as `Authenticator.authenticate`, for the dashboard."""
        if not self.enabled:
            return Principal(name="anonymous", role="admin", scopes={"admin"})
        if not header:
            raise OIDCError("missing Authorization header")
        parts = header.split(None, 1)
        if len(parts) != 2 or parts[0].lower() != "bearer":
            raise OIDCError("Authorization must be 'Bearer <token>'")
        supplied = parts[1].strip()
        if not supplied:
            raise OIDCError("empty bearer token")
        return self.verify(supplied)
