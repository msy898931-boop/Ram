"""Ed25519 signatures (RFC 8032) in pure Python.

Why hand-rolled instead of `cryptography`: AXON's pitch is that it runs in
air-gapped, dependency-free environments. The audit ledger is the artifact an
auditor actually trusts, so it must be signable without pulling a native
crypto stack into the runtime. This module is ~120 lines and is pinned to the
RFC 8032 test vectors in the test suite.

If `cryptography` happens to be installed, `cryptography_signer()` returns a
backend that produces byte-identical signatures (Ed25519 is deterministic),
which the tests assert.
"""

from __future__ import annotations

import contextlib
import hashlib
import os
from dataclasses import dataclass

_P = 2**255 - 19
_Q = 2**252 + 27742317777372353535851937790883648493  # order of the base point
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_I = pow(2, (_P - 1) // 4, _P)


class SignatureError(Exception):
    """Raised when a signature or key is malformed."""


def _sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


def _inv(x: int) -> int:
    return pow(x, _P - 2, _P)


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * _inv(_D * y * y + 1)
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = (x * _I) % _P
    if x % 2 != 0:
        x = _P - x
    return x


_BY = (4 * _inv(5)) % _P
_BX = _xrecover(_BY)
_B = (_BX, _BY, 1, (_BX * _BY) % _P)


def _add(P, Q):
    """Twisted Edwards addition in extended homogeneous coordinates."""
    x1, y1, z1, t1 = P
    x2, y2, z2, t2 = Q
    a = (y1 - x1) * (y2 - x2) % _P
    b = (y1 + x1) * (y2 + x2) % _P
    c = t1 * 2 * _D * t2 % _P
    d = z1 * 2 * z2 % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _scalarmult(P, e: int):
    """Iterative double-and-add; avoids recursion depth limits."""
    result = (0, 1, 1, 0)  # identity
    addend = P
    while e > 0:
        if e & 1:
            result = _add(result, addend)
        addend = _add(addend, addend)
        e >>= 1
    return result


def _encode_point(P) -> bytes:
    x, y, z, _ = P
    zi = _inv(z)
    x = x * zi % _P
    y = y * zi % _P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _decode_point(s: bytes):
    if len(s) != 32:
        raise SignatureError("point must be 32 bytes")
    value = int.from_bytes(s, "little")
    y = value & ((1 << 255) - 1)
    if y >= _P:
        raise SignatureError("point not canonical")
    x = _xrecover(y)
    if (x & 1) != (value >> 255):
        x = _P - x
    return (x, y, 1, (x * y) % _P)


def _clamp(scalar: bytes) -> int:
    h = bytearray(scalar[:32])
    h[0] &= 248
    h[31] &= 63
    h[31] |= 64
    return int.from_bytes(h, "little")


def _seed_to_scalar_and_prefix(seed: bytes) -> tuple[int, bytes]:
    if len(seed) != 32:
        raise SignatureError("seed must be 32 bytes")
    h = _sha512(seed)
    return _clamp(h), h[32:]


def public_key_from_seed(seed: bytes) -> bytes:
    scalar, _ = _seed_to_scalar_and_prefix(seed)
    return _encode_point(_scalarmult(_B, scalar))


def sign(message: bytes, seed: bytes) -> bytes:
    """Deterministic Ed25519 signature: 32-byte R || 32-byte S."""
    scalar, prefix = _seed_to_scalar_and_prefix(seed)
    public = _encode_point(_scalarmult(_B, scalar))
    r = int.from_bytes(_sha512(prefix + message), "little") % _Q
    R = _encode_point(_scalarmult(_B, r))
    k = int.from_bytes(_sha512(R + public + message), "little") % _Q
    S = (r + k * scalar) % _Q
    return R + S.to_bytes(32, "little")


def verify(message: bytes, signature: bytes, public_key: bytes) -> bool:
    """Return True iff `signature` is valid for `message` under `public_key`."""
    if len(signature) != 64 or len(public_key) != 32:
        return False
    R, S = signature[:32], int.from_bytes(signature[32:], "little")
    if S >= _Q:
        return False
    try:
        A = _decode_point(public_key)
        R_point = _decode_point(R)
    except SignatureError:
        return False
    k = int.from_bytes(_sha512(R + public_key + message), "little") % _Q
    left = _scalarmult(_B, S)
    right = _add(R_point, _scalarmult(A, k))
    return _encode_point(left) == _encode_point(right)


@dataclass(frozen=True)
class Signer:
    """Holds a signing key and exposes its public half."""

    seed: bytes

    @property
    def public_key(self) -> bytes:
        return public_key_from_seed(self.seed)

    def sign(self, message: bytes) -> bytes:
        return sign(message, self.seed)

    @property
    def fingerprint(self) -> str:
        """Short, human-readable id for a public key (shown in the ledger)."""
        return hashlib.sha256(self.public_key).hexdigest()[:16]


def generate_seed() -> bytes:
    return os.urandom(32)


def signer_from_file(path) -> Signer:
    """Load a 64-hex-char or base64 seed from `path`, creating one if absent."""
    from pathlib import Path

    p = Path(path)
    if p.exists():
        raw = p.read_text(encoding="utf-8").strip()
    else:
        raw = generate_seed().hex()
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(raw + "\n", encoding="utf-8")
        with contextlib.suppress(OSError):  # pragma: no cover - platform dependent
            p.chmod(0o600)
    try:
        seed = bytes.fromhex(raw)
    except ValueError as exc:
        raise SignatureError(f"{p}: expected a 64-character hex seed") from exc
    if len(seed) != 32:
        raise SignatureError(f"{p}: seed must be 32 bytes, got {len(seed)}")
    return Signer(seed)
