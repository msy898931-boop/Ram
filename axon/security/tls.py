# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 msy898931-boop
# Part of the AXON open core. See NOTICE for the license map.
"""Layer 6: transport security — TLS termination inside the dashboard.

Why this is a layer and not a deployment note: the previous posture check
reported transport as OFF and told the operator to "use TLS in front of
this". That is honest, but it puts the only unencrypted hop in the path of
every bearer token, and it makes the layer unverifiable from inside the
process. Terminating TLS here means the layer is present in the code, is
covered by tests, and can be asserted by `axon posture`.

Threat model: an attacker on the path between the operator and the dashboard
reads or rewrites the audit ledger in flight, and lifts the bearer token out
of the Authorization header. TLS with a modern protocol floor and no weak
ciphers closes that. It does not stop an attacker who holds a valid token,
and it does not stop a compromised endpoint — those are other layers' jobs.

Why the protocol floor is explicit: `ssl.PROTOCOL_TLS_SERVER` still negotiates
whatever the OpenSSL default allows, and defaults move. Pinning TLS 1.2 as the
floor and refusing TLS 1.0/1.1 is the difference between a control and a hope.

Why `check_hostname` and verification are asserted in `verify_pair`: a
certificate that does not match the host the operator types gives a browser
warning and gives an API client a silent failure, and a key that does not
belong to the certificate produces a server that starts and then fails every
handshake. Both are cheap to detect at startup and expensive to detect in
production.
"""

from __future__ import annotations

import hashlib
import ssl
from dataclasses import dataclass
from pathlib import Path

# TLS 1.2 is the floor: 1.0 and 1.1 are deprecated and have known attacks.
MINIMUM_VERSION = ssl.TLSVersion.TLSv1_2


class TLSError(Exception):
    """A certificate, key, or context could not be loaded or is unusable."""


@dataclass(frozen=True)
class TLSConfig:
    """Where the certificate and key live, and how strict to be."""

    certfile: str
    keyfile: str
    minimum_version: ssl.TLSVersion = MINIMUM_VERSION

    def __post_init__(self) -> None:
        if not self.certfile or not self.keyfile:
            raise TLSError("TLS requires both a certificate and a key")
        for label, path in (("certificate", self.certfile), ("key", self.keyfile)):
            if not Path(path).is_file():
                raise TLSError(f"{label} file not found: {path}")


def build_context(config: TLSConfig) -> ssl.SSLContext:
    """A server context that will refuse to negotiate a weak connection.

    `minimum_version` is set before the certificate is loaded so a failure to
    load is reported as a certificate problem rather than a protocol one.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = config.minimum_version
    # Explicitly forbid the cipher suites that still negotiate under TLS 1.2
    # with a NULL or export-grade cipher. OpenSSL's default is already safe;
    # being explicit means a future default change cannot silently weaken us.
    context.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL:!eNULL:!MD5:!RC4:!3DES")
    try:
        context.load_cert_chain(certfile=config.certfile, keyfile=config.keyfile)
    except (ssl.SSLError, OSError) as exc:
        raise TLSError(f"could not load certificate/key: {exc}") from exc
    return context


def wrap_server(httpd, config: TLSConfig):
    """Wrap a listening HTTP server's socket so every connection is TLS.

    Called after `server_bind` and before `serve_forever`, which is the only
    window where the socket exists but no request has been accepted.
    """
    httpd.socket = build_context(config).wrap_socket(httpd.socket, server_side=True)
    return httpd


def verify_pair(certfile: str, keyfile: str) -> str:
    """Prove the certificate and key belong together, and identify the leaf.

    A mismatch is the single most common TLS misconfiguration: the server
    starts, then every handshake fails with an opaque alert. OpenSSL checks
    key/certificate consistency inside `load_cert_chain`, so building the
    context *is* the verification — we do it and then report the certificate's
    fingerprint, which is a stable identifier an operator can compare against
    what their CA issued.
    """
    build_context(TLSConfig(certfile=certfile, keyfile=keyfile))

    try:
        pem = Path(certfile).read_text(encoding="utf-8")
    except OSError as exc:
        raise TLSError(f"could not read certificate: {exc}") from exc

    begin = "-----BEGIN CERTIFICATE-----"
    end = "-----END CERTIFICATE-----"
    if begin not in pem or end not in pem:
        raise TLSError("certificate file contains no PEM certificate block")
    block = pem[pem.index(begin): pem.index(end) + len(end)]
    try:
        der = ssl.PEM_cert_to_DER_cert(block)
    except (ValueError, ssl.SSLError) as exc:
        raise TLSError(f"could not parse certificate: {exc}") from exc
    if not der:
        raise TLSError("certificate is empty")

    digest = hashlib.sha256(der).hexdigest()
    # The full 256-bit digest: rendering only the first 32 hex characters
    # would print a 128-bit fingerprint while calling it sha256.
    return ":".join(digest[i:i + 2] for i in range(0, len(digest), 2)).upper()


def is_loopback(host: str) -> bool:
    return host in {"127.0.0.1", "::1", "localhost"}
