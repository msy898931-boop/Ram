"""AXON Vault — policy-gated secret brokering with audit.

The problem this solves: agents need credentials, and the usual answer is to
put them in the environment, where the agent can read them, log them, or
exfiltrate them. Vault inverts that. The agent never sees a secret value; it
asks for a *lease*, the request is policy-checked like any other action, the
value is resolved at the last moment, and the access is recorded.

Design choices worth naming:

  * Secrets live behind a resolver, not in AXON. `EnvResolver` is the default
    for local use; a production deployment supplies its own (Vault, AWS
    Secrets Manager, KMS) by implementing `Resolver.fetch`.
  * A lease is single-use and short-lived by default. Reuse and long TTLs
    are opt-in, so the common case leaks nothing.
  * Values are never written to the ledger. The ledger records that a lease
    was issued, for which key, to whom, and when — never the secret itself.
  * Redaction is available for the other direction: scrubbing known secret
    values out of model output before it is stored or returned.
"""

from __future__ import annotations

import os
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Protocol

from .core.audit import AuditLedger


class SecretNotFound(Exception):
    pass


class LeaseError(Exception):
    pass


class Resolver(Protocol):
    """A source of secret material. Implement `fetch` to plug in a backend."""

    def fetch(self, key: str) -> str:  # pragma: no cover - protocol
        ...


class EnvResolver:
    """Reads secrets from the process environment.

    Suitable for local development and CI. In production, prefer a backend
    that issues short-lived credentials so a leaked lease expires on its own.
    """

    def __init__(self, prefix: str = "AXON_SECRET_"):
        self.prefix = prefix

    def fetch(self, key: str) -> str:
        name = key if key.startswith(self.prefix) else self.prefix + key.upper().replace("-", "_")
        try:
            return os.environ[name]
        except KeyError:
            raise SecretNotFound(f"no environment variable {name}") from None


class MappingResolver:
    """In-memory resolver, primarily for tests and embedded use."""

    def __init__(self, values: dict[str, str]):
        self._values = dict(values)

    def fetch(self, key: str) -> str:
        try:
            return self._values[key]
        except KeyError:
            raise SecretNotFound(f"unknown secret '{key}'") from None


@dataclass
class Lease:
    """A time-bounded grant of access to one secret."""

    lease_id: str
    key: str
    expires_at: float
    reusable: bool = False
    _value: str = field(default="", repr=False)
    _consumed: bool = False

    @property
    def expired(self) -> bool:
        return time.time() > self.expires_at

    @property
    def ttl_seconds(self) -> float:
        return max(0.0, self.expires_at - time.time())

    def reveal(self) -> str:
        if self.expired:
            raise LeaseError(f"lease {self.lease_id} for '{self.key}' expired")
        if self._consumed and not self.reusable:
            raise LeaseError(f"lease {self.lease_id} for '{self.key}' already used")
        self._consumed = True
        return self._value


class SecretVault:
    """Issues audited leases for secrets, gated by the agent's policy."""

    def __init__(
        self,
        *,
        resolver: Resolver,
        ledger: AuditLedger,
        default_ttl: float = 60.0,
    ):
        self.resolver = resolver
        self.ledger = ledger
        self.default_ttl = default_ttl
        self._leases: dict[str, Lease] = {}
        self._redaction_values: set[str] = set()

    def issue(
        self,
        agent: str,
        key: str,
        *,
        ttl: float | None = None,
        reusable: bool = False,
        authorizer: Callable[[str, str], None] | None = None,
    ) -> Lease:
        """Authorize, fetch, and record a lease.

        `authorizer` is the runtime's `_authorize` hook. Passing it keeps
        secret access inside the same policy engine as every other action,
        so a policy that denies `vault.read` denies the secret too.
        """
        if authorizer is not None:
            authorizer("vault.read", key)
        value = self.resolver.fetch(key)
        ttl = self.default_ttl if ttl is None else ttl
        if ttl <= 0:
            raise LeaseError("ttl must be positive")
        lease = Lease(
            lease_id=uuid.uuid4().hex[:12],
            key=key,
            expires_at=time.time() + ttl,
            reusable=reusable,
            _value=value,
        )
        self._leases[lease.lease_id] = lease
        self._redaction_values.add(value)
        self.ledger.append(
            agent,
            "vault.lease",
            target=key,
            decision="allow",
            reason="lease issued",
            metadata={"lease_id": lease.lease_id, "ttl_seconds": ttl, "reusable": reusable},
        )
        return lease

    def revoke(self, lease_id: str, *, agent: str = "system") -> bool:
        lease = self._leases.pop(lease_id, None)
        if lease is None:
            return False
        lease._consumed = True
        lease._value = ""
        self.ledger.append(
            agent, "vault.revoke", target=lease.key, decision="allow",
            metadata={"lease_id": lease_id},
        )
        return True

    def redact(self, text: str) -> str:
        """Replace any known secret value with a marker.

        Intended for model output and log lines: anything the agent could
        echo back gets scrubbed before it is persisted.
        """
        for value in sorted(self._redaction_values, key=len, reverse=True):
            if value:
                text = text.replace(value, "[REDACTED]")
        return text

    def active_leases(self) -> list[Lease]:
        return [lease for lease in self._leases.values() if not lease.expired]
