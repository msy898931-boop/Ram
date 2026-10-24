"""Tamper-evident audit ledger.

Every action an agent takes is appended as a hash-chained record:
    record_hash = SHA256(prev_hash || canonical_json(record))

Because each record commits to the previous hash, mutating or removing
any historical record breaks every subsequent hash. This gives auditors a
verifiable, append-only trail without trusting the operator.

Signing (optional but recommended): when a Signer is supplied, each record
also carries an Ed25519 signature over its hash. Hashing alone proves a
record was not altered *after* the fact, but an operator who controls the
file could rewrite the whole chain and re-hash it. A signature with a key
the operator does not hold closes that gap: the auditor keeps the public
key, so a rewritten chain no longer verifies.
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .signing import Signer
from .signing import verify as verify_signature

GENESIS = "0" * 64


def canonical(obj: Any) -> str:
    """Deterministic JSON so hashes are reproducible across machines."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


@dataclass
class AuditRecord:
    seq: int
    timestamp: float
    actor: str
    action: str
    target: str = ""
    decision: str = ""  # allow | deny
    reason: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    prev_hash: str = GENESIS
    record_hash: str = ""
    signature: str = ""  # hex Ed25519 over the record hash, empty when unsigned
    key_fingerprint: str = ""  # identifies which key signed this record

    def compute_hash(self) -> str:
        """Hash the record body.

        `signature` never participates: it signs the hash, so including it
        would be circular. `key_fingerprint` is excluded for records written
        before signing existed, so ledgers created by an older version still
        verify instead of reporting a false tamper.
        """
        skip = {"record_hash", "signature"}
        if getattr(self, "_legacy", False):
            skip.add("key_fingerprint")
        body = {k: v for k, v in asdict(self).items() if k not in skip}
        return hashlib.sha256((self.prev_hash + canonical(body)).encode()).hexdigest()

    def signed_body(self) -> bytes:
        """What the signature covers: the record hash bound to its position."""
        return f"{self.seq}:{self.record_hash}".encode()


class AuditLedger:
    """Append-only, hash-chained ledger persisted as JSON Lines."""

    def __init__(self, path: str | Path, signer: Signer | None = None):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.signer = signer
        self._records: list[AuditRecord] = []
        if self.path.exists():
            self._load()

    def _load(self) -> None:
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            raw = json.loads(line)
            rec = AuditRecord(**raw)
            # Records written before signing existed hash only the original
            # fields. Remember that so verify() can still validate them.
            rec._legacy = "key_fingerprint" not in raw
            self._records.append(rec)

    @property
    def head(self) -> str:
        return self._records[-1].record_hash if self._records else GENESIS

    def append(
        self,
        actor: str,
        action: str,
        *,
        target: str = "",
        decision: str = "",
        reason: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> AuditRecord:
        rec = AuditRecord(
            seq=len(self._records) + 1,
            timestamp=time.time(),
            actor=actor,
            action=action,
            target=target,
            decision=decision,
            reason=reason,
            metadata=metadata or {},
            prev_hash=self.head,
        )
        if self.signer is not None:
            rec.key_fingerprint = self.signer.fingerprint
        rec.record_hash = rec.compute_hash()
        if self.signer is not None:
            rec.signature = self.signer.sign(rec.signed_body()).hex()
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(canonical(asdict(rec)) + "\n")
        self._records.append(rec)
        return rec

    def verify(self, public_key: bytes | None = None) -> tuple[bool, str]:
        """Re-walk the chain. Returns (ok, message).

        `public_key` is the auditor's copy of the signing key. Supplying it
        turns on strict mode: every record must then be signed *by that key*.
        Without this rule an attacker who controls the ledger file could
        simply delete every signature, leaving a chain that re-hashes cleanly
        and passes verification - which would make signing decorative.
        """
        expected_fp = (
            hashlib.sha256(public_key).hexdigest()[:16] if public_key else None
        )
        prev = GENESIS
        signed = 0
        for i, rec in enumerate(self._records, start=1):
            if rec.seq != i:
                return False, f"sequence gap at position {i} (got {rec.seq})"
            if rec.prev_hash != prev:
                return False, f"broken link at record {rec.seq}"
            if rec.record_hash != rec.compute_hash():
                return False, f"tampered record {rec.seq}"

            if rec.signature:
                signed += 1

            if expected_fp is not None:
                if not rec.signature:
                    return False, (
                        f"record {rec.seq} is unsigned but a public key was "
                        f"supplied - signature stripped or chain rewritten"
                    )
                if rec.key_fingerprint != expected_fp:
                    return False, (
                        f"record {rec.seq} signed by key {rec.key_fingerprint or '(none)'}, "
                        f"expected {expected_fp}"
                    )
                try:
                    sig = bytes.fromhex(rec.signature)
                except ValueError:
                    return False, f"malformed signature on record {rec.seq}"
                if not verify_signature(rec.signed_body(), sig, public_key):
                    return False, f"invalid signature on record {rec.seq}"
            prev = rec.record_hash

        detail = f"chain intact ({len(self._records)} records)"
        if expected_fp is not None:
            detail += f", {signed} signed and verified"
        elif signed:
            detail += (
                f", {signed} signed (no public key supplied - signatures present "
                f"but NOT checked)"
            )
        return True, detail

    def records(self) -> list[AuditRecord]:
        return list(self._records)

    def to_otel_spans(self) -> list[dict[str, Any]]:
        """Export as OpenTelemetry-shaped spans for the Observe module."""
        return [
            {
                "name": f"axon.{r.action}",
                "trace_id": uuid.uuid5(uuid.NAMESPACE_URL, f"axon/{r.seq}").hex,
                "start_time": r.timestamp,
                "attributes": {
                    "axon.actor": r.actor,
                    "axon.decision": r.decision,
                    "axon.target": r.target,
                    "axon.seq": r.seq,
                    "axon.signed": bool(r.signature),
                    **r.metadata,
                },
            }
            for r in self._records
        ]
