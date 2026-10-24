"""Tamper-evident audit ledger.

Every action an agent takes is appended as a hash-chained record:
    record_hash = SHA256(prev_hash || canonical_json(record))

Because each record commits to the previous hash, mutating or removing
any historical record breaks every subsequent hash. This gives auditors a
verifiable, append-only trail without trusting the operator.
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

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

    def compute_hash(self) -> str:
        body = {k: v for k, v in asdict(self).items() if k != "record_hash"}
        return hashlib.sha256((self.prev_hash + canonical(body)).encode()).hexdigest()


class AuditLedger:
    """Append-only, hash-chained ledger persisted as JSON Lines."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._records: list[AuditRecord] = []
        if self.path.exists():
            self._load()

    def _load(self) -> None:
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                self._records.append(AuditRecord(**json.loads(line)))

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
        rec.record_hash = rec.compute_hash()
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(canonical(asdict(rec)) + "\n")
        self._records.append(rec)
        return rec

    def verify(self) -> tuple[bool, str]:
        """Re-walk the chain. Returns (ok, message)."""
        prev = GENESIS
        for i, rec in enumerate(self._records, start=1):
            if rec.seq != i:
                return False, f"sequence gap at position {i} (got {rec.seq})"
            if rec.prev_hash != prev:
                return False, f"broken link at record {rec.seq}"
            if rec.record_hash != rec.compute_hash():
                return False, f"tampered record {rec.seq}"
            prev = rec.record_hash
        return True, f"chain intact ({len(self._records)} records)"

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
                    **r.metadata,
                },
            }
            for r in self._records
        ]
