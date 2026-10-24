"""AXON Observe — cost, risk, and activity analytics over the audit ledger.

The ledger already holds every decision. Observe turns it into the three
questions a buyer actually asks:

  * What did this cost, and per agent / per model?  (`cost_report`)
  * What was refused, and why?                       (`risk_report`)
  * Is the trail intact, and is it signed?           (`integrity_report`)

Everything here is derived, never authoritative: it reads the ledger and
computes. That means it cannot disagree with the ledger, and an auditor can
reproduce any number by re-running the same functions over the same file.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .core.audit import AuditLedger


@dataclass
class CostBucket:
    key: str
    calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0

    def as_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "calls": self.calls,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "cost_usd": round(self.cost_usd, 6),
        }


@dataclass
class CostReport:
    total_usd: float = 0.0
    total_calls: int = 0
    by_agent: list[CostBucket] = field(default_factory=list)
    by_model: list[CostBucket] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "total_usd": round(self.total_usd, 6),
            "total_calls": self.total_calls,
            "by_agent": [b.as_dict() for b in self.by_agent],
            "by_model": [b.as_dict() for b in self.by_model],
        }


@dataclass
class Denial:
    seq: int
    actor: str
    action: str
    target: str
    reason: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "seq": self.seq, "actor": self.actor, "action": self.action,
            "target": self.target, "reason": self.reason,
        }


@dataclass
class RiskReport:
    denials: list[Denial] = field(default_factory=list)
    by_actor: dict[str, int] = field(default_factory=dict)
    by_action: dict[str, int] = field(default_factory=dict)
    secret_access: int = 0

    @property
    def total(self) -> int:
        return len(self.denials)

    def as_dict(self) -> dict[str, Any]:
        return {
            "total_denials": self.total,
            "by_actor": self.by_actor,
            "by_action": self.by_action,
            "secret_access_attempts": self.secret_access,
            "denials": [d.as_dict() for d in self.denials],
        }


@dataclass
class IntegrityReport:
    ok: bool
    message: str
    records: int
    signed: int
    key_fingerprints: list[str] = field(default_factory=list)

    @property
    def fully_signed(self) -> bool:
        return self.records > 0 and self.signed == self.records

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "message": self.message,
            "records": self.records,
            "signed": self.signed,
            "fully_signed": self.fully_signed,
            "key_fingerprints": self.key_fingerprints,
        }


class Observer:
    """Read-only analytics over one ledger."""

    def __init__(self, ledger: AuditLedger):
        self.ledger = ledger

    def cost_report(self) -> CostReport:
        report = CostReport()
        agents: dict[str, CostBucket] = {}
        models: dict[str, CostBucket] = {}

        for rec in self.ledger.records():
            if rec.action != "model.usage":
                continue
            cost = float(rec.metadata.get("cost_usd", 0.0))
            in_tok = int(rec.metadata.get("input_tokens", 0))
            out_tok = int(rec.metadata.get("output_tokens", 0))

            report.total_usd += cost
            report.total_calls += 1

            bucket = agents.setdefault(rec.actor, CostBucket(key=rec.actor))
            bucket.calls += 1
            bucket.input_tokens += in_tok
            bucket.output_tokens += out_tok
            bucket.cost_usd += cost

            model = rec.target or "unknown"
            mbucket = models.setdefault(model, CostBucket(key=model))
            mbucket.calls += 1
            mbucket.input_tokens += in_tok
            mbucket.output_tokens += out_tok
            mbucket.cost_usd += cost

        report.by_agent = sorted(agents.values(), key=lambda b: -b.cost_usd)
        report.by_model = sorted(models.values(), key=lambda b: -b.cost_usd)
        return report

    def risk_report(self) -> RiskReport:
        report = RiskReport()
        for rec in self.ledger.records():
            if rec.action.startswith("vault."):
                report.secret_access += 1
            if rec.decision != "deny":
                continue
            report.denials.append(
                Denial(seq=rec.seq, actor=rec.actor, action=rec.action,
                       target=rec.target, reason=rec.reason)
            )
            report.by_actor[rec.actor] = report.by_actor.get(rec.actor, 0) + 1
            report.by_action[rec.action] = report.by_action.get(rec.action, 0) + 1
        return report

    def integrity_report(self, public_key: bytes | None = None) -> IntegrityReport:
        ok, message = self.ledger.verify(public_key=public_key)
        records = self.ledger.records()
        signed = sum(1 for r in records if r.signature)
        fps = sorted({r.key_fingerprint for r in records if r.key_fingerprint})
        return IntegrityReport(
            ok=ok, message=message, records=len(records), signed=signed, key_fingerprints=fps
        )

    def activity_by_agent(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for rec in self.ledger.records():
            counts[rec.actor] = counts.get(rec.actor, 0) + 1
        return dict(sorted(counts.items(), key=lambda kv: -kv[1]))

    def runs(self) -> list[dict[str, Any]]:
        """Group records into runs by `run_id`, newest first."""
        grouped: dict[str, dict[str, Any]] = {}
        for rec in self.ledger.records():
            run_id = rec.metadata.get("run_id")
            if not run_id:
                continue
            entry = grouped.setdefault(
                run_id,
                {"run_id": run_id, "actor": rec.actor, "start": rec.timestamp,
                 "records": 0, "denied": 0, "cost_usd": 0.0},
            )
            entry["records"] += 1
            if rec.decision == "deny":
                entry["denied"] += 1
            entry["cost_usd"] += float(rec.metadata.get("cost_usd", 0.0))
        out = sorted(grouped.values(), key=lambda e: -e["start"])
        for entry in out:
            entry["cost_usd"] = round(entry["cost_usd"], 6)
        return out

    def summary(self, public_key: bytes | None = None) -> dict[str, Any]:
        """Everything a dashboard header needs, in one call."""
        return {
            "cost": self.cost_report().as_dict(),
            "risk": {
                "total_denials": self.risk_report().total,
                "by_actor": self.risk_report().by_actor,
                "secret_access_attempts": self.risk_report().secret_access,
            },
            "integrity": self.integrity_report(public_key).as_dict(),
            "activity": self.activity_by_agent(),
            "runs": self.runs(),
        }
