"""AXON Shield — opinionated policy packs and an enforcement self-check.

Most teams do not want to invent a policy language before they can run an
agent safely. Shield ships named packs that encode what a given environment
should look like, plus a checker that reports whether a policy actually
enforces what its name claims.

`check()` is the part that matters commercially. A policy file is only
worth what it refuses, so Shield tests the loaded engine against a battery
of actions that must be denied and actions that must be allowed, and fails
loudly when reality disagrees with intent. That is a control an auditor can
run, not a paragraph of documentation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Sequence

import yaml

from .core.policy import PolicyEngine, Rule

PACKS_DIR = Path(__file__).resolve().parent / "policies" / "packs"


@dataclass
class Probe:
    """One expectation: an action that must be allowed or denied."""

    action: str
    target: str = ""
    actor: str = "*"
    tags: tuple[str, ...] = ()
    must_allow: bool = False


@dataclass
class Finding:
    probe: Probe
    actual: str

    @property
    def ok(self) -> bool:
        return (self.actual == "allow") == self.probe.must_allow

    def describe(self) -> str:
        want = "allow" if self.probe.must_allow else "deny"
        return (
            f"{'PASS' if self.ok else 'FAIL'}: {self.probe.action}"
            f"{' -> ' + self.probe.target if self.probe.target else ''} "
            f"expected {want}, got {self.actual}"
        )


@dataclass
class CheckReport:
    findings: list[Finding] = field(default_factory=list)

    @property
    def failures(self) -> list[Finding]:
        return [f for f in self.findings if not f.ok]

    @property
    def ok(self) -> bool:
        return not self.failures

    def as_dict(self) -> dict:
        return {
            "ok": self.ok,
            "passed": len(self.findings) - len(self.failures),
            "failed": len(self.failures),
            "findings": [f.describe() for f in self.findings],
        }


# What any AXON policy must refuse, regardless of environment. These are the
# invariants the product is sold on, so they are checked against every pack.
#
# Pack-specific expectations live in each pack's `shield.probes` block rather
# than here: a development pack legitimately allows delegation while a
# regulated one does not, so only the genuinely universal refusals belong in
# the baseline.
BASELINE_PROBES: tuple[Probe, ...] = (
    Probe("tool.read_file", "/home/user/secrets.txt"),
    Probe("tool.read_file", "/app/.env"),
    Probe("tool.write_file", "/etc/passwd"),
    Probe("tool.delete_everything"),
)


def _probes_from_data(data: dict) -> list[Probe]:
    out: list[Probe] = []
    for raw in (data.get("shield") or {}).get("probes", []) or []:
        out.append(
            Probe(
                action=raw["action"],
                target=raw.get("target", ""),
                actor=raw.get("actor", "*"),
                tags=tuple(raw.get("tags", []) or []),
                must_allow=bool(raw.get("must_allow", False)),
            )
        )
    return out


class Shield:
    """Loads, validates, and applies policy packs."""

    def __init__(self, engine: PolicyEngine):
        self.engine = engine

    @classmethod
    def from_pack(cls, name: str) -> "Shield":
        return cls(load_pack(name))

    def check(self, probes: Sequence[Probe] = BASELINE_PROBES) -> CheckReport:
        report = CheckReport()
        for probe in probes:
            decision = self.engine.evaluate(
                probe.actor, probe.action, probe.target, set(probe.tags)
            )
            report.findings.append(
                Finding(probe=probe, actual="allow" if decision.allowed else "deny")
            )
        return report

    def explain(self, actor: str, action: str, target: str = "", tags: Iterable[str] = ()) -> dict:
        """Why an action resolves the way it does — the rule that decided it."""
        decision = self.engine.evaluate(actor, action, target, set(tags))
        return {
            "actor": actor,
            "action": action,
            "target": target,
            "allowed": decision.allowed,
            "reason": decision.reason,
        }


def available_packs() -> list[str]:
    if not PACKS_DIR.exists():
        return []
    return sorted(p.stem for p in PACKS_DIR.glob("*.yaml"))


def load_pack(name: str) -> PolicyEngine:
    path = _pack_path(name)
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return PolicyEngine([Rule(**r) for r in data.get("rules", [])])


def _pack_path(name: str) -> Path:
    path = PACKS_DIR / f"{name}.yaml"
    if not path.exists():
        raise FileNotFoundError(
            f"unknown policy pack '{name}' (available: {', '.join(available_packs()) or 'none'})"
        )
    return path


def pack_probes(name: str) -> list[Probe]:
    """The expectations a pack declares about itself."""
    data = yaml.safe_load(_pack_path(name).read_text(encoding="utf-8")) or {}
    return _probes_from_data(data)


def check_pack(name: str) -> CheckReport:
    """Check a pack against the baseline plus its own declared expectations."""
    probes = list(BASELINE_PROBES) + pack_probes(name)
    return Shield(load_pack(name)).check(probes)


def validate_file(path: str | Path) -> CheckReport:
    """Run the baseline probes against a policy file on disk."""
    return Shield(PolicyEngine.from_yaml(path)).check()
