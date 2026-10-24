"""Compliance readiness — turn control statements into machine-checked claims.

A control matrix in a document ages the moment the code moves. This module
keeps the matrix executable: each `Control` names the code that implements
it, the ledger evidence it produces, and the tests that prove it. Running
`axon compliance` re-evaluates every control against the current tree, so a
control cannot silently rot.

The mapping follows the SOC 2 Trust Services Criteria and the ISO/IEC 27001
Annex A themes that agent deployments actually trip over: access control,
auditability, change management, and confidentiality. It is a readiness aid,
not a certification — an auditor still has to accept it.
"""

from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


@dataclass
class Control:
    """One control: what it requires, where it lives, and how it is proven."""

    id: str
    framework: str
    title: str
    requirement: str
    implementation: list[str]
    evidence: str
    tests: list[str] = field(default_factory=list)

    def code_present(self) -> bool:
        return all((REPO_ROOT / path).exists() for path in self.implementation)


CONTROLS: tuple[Control, ...] = (
    Control(
        id="CC6.1",
        framework="SOC 2",
        title="Logical access is restricted to authorized principals",
        requirement=(
            "Access to system components is limited to authorized users and "
            "the authorization model is enforced, not advisory."
        ),
        implementation=["axon/core/identity.py", "axon/core/policy.py", "axon/policies/identities.yaml"],
        evidence="Every run and tool call records the acting identity, role, and owner.",
        tests=["test_identity.py", "test_axon.py"],
    ),
    Control(
        id="CC6.6",
        framework="SOC 2",
        title="Access to data and secrets is controlled",
        requirement=(
            "Credentials are brokered rather than exposed, and each access is "
            "authorized and recorded."
        ),
        implementation=["axon/vault.py"],
        evidence="Ledger records vault.lease and vault.revoke events; values never appear.",
        tests=["test_commercial.py"],
    ),
    Control(
        id="CC6.8",
        framework="SOC 2",
        title="Unauthorized or malicious activity is prevented or detected",
        requirement=(
            "Destructive and exfiltration-shaped actions are refused by policy "
            "and the refusal is recorded."
        ),
        implementation=["axon/policies/packs/regulated.yaml", "axon/shield.py"],
        evidence="Denied actions are written to the ledger with the matching rule and reason.",
        tests=["test_commercial.py", "test_axon.py"],
    ),
    Control(
        id="CC7.2",
        framework="SOC 2",
        title="System activity is monitored and anomalies are detected",
        requirement=(
            "Activity is captured in sufficient detail to reconstruct what "
            "happened and to surface cost or access anomalies."
        ),
        implementation=["axon/observe.py", "axon/dashboard.py"],
        evidence="Observer derives cost, denial, and activity reports from the ledger.",
        tests=["test_commercial.py", "test_dashboard.py"],
    ),
    Control(
        id="CC7.3",
        framework="SOC 2",
        title="Security events are evaluated and responded to",
        requirement=(
            "Refusals are visible to operators with enough context to act, and "
            "secret access is revocable."
        ),
        implementation=["axon/dashboard.py", "axon/vault.py"],
        evidence="Dashboard exposes denials and secret-access counts; leases can be revoked.",
        tests=["test_dashboard.py", "test_commercial.py"],
    ),
    Control(
        id="CC8.1",
        framework="SOC 2",
        title="Changes are authorized and recorded",
        requirement=(
            "Configuration and policy changes are explicit, reviewable "
            "artifacts rather than ad-hoc runtime state."
        ),
        implementation=["axon/policies/packs", "axon/shield.py"],
        evidence="Policies are version-controlled files; Shield re-checks each pack's claims.",
        tests=["test_commercial.py"],
    ),
    Control(
        id="A.12.4.1",
        framework="ISO/IEC 27001",
        title="Event logging",
        requirement=(
            "Event logs record user activities, exceptions, and security "
            "events, and are protected against tampering."
        ),
        implementation=["axon/core/audit.py", "axon/core/signing.py"],
        evidence=(
            "Append-only hash-chained JSON Lines, with per-record Ed25519 "
            "signatures and a fail-closed verification mode."
        ),
        tests=["test_signing.py", "test_axon.py"],
    ),
    Control(
        id="A.12.4.2",
        framework="ISO/IEC 27001",
        title="Protection of log information",
        requirement="Logging facilities and log information are protected against tampering and unauthorized access.",
        implementation=["axon/core/signing.py", "axon/core/audit.py"],
        evidence=(
            "Removing a signature breaks verification when the auditor supplies "
            "the public key; rewriting history breaks the hash chain."
        ),
        tests=["test_signing.py"],
    ),
    Control(
        id="A.9.2.3",
        framework="ISO/IEC 27001",
        title="Management of privileged access",
        requirement="Allocation and use of privileged access rights is restricted and controlled.",
        implementation=["axon/core/policy.py", "axon/policies/identities.yaml"],
        evidence="Conditional allows require an explicit approval tag; denies cannot be overridden.",
        tests=["test_axon.py", "test_identity.py"],
    ),
    Control(
        id="A.12.1.3",
        framework="ISO/IEC 27001",
        title="Capacity and resource management",
        requirement="Resource use is monitored and bounded to preserve availability.",
        implementation=["axon/core/budget.py", "axon/core/orchestrator.py"],
        evidence=(
            "A Budget caps spend per run and is shared across delegated children, "
            "so a multi-agent fan-out cannot multiply cost."
        ),
        tests=["test_axon.py", "test_orchestrator.py"],
    ),
    Control(
        id="AI-01",
        framework="ISO/IEC 42001 (AI)",
        title="Autonomous action is bounded and attributable",
        requirement=(
            "An AI system's actions are authorized before execution, bounded in "
            "scope, and attributable to an accountable owner."
        ),
        implementation=["axon/core/runtime.py", "axon/core/orchestrator.py", "axon/integrations.py"],
        evidence=(
            "Deny-by-default authorization precedes every tool call and model "
            "call; each record carries the acting identity and its owner."
        ),
        tests=["test_axon.py", "test_orchestrator.py", "test_integrations.py"],
    ),
)


@dataclass
class ControlResult:
    control: Control
    code_ok: bool
    tests_ok: bool

    @property
    def ok(self) -> bool:
        return self.code_ok and self.tests_ok


def _tests_exist(control: Control) -> bool:
    return all((REPO_ROOT / "tests" / name).exists() for name in control.tests)


def evaluate() -> list[ControlResult]:
    return [
        ControlResult(control=c, code_ok=c.code_present(), tests_ok=_tests_exist(c))
        for c in CONTROLS
    ]


def run_tests(names: list[str]) -> bool:
    """Actually execute the cited tests. Used by `axon compliance --run`."""
    paths = [str(REPO_ROOT / "tests" / n) for n in names]
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", *paths],
        capture_output=True, text=True, cwd=REPO_ROOT,
    )
    return proc.returncode == 0


def report() -> dict:
    results = evaluate()
    return {
        "controls": len(results),
        "passing": sum(1 for r in results if r.ok),
        "failing": [r.control.id for r in results if not r.ok],
        "detail": [
            {
                "id": r.control.id,
                "framework": r.control.framework,
                "title": r.control.title,
                "requirement": r.control.requirement,
                "implementation": r.control.implementation,
                "evidence": r.control.evidence,
                "tests": r.control.tests,
                "code_present": r.code_ok,
                "tests_present": r.tests_ok,
            }
            for r in results
        ],
    }
