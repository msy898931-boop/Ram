"""End-to-end AXON demo: a governed agent run you can show investors.

Run:  python3 examples/demo.py
"""

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from axon.core.audit import AuditLedger
from axon.core.budget import Budget, BudgetExceeded
from axon.core.policy import PolicyEngine
from axon.core.providers import MockProvider
from axon.core.runtime import AgentRuntime, PolicyDenied

POLICY = Path(__file__).resolve().parent.parent / "axon" / "policies" / "default.yaml"


def banner(text):
    print(f"\n\033[1;36m{'=' * 62}\n  {text}\n{'=' * 62}\033[0m")


def main():
    tmp = tempfile.mkdtemp()
    ledger = AuditLedger(Path(tmp) / "audit.jsonl")
    runtime = AgentRuntime(
        agent_id="support-agent",
        ledger=ledger,
        policy=PolicyEngine.from_yaml(POLICY),
        budget=Budget(limit_usd=0.50),
        provider=MockProvider(),
    )

    banner("1. Agent runs a task with a sandboxed file read (allowed)")
    res = runtime.run(
        "Read the release notes and summarise them",
        model="claude-sonnet",
        tools={"read_file": ("/sandbox/notes.txt", lambda: "v1.2 fixed the login bug")},
    )
    print(f"  outputs: {len(res.outputs)}  tools: {len(res.tool_results)}  denied: {res.denied}")
    print(f"  tool result: {res.tool_results[0].output}")

    banner("2. Agent tries to read production secrets (DENIED by policy)")
    res2 = runtime.run(
        "Find the database password",
        model="claude-sonnet",
        tools={"read_file": ("/home/deploy/secrets/db.txt", lambda: "SHOULD-NEVER-RUN")},
    )
    print(f"  denied: {res2.denied}")
    print(f"  tool result: {res2.tool_results[0].output[:90]}")

    banner("3. Agent tries a production write without approval (DENIED)")
    res3 = runtime.run(
        "Deploy to production",
        model="claude-sonnet",
        tools={"write_file": ("/prod/app/config.yml", lambda: "wrote prod")},
    )
    print(f"  denied: {res3.denied}")

    banner("4. Cost cap stops a runaway loop before it burns budget")
    tight = AgentRuntime(
        agent_id="loop-agent",
        ledger=ledger,
        policy=PolicyEngine.from_yaml(POLICY),
        budget=Budget(limit_usd=0.000001),
        provider=MockProvider(),
    )
    try:
        tight.run("loop forever", model="claude-sonnet")
    except BudgetExceeded as exc:
        print(f"  \033[1;31mSTOPPED:\033[0m {exc}")

    banner("5. Auditor verifies the tamper-evident ledger")
    ok, msg = ledger.verify()
    print(f"  verify() -> {ok}  ({msg})")
    print(f"  total records: {len(ledger.records())}")
    print("  last 3 events:")
    for rec in ledger.records()[-3:]:
        print(f"    #{rec.seq:<3} {rec.actor:<14} {rec.action:<22} {rec.decision:<6} {rec.record_hash[:12]}…")

    banner("6. Tamper attempt is detected")
    ledger._records[1].actor = "attacker"
    ok, msg = ledger.verify()
    print(f"  after mutating record #2 -> verify() = {ok}  ({msg})")

    print("\n\033[1;32mDemo complete. Governance, cost control, and audit all enforced.\033[0m\n")


if __name__ == "__main__":
    main()
