"""AXON MVP test suite — exercises real code paths, no mocks of our own logic."""

import os
import tempfile

import pytest

from axon.core.audit import GENESIS, AuditLedger
from axon.core.budget import Budget, BudgetExceeded
from axon.core.policy import PolicyEngine, Rule
from axon.core.providers import MockProvider, Usage, price_for
from axon.core.runtime import AgentRuntime

POLICY = os.path.join(os.path.dirname(__file__), "..", "axon", "policies", "default.yaml")


@pytest.fixture
def ledger():
    with tempfile.TemporaryDirectory() as d:
        yield AuditLedger(os.path.join(d, "audit.jsonl"))


def make_runtime(ledger, budget_usd=10.0, agent="agent-1"):
    return AgentRuntime(
        agent_id=agent,
        ledger=ledger,
        policy=PolicyEngine.from_yaml(POLICY),
        budget=Budget(limit_usd=budget_usd),
        provider=MockProvider(),
    )


# --- audit ledger ---------------------------------------------------------

def test_ledger_chains_and_verifies(ledger):
    ledger.append("a", "run.start")
    ledger.append("a", "model.complete", decision="allow")
    ledger.append("a", "tool.read_file", decision="deny")
    ok, msg = ledger.verify()
    assert ok, msg
    assert ledger.records()[0].prev_hash == GENESIS


def test_ledger_detects_tampering(ledger):
    ledger.append("a", "run.start")
    ledger.append("a", "model.complete", decision="allow")
    ledger._records[0].actor = "attacker"  # mutate history
    ok, msg = ledger.verify()
    assert not ok and "tampered" in msg


def test_ledger_persists_and_reloads(ledger):
    ledger.append("a", "run.start")
    reloaded = AuditLedger(ledger.path)
    ok, _ = reloaded.verify()
    assert ok and len(reloaded.records()) == 1


# --- policy engine --------------------------------------------------------

def test_policy_denies_by_default():
    engine = PolicyEngine([Rule(action="tool.read_file", effect="allow")])
    assert engine.evaluate("a", "tool.delete_everything").allowed is False


def test_policy_blocks_secrets_glob():
    engine = PolicyEngine.from_yaml(POLICY)
    assert engine.evaluate("a", "tool.read_file", "/home/x/secrets.txt").allowed is False
    assert engine.evaluate("a", "tool.read_file", "/app/.env").allowed is False


def test_policy_requires_approval_tag():
    engine = PolicyEngine.from_yaml(POLICY)
    assert engine.evaluate("a", "tool.write_file", "/prod/db").allowed is False
    assert engine.evaluate("a", "tool.write_file", "/prod/db", {"approved"}).allowed is True


# --- budget ---------------------------------------------------------------

def test_budget_blocks_overrun():
    b = Budget(limit_usd=1.0)
    b.charge(0.9)
    with pytest.raises(BudgetExceeded):
        b.check(next_estimate=0.2)


def test_price_table():
    assert price_for("mock", Usage(1000, 1000)) == 0.0
    assert price_for("claude-sonnet", Usage(1_000_000, 0)) == 3.0


# --- runtime integration --------------------------------------------------

def test_runtime_denies_secret_access_and_records_it(ledger):
    rt = make_runtime(ledger)
    res = rt.run("do work", tools={"read_file": ("/home/user/secrets.txt", lambda: "SECRET")})
    assert res.denied == 1
    assert res.tool_results[0].allowed is False
    assert any(r.decision == "deny" for r in ledger.records())
    ok, _ = ledger.verify()
    assert ok


def test_runtime_allows_sandbox_read(ledger):
    rt = make_runtime(ledger)
    res = rt.run("do work", tools={"read_file": ("/sandbox/notes.txt", lambda: "hello")})
    assert res.denied == 0
    assert res.tool_results[0].output == "hello"


def test_runtime_enforces_budget_mid_run(ledger):
    # A priced model so the run actually consumes budget and trips the cap.
    rt = make_runtime(ledger, budget_usd=0.000001)
    with pytest.raises(BudgetExceeded):
        rt.run("do work", model="claude-sonnet")


def test_runtime_full_run_is_audited(ledger):
    rt = make_runtime(ledger)
    rt.run("summarise the repo", tools={"read_file": ("/sandbox/a.txt", lambda: "x")})
    actions = [r.action for r in ledger.records()]
    assert actions[0] == "run.start" and actions[-1] == "run.end"
    assert "model.usage" in actions
