"""Orchestrator tests — delegation must not become an escape hatch.

Each test here corresponds to one way a multi-agent system could leak
authority: spawning without permission, resetting the budget by existing,
recursing without bound, or spawning a principal nobody vouched for.
"""

import os
import tempfile
from pathlib import Path

import pytest

from axon.core.audit import AuditLedger
from axon.core.budget import Budget
from axon.core.identity import Identity, IdentityRegistry
from axon.core.orchestrator import Delegation, OrchestrationResult, Orchestrator
from axon.core.policy import PolicyEngine
from axon.core.providers import MockProvider
from axon.core.runtime import AgentRuntime

POLICY = os.path.join(os.path.dirname(__file__), "..", "axon", "policies", "default.yaml")


def make_registry():
    reg = IdentityRegistry(roles={"operator": {"approved"}, "agent": set()})
    for name, role in [
        ("ops-bot", "operator"), ("worker-1", "agent"),
        ("worker-2", "agent"), ("worker-3", "agent"),
    ]:
        reg.register(Identity(name=name, role=role, owner="sre@example.com"))
    return reg


def make_root(tmp, registry=None, budget=5.0, policy=None, agent="ops-bot"):
    return AgentRuntime(
        agent_id=agent,
        ledger=AuditLedger(Path(tmp) / "l.jsonl"),
        policy=policy or PolicyEngine.from_yaml(POLICY),
        budget=Budget(budget),
        provider=MockProvider(),
        registry=registry if registry is not None else make_registry(),
    )


def test_authorized_parent_can_delegate():
    with tempfile.TemporaryDirectory() as tmp:
        orch = Orchestrator(root=make_root(tmp))
        res = orch.sequential([Delegation("worker-1", "do A")])
        assert res.succeeded == 1 and res.denied == 0


def test_parent_without_delegate_rule_is_refused():
    with tempfile.TemporaryDirectory() as tmp:
        root = make_root(tmp, agent="worker-1")
        res = Orchestrator(root=root).sequential([Delegation("worker-2", "help")])
        assert res.denied == 1
        assert "agent.delegate" in res.delegations[0].error


def test_unknown_child_is_refused():
    with tempfile.TemporaryDirectory() as tmp:
        res = Orchestrator(root=make_root(tmp)).sequential([Delegation("ghost", "hi")])
        assert res.denied == 1
        assert "unknown identity" in res.delegations[0].error


def test_child_shares_parent_budget_instead_of_resetting_it():
    """The decisive property: a child cannot escape the cost cap."""
    with tempfile.TemporaryDirectory() as tmp:
        root = make_root(tmp, budget=0.000001)
        res = Orchestrator(root=root).sequential(
            [Delegation("worker-1", "expensive", model="claude-sonnet")]
        )
        assert res.denied == 1
        assert "budget cap" in res.delegations[0].error


def test_child_spend_counts_against_the_shared_cap():
    with tempfile.TemporaryDirectory() as tmp:
        root = make_root(tmp, budget=10.0)
        orch = Orchestrator(root=root)
        orch.sequential([Delegation("worker-1", "a", model="claude-sonnet")])
        assert root.budget.spent_usd > 0


def test_depth_limit_refuses_rather_than_raising():
    with tempfile.TemporaryDirectory() as tmp:
        orch = Orchestrator(root=make_root(tmp), max_depth=1)
        result = orch.delegate(orch.root, Delegation("worker-1", "deep"), depth=5)
        assert result.denied and "max delegation depth" in result.error


def test_max_children_is_enforced():
    with tempfile.TemporaryDirectory() as tmp:
        orch = Orchestrator(root=make_root(tmp), max_children=2)
        res = orch.sequential([
            Delegation("worker-1", "a"),
            Delegation("worker-2", "b"),
            Delegation("worker-3", "c"),
        ])
        assert res.succeeded == 2 and res.denied == 1
        assert "max children" in res.delegations[-1].error


def test_negative_depth_is_a_programmer_error():
    with tempfile.TemporaryDirectory() as tmp:
        with pytest.raises(ValueError):
            Orchestrator(root=make_root(tmp), max_depth=-1)


def test_all_delegations_land_in_one_verifiable_ledger():
    with tempfile.TemporaryDirectory() as tmp:
        root = make_root(tmp)
        Orchestrator(root=root).sequential([
            Delegation("worker-1", "a"), Delegation("worker-2", "b")
        ])
        ok, msg = root.ledger.verify()
        assert ok, msg
        actors = {r.actor for r in root.ledger.records()}
        assert {"ops-bot", "worker-1", "worker-2"} <= actors


def test_nested_tree_walks_two_levels():
    with tempfile.TemporaryDirectory() as tmp:
        root = make_root(tmp)
        orch = Orchestrator(root=root, max_depth=2, max_children=8)
        tree = {
            "ops-bot": [Delegation("worker-1", "A"), Delegation("worker-2", "B")],
            "worker-1": [Delegation("worker-3", "A.1")],
        }
        out = orch.nested(tree, root_task="orchestrate")
        assert [(d.agent_id, d.depth) for d in out.delegations] == [
            ("worker-1", 1), ("worker-2", 1), ("worker-3", 2)
        ]


def test_child_cannot_delegate_further_without_permission():
    """A child inherits the parent's policy; it does not inherit permission
    to delegate, which stays an explicit per-actor rule."""
    with tempfile.TemporaryDirectory() as tmp:
        root = make_root(tmp)
        orch = Orchestrator(root=root, max_depth=3, max_children=8)
        tree = {"ops-bot": [Delegation("worker-1", "A")], "worker-1": [Delegation("worker-2", "B")]}
        out = orch.nested(tree, root_task="x")
        deep = [d for d in out.delegations if d.agent_id == "worker-2"]
        assert deep and deep[0].denied


def test_delegation_refusals_are_recorded_in_the_ledger():
    with tempfile.TemporaryDirectory() as tmp:
        root = make_root(tmp, agent="worker-1")
        Orchestrator(root=root).sequential([Delegation("worker-2", "x")])
        denials = [r for r in root.ledger.records() if r.action == "agent.delegate"]
        assert denials and denials[0].decision == "deny"


def test_fan_out_matches_sequential():
    with tempfile.TemporaryDirectory() as tmp:
        root = make_root(tmp)
        orch = Orchestrator(root=root)
        res = orch.fan_out([Delegation("worker-1", "a"), Delegation("worker-2", "b")])
        assert isinstance(res, OrchestrationResult)
        assert res.succeeded == 2
