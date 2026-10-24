"""RBAC tests — roles must gate actions without ever widening policy denials.

The key property under test: a role confers *tags*, and tags only satisfy
`requires:` clauses. A role can therefore unlock an action a policy already
allows conditionally, but it can never override a policy `deny`.
"""

import os
import tempfile
from pathlib import Path

import pytest

from axon.core.audit import AuditLedger
from axon.core.budget import Budget
from axon.core.identity import Identity, IdentityError, IdentityRegistry
from axon.core.policy import PolicyEngine
from axon.core.providers import MockProvider
from axon.core.runtime import AgentRuntime, PolicyDenied

POLICY = os.path.join(os.path.dirname(__file__), "..", "axon", "policies", "default.yaml")
IDENTITIES = os.path.join(os.path.dirname(__file__), "..", "axon", "policies", "identities.yaml")


@pytest.fixture
def registry():
    return IdentityRegistry.from_yaml(IDENTITIES)


@pytest.fixture
def policy():
    return PolicyEngine.from_yaml(POLICY)


def runtime(registry, policy, agent, tmp):
    return AgentRuntime(
        agent_id=agent,
        ledger=AuditLedger(Path(tmp) / "l.jsonl"),
        policy=policy,
        budget=Budget(10.0),
        provider=MockProvider(),
        registry=registry,
    )


def attempt(registry, policy, agent, tmp, tool, target):
    rt = runtime(registry, policy, agent, tmp)
    try:
        rt.call_tool(tool, target, lambda: "done")
        return True
    except PolicyDenied:
        return False


# --- registry -------------------------------------------------------------

def test_registry_loads_roles_and_identities(registry):
    assert registry.get("agent-1").role == "agent"
    assert registry.get("ops-bot").has("approved")
    assert registry.get("ops-bot").owner == "sre@example.com"
    assert set(registry.roles()) >= {"admin", "operator", "agent", "readonly"}


def test_unknown_identity_raises(registry):
    with pytest.raises(IdentityError):
        registry.get("ghost")


def test_disabled_identity_raises(registry):
    with pytest.raises(IdentityError):
        registry.get("break-glass")


def test_register_confers_role_tags():
    reg = IdentityRegistry(roles={"operator": {"approved", "deploy"}})
    ident = reg.register(Identity(name="new-bot", role="operator"))
    assert ident.has("approved", "deploy")


def test_from_oidc_claims_maps_subject_role_and_groups():
    ident = Identity.from_oidc_claims(
        {"sub": "svc-7", "roles": ["operator"], "groups": ["sre"], "email": "s@example.com"}
    )
    assert ident.name == "svc-7" and ident.role == "operator"
    assert ident.has("operator", "sre")


def test_from_oidc_claims_requires_subject():
    with pytest.raises(IdentityError):
        Identity.from_oidc_claims({"groups": ["x"]})


def test_resolve_prefers_declared_identity_over_claims(registry):
    """A deployment can pin a role regardless of what a token claims."""
    ident = registry.resolve("agent-1", oidc_claims={"sub": "agent-1", "role": "admin"})
    assert ident.role == "agent"


# --- enforcement ----------------------------------------------------------

def test_role_without_tag_is_denied(registry, policy):
    with tempfile.TemporaryDirectory() as tmp:
        assert attempt(registry, policy, "agent-1", tmp, "write_file", "/prod/db") is False


def test_role_with_tag_is_allowed(registry, policy):
    with tempfile.TemporaryDirectory() as tmp:
        assert attempt(registry, policy, "ops-bot", tmp, "write_file", "/prod/db") is True


def test_hard_deny_beats_any_role(registry, policy):
    """`approved` unlocks /prod, but nothing unlocks secrets."""
    with tempfile.TemporaryDirectory() as tmp:
        assert attempt(registry, policy, "agent-1", tmp, "read_file", "/x/secrets.txt") is False
        assert attempt(registry, policy, "ops-bot", tmp, "read_file", "/x/secrets.txt") is False


def test_runtime_without_registry_has_no_tags(policy):
    with tempfile.TemporaryDirectory() as tmp:
        rt = AgentRuntime(
            agent_id="agent-1",
            ledger=AuditLedger(Path(tmp) / "l.jsonl"),
            policy=policy,
            budget=Budget(10.0),
            provider=MockProvider(),
        )
        assert rt.granted_tags == set()
        with pytest.raises(PolicyDenied):
            rt.call_tool("write_file", "/prod/db", lambda: "x")


def test_grant_and_revoke_are_explicit_and_narrow(registry, policy):
    with tempfile.TemporaryDirectory() as tmp:
        rt = runtime(registry, policy, "agent-1", tmp)
        with pytest.raises(PolicyDenied):
            rt.call_tool("write_file", "/prod/db", lambda: "x")
        rt.grant("approved")
        assert rt.call_tool("write_file", "/prod/db", lambda: "x").output == "x"
        rt.revoke("approved")
        with pytest.raises(PolicyDenied):
            rt.call_tool("write_file", "/prod/db2", lambda: "x")


def test_audit_records_role_owner_and_tags(registry, policy):
    with tempfile.TemporaryDirectory() as tmp:
        rt = runtime(registry, policy, "ops-bot", tmp)
        rt.call_tool("write_file", "/prod/db", lambda: "x")
        rec = rt.ledger.records()[-1]
        assert rec.metadata["role"] == "operator"
        assert rec.metadata["owner"] == "sre@example.com"
        assert "approved" in rec.metadata["tags"]


def test_run_start_records_identity(registry, policy):
    with tempfile.TemporaryDirectory() as tmp:
        rt = runtime(registry, policy, "agent-1", tmp)
        rt.run("do the thing")
        start = rt.ledger.records()[0]
        assert start.action == "run.start"
        assert start.metadata["role"] == "agent"
        assert start.metadata["owner"] == "platform-team@example.com"
