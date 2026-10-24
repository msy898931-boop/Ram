"""Commercial layer tests: Shield packs, Observe analytics, Vault leases."""

import os
import tempfile
import time
from pathlib import Path

import pytest

from axon.core.audit import AuditLedger
from axon.core.budget import Budget
from axon.core.providers import MockProvider
from axon.core.runtime import AgentRuntime, PolicyDenied
from axon.observe import Observer
from axon.shield import (
    BASELINE_PROBES,
    Probe,
    Shield,
    available_packs,
    check_pack,
    load_pack,
    validate_file,
)
from axon.vault import LeaseError, MappingResolver, SecretNotFound, SecretVault

POLICY = os.path.join(os.path.dirname(__file__), "..", "axon", "policies", "default.yaml")


def make_runtime(tmp, policy=None, vault=None, agent="ops-bot", registry=None):
    return AgentRuntime(
        agent_id=agent,
        ledger=AuditLedger(Path(tmp) / "l.jsonl"),
        policy=policy or load_pack("production"),
        budget=Budget(5.0),
        provider=MockProvider(),
        registry=registry,
        vault=vault,
    )


# --- Shield ---------------------------------------------------------------

def test_packs_are_discoverable():
    assert set(available_packs()) >= {"development", "production", "regulated"}


def test_every_pack_refuses_the_baseline_invariants():
    """The product promise: secrets and destructive tools are refused by all packs."""
    for name in available_packs():
        report = Shield(load_pack(name)).check(BASELINE_PROBES)
        assert report.ok, f"{name}: {[f.describe() for f in report.failures]}"


def test_every_pack_passes_its_own_declared_expectations():
    for name in available_packs():
        report = check_pack(name)
        assert report.ok, f"{name}: {[f.describe() for f in report.failures]}"


def test_check_reports_failures_when_a_policy_is_wrong():
    """A policy that allows secrets but claims otherwise must fail the check.

    This is the point of Shield: the checker must be able to say "no", or it
    is decoration. An allow-everything engine is the clearest counterexample.
    """
    from axon.core.policy import PolicyEngine

    weak = Shield(PolicyEngine.permissive())
    report = weak.check([Probe("tool.read_file", "/x/secrets.txt", must_allow=False)])
    assert not report.ok
    assert "FAIL" in report.failures[0].describe()


def test_unknown_pack_raises_with_guidance():
    with pytest.raises(FileNotFoundError) as exc:
        load_pack("nope")
    assert "available" in str(exc.value)


def test_default_policy_file_passes_baseline():
    assert validate_file(POLICY).ok


def test_explain_names_the_deciding_rule():
    result = Shield.from_pack("production").explain("a", "tool.read_file", "/x/secrets.txt")
    assert result["allowed"] is False and result["reason"]


def test_pack_report_serialises():
    data = check_pack("production").as_dict()
    assert data["ok"] is True and data["failed"] == 0 and data["findings"]


# --- Observe --------------------------------------------------------------

def test_cost_report_groups_by_agent_and_model():
    with tempfile.TemporaryDirectory() as tmp:
        rt = make_runtime(tmp, policy=load_pack("development"))
        rt.run("task one", model="claude-sonnet")
        report = Observer(rt.ledger).cost_report()
        assert report.total_calls == 2  # plan + summary
        assert report.total_usd > 0
        assert report.by_model[0].key == "claude-sonnet"
        assert report.by_agent[0].key == "ops-bot"


def test_risk_report_counts_denials_by_actor_and_action():
    with tempfile.TemporaryDirectory() as tmp:
        rt = make_runtime(tmp)
        with pytest.raises(PolicyDenied):
            rt.call_tool("read_file", "/x/secrets.txt", lambda: "x")
        risk = Observer(rt.ledger).risk_report()
        assert risk.total == 1
        assert risk.by_actor == {"ops-bot": 1}
        assert risk.by_action == {"tool.read_file": 1}


def test_integrity_report_detects_unsigned_and_signed_state():
    with tempfile.TemporaryDirectory() as tmp:
        rt = make_runtime(tmp, policy=load_pack("development"))
        rt.run("x")
        report = Observer(rt.ledger).integrity_report()
        assert report.ok and report.records > 0
        assert report.signed == 0 and not report.fully_signed


def test_runs_group_records_by_run_id():
    with tempfile.TemporaryDirectory() as tmp:
        rt = make_runtime(tmp, policy=load_pack("development"))
        rt.run("first")
        rt.run("second")
        runs = Observer(rt.ledger).runs()
        assert len(runs) == 2
        assert all(r["records"] > 0 for r in runs)


def test_summary_is_json_serialisable():
    import json
    with tempfile.TemporaryDirectory() as tmp:
        rt = make_runtime(tmp, policy=load_pack("development"))
        rt.run("x")
        json.dumps(Observer(rt.ledger).summary())


# --- Vault ----------------------------------------------------------------

def make_vault(tmp, values=None):
    ledger = AuditLedger(Path(tmp) / "v.jsonl")
    vault = SecretVault(
        resolver=MappingResolver(values or {"sandbox/api-key": "sk-live-abc123"}),
        ledger=ledger,
        default_ttl=30,
    )
    return vault, ledger


def test_lease_reveals_once_then_refuses_reuse():
    with tempfile.TemporaryDirectory() as tmp:
        vault, _ = make_vault(tmp)
        lease = vault.issue("a", "sandbox/api-key")
        assert lease.reveal() == "sk-live-abc123"
        with pytest.raises(LeaseError):
            lease.reveal()


def test_reusable_lease_can_be_revealed_twice():
    with tempfile.TemporaryDirectory() as tmp:
        vault, _ = make_vault(tmp)
        lease = vault.issue("a", "sandbox/api-key", reusable=True)
        assert lease.reveal() == lease.reveal() == "sk-live-abc123"


def test_expired_lease_refuses_reveal():
    with tempfile.TemporaryDirectory() as tmp:
        vault, _ = make_vault(tmp)
        lease = vault.issue("a", "sandbox/api-key", ttl=0.01)
        time.sleep(0.05)
        with pytest.raises(LeaseError):
            lease.reveal()


def test_non_positive_ttl_is_rejected():
    with tempfile.TemporaryDirectory() as tmp:
        vault, _ = make_vault(tmp)
        with pytest.raises(LeaseError):
            vault.issue("a", "sandbox/api-key", ttl=0)


def test_missing_secret_raises():
    with tempfile.TemporaryDirectory() as tmp:
        vault, _ = make_vault(tmp)
        with pytest.raises(SecretNotFound):
            vault.issue("a", "does/not/exist")


def test_vault_never_writes_the_secret_value_to_the_ledger():
    """The core security claim: the ledger records access, not material."""
    with tempfile.TemporaryDirectory() as tmp:
        vault, ledger = make_vault(tmp)
        vault.issue("a", "sandbox/api-key")
        assert "sk-live-abc123" not in ledger.path.read_text()


def test_redact_scrubs_known_values():
    with tempfile.TemporaryDirectory() as tmp:
        vault, _ = make_vault(tmp)
        vault.issue("a", "sandbox/api-key")
        assert vault.redact("leaked sk-live-abc123 here") == "leaked [REDACTED] here"


def test_revoke_clears_material_and_audits():
    with tempfile.TemporaryDirectory() as tmp:
        vault, ledger = make_vault(tmp)
        lease = vault.issue("a", "sandbox/api-key")
        assert vault.revoke(lease.lease_id, agent="admin") is True
        with pytest.raises(LeaseError):
            lease.reveal()
        assert any(r.action == "vault.revoke" for r in ledger.records())


def test_runtime_read_secret_is_policy_gated():
    with tempfile.TemporaryDirectory() as tmp:
        ledger = AuditLedger(Path(tmp) / "l.jsonl")
        vault = SecretVault(
            resolver=MappingResolver({"sandbox/ok": "v", "prod/no": "v"}),
            ledger=ledger,
        )
        rt = AgentRuntime(
            agent_id="ops-bot", ledger=ledger, policy=load_pack("production"),
            budget=Budget(5.0), provider=MockProvider(), vault=vault,
        )
        assert rt.read_secret("sandbox/ok").reveal() == "v"
        with pytest.raises(PolicyDenied):
            rt.read_secret("prod/no")


def test_runtime_without_vault_refuses_secret_requests():
    with tempfile.TemporaryDirectory() as tmp:
        rt = make_runtime(tmp)
        with pytest.raises(PolicyDenied):
            rt.read_secret("sandbox/api-key")
