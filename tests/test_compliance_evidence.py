"""Tests for the auditor evidence pack.

The pack's value is that it is honest: it evidences technical controls and
states plainly that it is not an audit opinion. These tests assert both
halves, because a pack that quietly omitted its limitations would be worse
than no pack at all — someone would mistake it for a certification.
"""

from __future__ import annotations

import json

from axon.compliance import CONTROLS, evidence_package


def test_pack_covers_every_control():
    package = evidence_package()
    assert len(package["controls"]) == len(CONTROLS)
    assert package["summary"]["controls"] == len(CONTROLS)
    assert package["summary"]["passing"] == len(CONTROLS)


def test_pack_carries_digests_for_every_present_file():
    package = evidence_package()
    for control in package["controls"]:
        assert control["implementing_files"], control["id"]
        for entry in control["implementing_files"]:
            assert entry["present"] is True, entry
            # A digest, not a path: the auditor needs to know *which* revision
            # was examined, and a path alone does not pin that down.
            assert len(entry["sha256"]) == 64
            int(entry["sha256"], 16)


def test_pack_states_its_limitations():
    package = evidence_package()
    assert package["limitations"]
    joined = " ".join(package["limitations"]).lower()
    assert "not a soc 2 report" in joined
    assert "independent third party" in joined
    assert package["scope"] == "AXON technical controls only"


def test_pack_includes_ledger_integrity_when_a_ledger_is_given(tmp_path):
    from axon.core.audit import AuditLedger

    ledger_path = tmp_path / "audit.jsonl"
    ledger = AuditLedger(ledger_path)
    ledger.append(actor="agent-1", action="run.start", target="t", decision="allow")

    package = evidence_package(ledger_path)
    assert package["audit_ledger"]["records"] == 1
    assert package["audit_ledger"]["chain_ok"] is True


def test_pack_omits_ledger_when_none_is_given(tmp_path):
    package = evidence_package(tmp_path / "does-not-exist.jsonl")
    assert "audit_ledger" not in package


def test_pack_is_json_serialisable():
    """It is written to disk, so it must round-trip through JSON."""
    package = evidence_package()
    assert json.loads(json.dumps(package))["summary"]["controls"] == len(CONTROLS)


def test_new_security_controls_are_in_the_matrix():
    ids = {c.id for c in CONTROLS}
    assert "A.8.24" in ids  # transport encryption
    assert "CC6.5" in ids   # deprovisioning through the IdP
