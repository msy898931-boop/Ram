# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 msy898931-boop
# Part of the AXON open core. See NOTICE for the license map.
"""Compliance mapping tests — the matrix must not rot.

Each control claims specific files implement it and specific tests prove it.
These tests assert those claims still hold, so deleting or renaming an
implementation file turns into a failing test rather than a stale document.
"""

from axon.compliance import CONTROLS, evaluate, report


def test_controls_are_unique_and_identified():
    ids = [c.id for c in CONTROLS]
    assert len(ids) == len(set(ids))
    assert all(c.id and c.framework and c.title for c in CONTROLS)


def test_every_control_cites_implementation_and_tests():
    for control in CONTROLS:
        assert control.implementation, f"{control.id} cites no implementation"
        assert control.tests, f"{control.id} cites no tests"
        assert control.evidence, f"{control.id} states no evidence"


def test_every_cited_file_exists():
    """A control pointing at a file that is gone is a broken control."""
    results = evaluate()
    missing = [r.control.id for r in results if not r.code_ok]
    assert not missing, f"controls citing missing code: {missing}"


def test_every_cited_test_file_exists():
    results = evaluate()
    missing = [r.control.id for r in results if not r.tests_ok]
    assert not missing, f"controls citing missing tests: {missing}"


def test_report_summarises_cleanly():
    data = report()
    assert data["controls"] == len(CONTROLS)
    assert data["passing"] == len(CONTROLS)
    assert data["failing"] == []


def test_multi_agent_and_ai_controls_are_covered():
    frameworks = {c.framework for c in CONTROLS}
    assert any("42001" in f for f in frameworks), "AI-specific controls should be mapped"
    assert any("SOC 2" in f for f in frameworks)
    assert any("27001" in f for f in frameworks)
