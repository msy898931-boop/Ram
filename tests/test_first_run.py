# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 msy898931-boop
# Part of the AXON open core. See NOTICE for the license map.
"""The documented first-run experience must actually work.

Every command in the README quickstart is what a visitor runs in their first
minute, and it is also what a founder runs on a sales call. If one of them
breaks, the failure is invisible to the test suite and fatal to the funnel —
nobody files an issue, they just leave.

These tests run the real CLI as a subprocess, the way a user would, rather
than importing the functions. A command that works when called as a function
but fails as an installed entry point is exactly the bug this catches.
"""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent


def run(*args, cwd=ROOT):
    return subprocess.run(
        [sys.executable, "-m", "axon.cli", *args],
        capture_output=True,
        text=True,
        cwd=cwd,
    )


def test_version_answers():
    r = run("--version")
    assert r.returncode == 0, r.stderr
    assert "0." in r.stdout


def test_governed_run_is_denied_by_default(tmp_path):
    """The headline behaviour: an agent does nothing until it is allowed."""
    ledger = tmp_path / "audit.jsonl"
    r = run(
        "run",
        "read the changelog",
        "--tool",
        f"read_file={ROOT / 'CHANGELOG.md'}",
        "--ledger",
        str(ledger),
    )
    assert r.returncode == 0, r.stderr
    payload = json.loads(r.stdout)
    assert payload["denied"] == 1
    assert "deny by default" in payload["tools"][0]["output"]
    assert ledger.exists(), "the run must leave an audit trail behind"


def test_audit_verifies_a_fresh_ledger(tmp_path):
    ledger = tmp_path / "audit.jsonl"
    run("run", "do a thing", "--ledger", str(ledger))
    r = run("audit", "--ledger", str(ledger))
    assert r.returncode == 0, r.stderr
    assert "verify: OK" in r.stdout


def test_keygen_then_strict_verification(tmp_path):
    """The command the README gives for an auditor. If this breaks, the
    central security claim is unreachable by the documented path."""
    ledger = tmp_path / "audit.jsonl"
    key = tmp_path / "sign.key"
    run("run", "sign a thing", "--ledger", str(ledger), "--key", str(key))
    assert key.exists()
    assert pathlib.Path(str(key) + ".pub").exists(), (
        "`run --key` creates the private key, so it must write the public half "
        "too -- otherwise the documented `audit --pubkey <key>.pub` crashes"
    )

    r = run("audit", "--ledger", str(ledger), "--pubkey", str(key) + ".pub")
    assert r.returncode == 0, r.stderr
    assert "verify: OK" in r.stdout


def test_unsigned_ledger_reports_a_clear_error_not_a_traceback(tmp_path):
    """Following the docs out of order must not look like a crash."""
    r = run(
        "audit",
        "--ledger",
        str(tmp_path / "missing.jsonl"),
        "--pubkey",
        str(tmp_path / "nope.pub"),
    )
    assert r.returncode == 4
    assert "public key not found" in r.stderr
    assert "Traceback" not in r.stderr


def test_posture_reports_honestly():
    """posture exits 1 when a layer is off, by design: it is a CI gate.
    What matters is that it never claims a layer is on when it is not."""
    r = run("posture")
    assert r.returncode in (0, 1), r.stderr
    assert "/9 layers enforcing" in r.stdout


def test_shield_proves_the_packs_refuse_what_they_claim():
    r = run("shield")
    assert r.returncode == 0, r.stderr
    assert "PASS" in r.stdout


def test_compliance_controls_all_map_to_code():
    r = run("compliance")
    assert r.returncode == 0, r.stderr
    assert "20/20 controls map to present code and tests" in r.stdout


@pytest.mark.parametrize("argv", [["models"], ["identities"]])
def test_listing_commands_do_not_crash(argv):
    r = run(*argv)
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip()


def test_the_demo_and_the_proof_script_run_end_to_end():
    """The two things a founder runs on a sales call. They must not raise."""
    for script in ("examples/demo.py", "examples/signed_ledger_proof.py"):
        r = subprocess.run(
            [sys.executable, script], capture_output=True, text=True, cwd=ROOT
        )
        assert r.returncode == 0, f"{script} failed:\n{r.stderr}"
        assert r.stdout.strip(), f"{script} produced no output"
