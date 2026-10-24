"""CLI-level tests.

The `run` command builds a stub tool closure per `--tool` flag. A closure
that captures the loop variable by reference makes every stub report the
last tool's name, so these tests exercise several tools at once.
"""

import json

import pytest

from axon.cli import main


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    return tmp_path


def _run(argv, capsys):
    code = main(argv)
    return code, capsys.readouterr().out


def test_each_tool_stub_reports_its_own_name(workspace, capsys):
    """Regression: the stub lambda must bind the tool name per iteration."""
    code, out = _run(
        [
            "run", "multi tool task",
            "--tool", "read_file=/sandbox/a",
            "--tool", "list_dir=/sandbox/b",
            "--ledger", "./audit.jsonl",
        ],
        capsys,
    )
    assert code == 0
    payload = json.loads(out[out.index("{"):out.rindex("}") + 1])
    outputs = [t["output"] for t in payload["tools"]]
    assert any("read_file" in o for o in outputs)
    assert any("list_dir" in o for o in outputs)


def test_unknown_tool_is_denied_by_default(workspace, capsys):
    code, out = _run(
        ["run", "task", "--tool", "write_file=/sandbox/x", "--ledger", "./audit.jsonl"],
        capsys,
    )
    assert code == 0
    payload = json.loads(out[out.index("{"):out.rindex("}") + 1])
    assert payload["denied"] >= 1
    assert any("deny by default" in t["output"] for t in payload["tools"])


def test_run_writes_a_verifiable_ledger(workspace, capsys):
    _run(["run", "task", "--ledger", "./audit.jsonl"], capsys)
    code, out = _run(["audit", "--ledger", "./audit.jsonl"], capsys)
    assert code == 0
    assert "verify: OK" in out


def test_policy_check_reports_a_denial(workspace, capsys):
    """A denial exits non-zero so the command can gate a CI step."""
    code, out = _run(
        ["policy-check", "tool.read_file", "--target", "/home/deploy/secrets/db.txt"],
        capsys,
    )
    assert code == 3
    assert "DENY" in out


def test_policy_check_allows_a_sandbox_path(workspace, capsys):
    code, out = _run(
        ["policy-check", "tool.read_file", "--target", "/sandbox/notes.txt"], capsys
    )
    assert code == 0
    assert "ALLOW" in out


def test_keygen_then_strict_verification_passes(workspace, capsys):
    code, out = _run(["keygen", "--key", "./sign.key"], capsys)
    assert code == 0
    assert (workspace / "sign.key.pub").exists()

    _run(["run", "task", "--ledger", "./audit.jsonl", "--key", "./sign.key"], capsys)
    code, out = _run(
        ["audit", "--ledger", "./audit.jsonl", "--pubkey", "./sign.key.pub"], capsys
    )
    assert code == 0
    assert "verify: OK" in out
    assert "signed and verified" in out


def test_shield_command_passes_every_pack(workspace, capsys):
    code, out = _run(["shield"], capsys)
    assert code == 0
    assert "development" in out and "production" in out and "regulated" in out


def test_compliance_command_maps_every_control(workspace, capsys):
    code, out = _run(["compliance"], capsys)
    assert code == 0
    assert "11/11 controls" in out
