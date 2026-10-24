# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 msy898931-boop
# Part of the AXON open core. See NOTICE for the license map.
"""Integration tests — adopting AXON must not require rewriting an agent.

The adapters are exercised with stand-in objects that mimic each
framework's tool shape, so the tests run without those frameworks installed.
The behaviour under test is the wrapping itself, not the framework.
"""

import tempfile
from pathlib import Path

import pytest

from axon.core.audit import AuditLedger
from axon.core.budget import Budget
from axon.core.providers import MockProvider
from axon.core.runtime import AgentRuntime, PolicyDenied
from axon.integrations import CrewAIAdapter, LangChainAdapter, OpenHandsAdapter, guard_tool
from axon.shield import load_pack


@pytest.fixture
def runtime():
    with tempfile.TemporaryDirectory() as tmp:
        yield AgentRuntime(
            agent_id="agent-1",
            ledger=AuditLedger(Path(tmp) / "l.jsonl"),
            policy=load_pack("production"),
            budget=Budget(5.0),
            provider=MockProvider(),
        )


def test_guard_tool_allows_a_permitted_path(runtime):
    @guard_tool(runtime, name="read_file", target=lambda path: path)
    def read_file(path):
        return f"contents:{path}"

    assert read_file("/sandbox/a.txt") == "contents:/sandbox/a.txt"


def test_guard_tool_denies_a_secret_path(runtime):
    @guard_tool(runtime, name="read_file", target=lambda path: path)
    def read_file(path):
        return f"contents:{path}"

    with pytest.raises(PolicyDenied):
        read_file("/home/user/secrets.txt")


def test_guard_tool_does_not_double_prefix_the_action(runtime):
    @guard_tool(runtime, name="tool.read_file", target=lambda path: path)
    def read_file(path):
        return "ok"

    read_file("/sandbox/a.txt")
    actions = {r.action for r in runtime.ledger.records()}
    assert "tool.read_file" in actions
    assert "tool.tool.read_file" not in actions


def test_guard_tool_honours_required_tags(runtime):
    @guard_tool(runtime, name="write_file", target=lambda path: path, tags={"approved"})
    def write_file(path):
        return f"wrote:{path}"

    assert write_file("/prod/db") == "wrote:/prod/db"


def test_blocked_call_raises_rather_than_returning_a_sentinel(runtime):
    """A refusal must be unmistakable; a silent empty result would let a
    framework treat a denial as success."""
    @guard_tool(runtime, name="read_file", target=lambda path: path)
    def read_file(path):
        return "ok"

    with pytest.raises(PolicyDenied):
        read_file("/app/.env")


def test_langchain_shaped_tool_is_wrapped(runtime):
    class FakeTool:
        name = "read_file"
        def func(self, path):
            return f"read:{path}"

    wrapped = LangChainAdapter(runtime, target_attr="path").wrap(FakeTool())
    assert wrapped(path="/sandbox/x") == "read:/sandbox/x"
    with pytest.raises(PolicyDenied):
        wrapped(path="/x/.env")


def test_crewai_shaped_tool_is_wrapped(runtime):
    class FakeTool:
        name = "read_file"
        def _run(self, path):
            return f"read:{path}"

    wrapped = CrewAIAdapter(runtime, target_attr="path").wrap(FakeTool())
    assert wrapped(path="/sandbox/x") == "read:/sandbox/x"


def test_openhands_shaped_action_is_governed(runtime):
    adapter = OpenHandsAdapter(runtime)
    assert adapter.action("read_file", "/sandbox/y", lambda: "y") == "y"
    with pytest.raises(PolicyDenied):
        adapter.action("read_file", "/etc/passwd", lambda: "no")


def test_adapter_uses_first_argument_as_target_by_default(runtime):
    adapter = CrewAIAdapter(runtime)
    assert adapter.wrap(lambda path: f"r:{path}", "read_file")("/sandbox/z") == "r:/sandbox/z"


def test_wrap_all_covers_every_tool(runtime):
    adapter = CrewAIAdapter(runtime)
    tools = {"read_file": lambda path="": f"r:{path}"}
    wrapped = adapter.wrap_all(tools)
    assert set(wrapped) == set(tools)


def test_every_guarded_call_lands_in_one_verifiable_ledger(runtime):
    @guard_tool(runtime, name="read_file", target=lambda path: path)
    def read_file(path):
        return "ok"

    read_file("/sandbox/a.txt")
    with pytest.raises(PolicyDenied):
        read_file("/x/secrets.txt")

    ok, message = runtime.ledger.verify()
    assert ok, message
    decisions = [r.decision for r in runtime.ledger.records() if r.action == "tool.read_file"]
    assert "allow" in decisions and "deny" in decisions
