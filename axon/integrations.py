# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 msy898931-boop
# AXON commercial module. See LICENSE-COMMERCIAL. Converts to
# Apache-2.0 four years after publication.
"""Framework integrations — put AXON underneath an agent you already have.

The pitch is only credible if adopting AXON does not mean rewriting an
agent. These adapters wrap a tool function so that calling it routes through
the governed runtime first: policy decides, budget is charged, and the
ledger records it. Nothing else about the framework changes.

Two layers, on purpose:

  `guard_tool`   a plain decorator with no framework dependency. Works with
                 any Python callable, including LangChain's `@tool`, CrewAI
                 tools, the OpenAI Agents SDK, or hand-rolled functions.

  adapters       thin, explicit shims (`LangChainAdapter`, `CrewAIAdapter`,
                 `OpenHandsAdapter`) that exist mainly to document the
                 integration point and to normalise each framework's tool
                 naming. They import nothing from those frameworks, so AXON
                 keeps its zero-dependency guarantee and a user does not
                 have to install a framework they do not use.

A blocked call raises `PolicyDenied` rather than returning a sentinel, so a
framework cannot mistake a refusal for a successful empty result. Every
adapter propagates that same exception type, so one `except` clause covers a
refusal no matter which framework produced the call.
"""

from __future__ import annotations

import functools
from collections.abc import Callable
from typing import Any

from .core.runtime import AgentRuntime, PolicyDenied

__all__ = [
    "CrewAIAdapter",
    "LangChainAdapter",
    "OpenHandsAdapter",
    "PolicyDenied",
    "guard_tool",
]


def guard_tool(
    runtime: AgentRuntime,
    *,
    name: str | None = None,
    target: str | Callable[..., str] | None = None,
    tags: set[str] | None = None,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Wrap a tool so every call is policy-checked, budgeted, and audited.

    `target` may be a literal path or a callable that derives the target from
    the call arguments — the latter is what lets a single file-reading tool
    be governed per path instead of as one opaque capability.
    """

    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        tool_name = name or getattr(fn, "__name__", "tool")
        # `call_tool` prefixes "tool." itself, so strip any prefix here to
        # avoid producing "tool.tool.read_file".
        bare = tool_name.split(".")[-1]

        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            resolved = target(*args, **kwargs) if callable(target) else (target or "")
            result = runtime.call_tool(bare, str(resolved), lambda: fn(*args, **kwargs), tags)
            return result.output

        wrapper.__axon_tool__ = bare  # type: ignore[attr-defined]
        return wrapper

    return decorator


class _AdapterBase:
    """Shared behaviour: one runtime, one default target strategy."""

    framework = "generic"

    def __init__(self, runtime: AgentRuntime, *, target_attr: str | None = None):
        self.runtime = runtime
        self.target_attr = target_attr

    def _resolve_target(self, args: tuple, kwargs: dict) -> str:
        """Derive the policy target for a call.

        An explicit `target_attr` names the argument that carries the path.
        Without one, fall back to the first positional argument, which is the
        conventional place for a tool's subject; if the call has neither, the
        framework name is used so the action is still governed (and, under a
        deny-by-default policy, refused rather than silently allowed).
        """
        if self.target_attr:
            if self.target_attr in kwargs:
                return str(kwargs[self.target_attr])
            if args:
                return str(args[0])
        if args:
            return str(args[0])
        if kwargs:
            return str(next(iter(kwargs.values())))
        return self.framework

    def wrap(self, fn: Callable[..., Any], name: str | None = None) -> Callable[..., Any]:
        tool_name = name or getattr(fn, "__name__", "tool")
        bare = tool_name.split(".")[-1]

        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            resolved = self._resolve_target(args, kwargs)
            result = self.runtime.call_tool(bare, resolved, lambda: fn(*args, **kwargs))
            return result.output

        return wrapper

    def wrap_all(self, tools: dict[str, Callable[..., Any]]) -> dict[str, Callable[..., Any]]:
        return {name: self.wrap(fn, name) for name, fn in tools.items()}


class LangChainAdapter(_AdapterBase):
    """Wrap LangChain tools.

    LangChain tools expose `.name` and `.func`; `wrap` accepts either a
    `StructuredTool`-like object or a plain callable. Kept dependency-free so
    AXON does not pin a LangChain version.
    """

    framework = "langchain"

    def wrap(self, tool: Any, name: str | None = None) -> Callable[..., Any]:
        fn = getattr(tool, "func", tool)
        tool_name = name or getattr(tool, "name", None) or getattr(fn, "__name__", "tool")
        return super().wrap(fn, tool_name)


class CrewAIAdapter(_AdapterBase):
    """Wrap CrewAI tools, which call `run` on a `BaseTool` subclass."""

    framework = "crewai"

    def wrap(self, tool: Any, name: str | None = None) -> Callable[..., Any]:
        fn = getattr(tool, "_run", None) or getattr(tool, "run", tool)
        tool_name = name or getattr(tool, "name", None) or getattr(fn, "__name__", "tool")
        return super().wrap(fn, tool_name)


class OpenHandsAdapter(_AdapterBase):
    """Wrap OpenHands-style actions, which are named verbs with arguments."""

    framework = "openhands"

    def action(self, verb: str, target: str, fn: Callable[[], Any]) -> Any:
        result = self.runtime.call_tool(verb.split(".")[-1], target, fn)
        return result.output
