"""Agent runtime — the governed execution loop.

Every model call and every tool call passes through:
  1. PolicyEngine  -> allow / deny (fail-closed)
  2. Budget        -> hard cost cap
  3. AuditLedger   -> tamper-evident record

An agent cannot bypass these; the runtime is the only path to a model.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from .audit import AuditLedger
from .budget import Budget, BudgetExceeded
from .policy import PolicyEngine
from .providers import Completion, Provider, default_provider


class PolicyDenied(Exception):
    pass


@dataclass
class ToolResult:
    name: str
    output: str
    allowed: bool


@dataclass
class RunResult:
    run_id: str
    outputs: list[str] = field(default_factory=list)
    tool_results: list[ToolResult] = field(default_factory=list)
    cost_usd: float = 0.0
    denied: int = 0


class AgentRuntime:
    """Executes an agent under policy, budget, and audit control."""

    def __init__(
        self,
        *,
        agent_id: str,
        ledger: AuditLedger,
        policy: PolicyEngine,
        budget: Budget,
        provider: Provider | None = None,
    ):
        self.agent_id = agent_id
        self.ledger = ledger
        self.policy = policy
        self.budget = budget
        self.provider = provider or default_provider()

    def _authorize(self, action: str, target: str = "", tags: set[str] | None = None) -> None:
        decision = self.policy.evaluate(self.agent_id, action, target, tags)
        self.ledger.append(
            self.agent_id,
            action,
            target=target,
            decision="allow" if decision.allowed else "deny",
            reason=decision.reason,
        )
        if not decision.allowed:
            raise PolicyDenied(f"{self.agent_id} denied '{action}' on '{target}': {decision.reason}")

    def think(self, prompt: str, model: str = "mock") -> Completion:
        """One governed model call."""
        self._authorize("model.complete", target=model)
        self.budget.check()
        completion = self.provider.complete(prompt, model)
        self.budget.charge(completion.usage.cost_usd)
        self.ledger.append(
            self.agent_id,
            "model.usage",
            target=model,
            decision="allow",
            reason="tokens charged",
            metadata={
                "input_tokens": completion.usage.input_tokens,
                "output_tokens": completion.usage.output_tokens,
                "cost_usd": round(completion.usage.cost_usd, 6),
            },
        )
        return completion

    def call_tool(
        self, name: str, target: str, fn: Callable[[], str], tags: set[str] | None = None
    ) -> ToolResult:
        """One governed tool call. `fn` runs only if authorized."""
        self._authorize(f"tool.{name}", target=target, tags=tags)
        try:
            output = fn()
            ok = True
        except Exception as exc:  # tool failure is recorded, not swallowed
            output = f"error: {exc}"
            ok = False
        self.ledger.append(
            self.agent_id,
            f"tool.{name}.result",
            target=target,
            decision="allow",
            reason="executed" if ok else "failed",
            metadata={"ok": ok},
        )
        return ToolResult(name=name, output=output, allowed=True)

    def run(self, task: str, *, model: str = "mock", tools: dict[str, tuple[str, Callable[[], str]]] | None = None) -> RunResult:
        """Minimal single-agent loop: plan -> tool(s) -> summarise.

        Deliberately small for the MVP; the orchestrator (multi-agent)
        builds on this same governed primitive.
        """
        import uuid

        run_id = uuid.uuid4().hex[:12]
        self.ledger.append(self.agent_id, "run.start", target=task[:120], metadata={"run_id": run_id})
        result = RunResult(run_id=run_id)

        plan = self.think(f"Plan how to accomplish: {task}", model=model)
        result.outputs.append(plan.text)
        result.cost_usd += plan.usage.cost_usd

        for name, (target, fn) in (tools or {}).items():
            try:
                tr = self.call_tool(name, target, fn)
                result.tool_results.append(tr)
            except PolicyDenied as exc:
                result.denied += 1
                result.tool_results.append(ToolResult(name=name, output=str(exc), allowed=False))

        summary = self.think(f"Summarise progress on: {task}", model=model)
        result.outputs.append(summary.text)
        result.cost_usd += summary.usage.cost_usd

        self.ledger.append(
            self.agent_id,
            "run.end",
            decision="allow",
            metadata={"run_id": run_id, "cost_usd": round(result.cost_usd, 6), "denied": result.denied},
        )
        return result
