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
from .identity import IdentityRegistry
from .policy import PolicyEngine
from axon.providers import Completion, default_provider, get_provider


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
        provider: Any | None = None,
        registry: IdentityRegistry | None = None,
        vault: Any | None = None,
    ):
        self.agent_id = agent_id
        self.ledger = ledger
        self.policy = policy
        self.budget = budget
        self.provider = provider or default_provider()
        self.registry = registry
        self.vault = vault
        # Role-derived tags are merged with any explicitly granted ones, so a
        # caller cannot hand an agent authority its role does not carry.
        self.identity = registry.get(agent_id) if registry is not None else None
        self.granted_tags: set[str] = set(self.identity.tags) if self.identity else set()

    @property
    def owner(self) -> str:
        """The human accountable for this agent, if the registry knows one."""
        return self.identity.owner if self.identity else ""

    def grant(self, *tags: str) -> None:
        """Grant extra tags for the lifetime of this runtime.

        Deliberately explicit and narrow: tags are consumed by `requires:`
        clauses, so this is how a human approval workflow unlocks a specific
        action without loosening the policy itself.
        """
        self.granted_tags |= set(tags)

    def revoke(self, *tags: str) -> None:
        self.granted_tags -= set(tags)

    def _tags(self, extra: set[str] | None) -> set[str]:
        return self.granted_tags | (extra or set())

    def _identity_metadata(self, tags: set[str] | None = None) -> dict[str, Any]:
        """Who acted and under what authority — attached to every record.

        An audit trail is only useful if each entry names the accountable
        principal, so this is added uniformly rather than per call site.
        """
        return {
            "role": self.identity.role if self.identity else "unregistered",
            "owner": self.owner,
            "tags": sorted(self._tags(tags)),
        }

    def _authorize(self, action: str, target: str = "", tags: set[str] | None = None) -> None:
        effective = self._tags(tags)
        decision = self.policy.evaluate(self.agent_id, action, target, effective)
        self.ledger.append(
            self.agent_id,
            action,
            target=target,
            decision="allow" if decision.allowed else "deny",
            reason=decision.reason,
            metadata=self._identity_metadata(tags),
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
                **self._identity_metadata(),
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
            metadata={"ok": ok, **self._identity_metadata()},
        )
        return ToolResult(name=name, output=output, allowed=True)

    def read_secret(self, key: str, *, ttl: float | None = None, reusable: bool = False):
        """Request a secret lease through the policy engine.

        The agent never receives the raw value from the environment; it gets
        a lease whose access is authorized, recorded, and revocable.
        """
        if self.vault is None:
            raise PolicyDenied(
                f"{self.agent_id} requested secret '{key}' but no vault is configured"
            )
        return self.vault.issue(
            self.agent_id, key, ttl=ttl, reusable=reusable, authorizer=self._authorize
        )

    def run(self, task: str, *, model: str = "mock", tools: dict[str, tuple[str, Callable[[], str]]] | None = None) -> RunResult:
        """Minimal single-agent loop: plan -> tool(s) -> summarise.

        Deliberately small for the MVP; the orchestrator (multi-agent)
        builds on this same governed primitive.
        """
        import uuid

        run_id = uuid.uuid4().hex[:12]
        self.ledger.append(
            self.agent_id,
            "run.start",
            target=task[:120],
            metadata={"run_id": run_id, **self._identity_metadata()},
        )
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
            metadata={
                "run_id": run_id,
                "cost_usd": round(result.cost_usd, 6),
                "denied": result.denied,
                **self._identity_metadata(),
            },
        )
        return result
