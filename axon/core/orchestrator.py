"""Multi-agent orchestration with governance preserved across delegation.

The hard part of multi-agent systems is not spawning sub-agents, it is
keeping the guarantees intact once you do. A child agent must not be a way
to escape the parent's policy, budget, or audit trail. This module enforces
four invariants:

1. Delegation is itself a policy decision. `agent.delegate` must be allowed
   for the parent, targeting the child's name. A parent with no `delegate`
   rule cannot spawn anything, so the capability is deny-by-default like
   every other action.

2. Children inherit the parent's *budget*, not a fresh one. A shared
   `Budget` object means a child cannot reset the cap by existing, and the
   parent stops when the total spend is exhausted. This is the difference
   between a cost cap and a cost suggestion.

3. Depth is bounded. `max_depth` prevents an agent from recursively
   spawning children until the process dies — the multi-agent equivalent of
   an infinite loop.

4. Every child action lands in the *same* ledger as the parent, tagged with
   its delegation path, so the trail reconstructs a tree rather than a set
   of unrelated runs.

The orchestration strategy is deliberately pluggable: `sequential` runs a
fixed plan in order, `fan_out` runs independent children and joins them.
A planner (any callable) decides what to spawn; the orchestrator guarantees
governance regardless of what the planner proposes.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field

from .budget import BudgetExceeded
from .runtime import AgentRuntime, PolicyDenied, RunResult


class DelegationError(Exception):
    """Raised only for programmer errors (e.g. a negative max_depth).

    Runtime refusals are reported as `DelegationResult(denied=True)` so that
    iterating a plan never aborts partway with an exception.
    """


@dataclass
class Delegation:
    """One parent -> child hand-off requested by a planner."""

    agent_id: str
    task: str
    tools: dict[str, tuple[str, Callable[[], str]]] = field(default_factory=dict)
    model: str = "mock"


@dataclass
class DelegationResult:
    agent_id: str
    depth: int
    result: RunResult | None = None
    error: str = ""
    denied: bool = False


@dataclass
class OrchestrationResult:
    root_agent: str
    delegations: list[DelegationResult] = field(default_factory=list)
    cost_usd: float = 0.0

    @property
    def succeeded(self) -> int:
        return sum(1 for d in self.delegations if d.result is not None and not d.denied)

    @property
    def denied(self) -> int:
        return sum(1 for d in self.delegations if d.denied)


class Orchestrator:
    """Runs a parent agent that may delegate to children, under one governance frame."""

    def __init__(
        self,
        *,
        root: AgentRuntime,
        max_depth: int = 2,
        max_children: int = 8,
    ):
        if max_depth < 0:
            raise ValueError("max_depth must be >= 0")
        self.root = root
        self.max_depth = max_depth
        self.max_children = max_children
        self._spawned = 0

    def _child_runtime(self, parent: AgentRuntime, child_id: str) -> AgentRuntime:
        """Build a child that shares the parent's ledger, policy and budget.

        Sharing the `Budget` object is the load-bearing detail: it makes the
        cap cumulative across the whole tree.
        """
        return AgentRuntime(
            agent_id=child_id,
            ledger=parent.ledger,
            policy=parent.policy,
            budget=parent.budget,
            provider=parent.provider,
            registry=parent.registry,
        )

    def delegate(self, parent: AgentRuntime, delegation: Delegation, depth: int) -> DelegationResult:
        """Hand work from `parent` to a child, refusing rather than raising.

        Every refusal — depth, fan-out, policy, unknown identity — comes back
        as a `DelegationResult` with `denied=True`, so a caller iterating a
        plan always gets a result per delegation instead of an exception
        partway through.
        """
        if depth > self.max_depth:
            return self._refuse(
                parent, delegation, depth,
                f"max delegation depth {self.max_depth} exceeded",
            )
        if self._spawned >= self.max_children:
            return self._refuse(
                parent, delegation, depth,
                f"max children per orchestration ({self.max_children}) reached",
            )

        # A child must be a known principal; an unregistered agent has no
        # role and therefore no authority. This is checked before the policy
        # question so a refusal for an unknown identity writes one deny
        # record rather than an allow followed by a deny, which would read
        # like a successful authorization to anyone auditing the ledger.
        if parent.registry is not None:
            try:
                parent.registry.get(delegation.agent_id)
            except Exception as exc:
                return self._refuse(parent, delegation, depth, str(exc))

        # The delegation itself is a governed action: deny-by-default policy
        # decides whether this parent may hand work to this child.
        try:
            parent._authorize("agent.delegate", target=delegation.agent_id)
        except PolicyDenied as exc:
            return self._refuse(parent, delegation, depth, str(exc))

        self._spawned += 1
        child = self._child_runtime(parent, delegation.agent_id)
        parent.ledger.append(
            parent.agent_id,
            "agent.delegate.accepted",
            target=delegation.agent_id,
            decision="allow",
            metadata={"depth": depth, "task": delegation.task[:120]},
        )
        try:
            res = child.run(delegation.task, model=delegation.model, tools=delegation.tools)
        except (PolicyDenied, BudgetExceeded) as exc:
            return DelegationResult(
                agent_id=delegation.agent_id, depth=depth, error=str(exc), denied=True
            )
        return DelegationResult(agent_id=delegation.agent_id, depth=depth, result=res)

    def _refuse(
        self, parent: AgentRuntime, delegation: Delegation, depth: int, reason: str
    ) -> DelegationResult:
        """Record a refused delegation in the ledger and return the outcome."""
        parent.ledger.append(
            parent.agent_id,
            "agent.delegate",
            target=delegation.agent_id,
            decision="deny",
            reason=reason,
        )
        return DelegationResult(
            agent_id=delegation.agent_id, depth=depth, error=reason, denied=True
        )

    def sequential(self, plan: Sequence[Delegation]) -> OrchestrationResult:
        """Run each delegation in order. One failure does not abort the rest."""
        out = OrchestrationResult(root_agent=self.root.agent_id)
        for delegation in plan:
            dr = self.delegate(self.root, delegation, depth=1)
            out.delegations.append(dr)
            if dr.result is not None:
                out.cost_usd += dr.result.cost_usd
        return out

    def fan_out(self, delegations: Iterable[Delegation]) -> OrchestrationResult:
        """Run independent delegations and join the results.

        Execution is sequential on purpose: a shared budget and a single
        append-only ledger both need a consistent order, and parallelism
        would make cost accounting race.
        """
        return self.sequential(list(delegations))

    def nested(self, tree: dict[str, Sequence[Delegation]], *, root_task: str) -> OrchestrationResult:
        """Walk a parent -> children tree, delegating level by level.

        `tree` maps a parent agent id to the delegations that parent makes.
        The root agent's own run happens first so its context is in the
        ledger before children append to it.
        """
        out = OrchestrationResult(root_agent=self.root.agent_id)
        self.root.run(root_task)
        frontier: list[tuple[AgentRuntime, int]] = [(self.root, 1)]

        while frontier:
            parent, depth = frontier.pop(0)
            if depth > self.max_depth:
                continue
            for delegation in tree.get(parent.agent_id, []):
                dr = self.delegate(parent, delegation, depth=depth)
                out.delegations.append(dr)
                if dr.result is not None:
                    out.cost_usd += dr.result.cost_usd
                if dr.result is not None and depth < self.max_depth:
                    child = self._child_runtime(parent, delegation.agent_id)
                    frontier.append((child, depth + 1))
        return out
