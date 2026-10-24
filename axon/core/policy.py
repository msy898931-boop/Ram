"""Policy engine — deny-by-default authorization for agent actions.

Rules are evaluated in order; the first matching rule wins. If nothing
matches, the action is denied (fail-closed). This is the core of AXON
Shield: no agent may take a privileged action without an explicit grant.

Rule fields (all optional except `action`):
    action:   glob pattern matched against the requested action
    actor:    glob pattern matched against the agent identity
    target:   glob pattern matched against the resource (path/URL/etc.)
    effect:   "allow" or "deny"  (default: deny)
    requires: list of tags that must ALL be satisfied by the request
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class Rule:
    action: str = "*"
    actor: str = "*"
    target: str = "*"
    effect: str = "deny"
    requires: list[str] = field(default_factory=list)

    @staticmethod
    def _match(pattern: str, value: str) -> bool:
        return fnmatch.fnmatch(value, pattern)

    def matches(self, actor: str, action: str, target: str, tags: set[str]) -> bool:
        return (
            self._match(self.actor, actor)
            and self._match(self.action, action)
            and self._match(self.target, target)
            and all(t in tags for t in self.requires)
        )


@dataclass
class Decision:
    allowed: bool
    reason: str
    rule: Rule | None = None


class PolicyEngine:
    """Loads YAML policies and answers allow/deny for each request."""

    def __init__(self, rules: list[Rule] | None = None):
        self.rules: list[Rule] = rules or []

    @classmethod
    def from_yaml(cls, path: str | Path) -> PolicyEngine:
        data: dict[str, Any] = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        rules = [Rule(**r) for r in data.get("rules", [])]
        return cls(rules)

    @classmethod
    def permissive(cls) -> PolicyEngine:
        """Explicit opt-out of governance. For local dev and tests only.

        Never use in production: it disables the fail-closed guarantee that
        is AXON's entire point. Kept as a loud, greppable name so an audit
        of a deployment can find every use with one search.
        """
        return cls([Rule(action="*", actor="*", target="*", effect="allow")])

    @classmethod
    def bootstrap(cls) -> PolicyEngine:
        """A safe starting policy: model calls allowed, nothing else.

        This is what `axon run` uses when the caller passes no policy file.
        Unlike `permissive()` it keeps tools denied, so a first run cannot
        touch a filesystem or a network by accident.
        """
        return cls([
            Rule(action="model.complete", actor="*", target="*", effect="allow"),
            Rule(action="run.start", actor="*", target="*", effect="allow"),
            Rule(action="run.end", actor="*", target="*", effect="allow"),
        ])

    def evaluate(
        self, actor: str, action: str, target: str = "", tags: set[str] | None = None
    ) -> Decision:
        tags = tags or set()
        for rule in self.rules:
            if rule.matches(actor, action, target, tags):
                allowed = rule.effect == "allow"
                return Decision(
                    allowed=allowed,
                    reason=f"matched rule: {rule.effect} {rule.actor}:{rule.action}->{rule.target}",
                    rule=rule,
                )
        return Decision(allowed=False, reason="no matching rule (deny by default)")
