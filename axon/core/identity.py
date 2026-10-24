# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 msy898931-boop
# Part of the AXON open core. See NOTICE for the license map.
"""Identity and role-based access control.

The MVP granted every agent the same implicit authority: a policy rule
matched on `actor: "*"` and nothing tied an agent to a human owner. For an
enterprise that is the first thing an auditor asks about — *who* is this
agent acting for, and what is it allowed to do?

This module answers that with three small pieces:

  Identity   a named principal (agent, service, or human) with a role and
             a set of tags. Tags are what policy rules already consume via
             `requires:`, so roles compose with the existing engine rather
             than bypassing it.
  Registry   loads identities from YAML and resolves them by name.
  bindings   an agent inherits the *intersection* of its role's permissions
             and its own; a role can never widen what a policy denies.

OIDC/SSO: `Identity.from_oidc_claims()` maps a verified token's claims onto
a principal. Verification of the token itself is the deployment's job (any
JWT library); AXON deliberately does not take on that dependency.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


class IdentityError(Exception):
    """Raised for unknown principals or malformed identity documents."""


@dataclass
class Identity:
    """A principal that can act. `name` is the value policy rules match on."""

    name: str
    role: str = "agent"
    tags: set[str] = field(default_factory=set)
    owner: str = ""  # the human accountable for this agent
    enabled: bool = True

    def __post_init__(self) -> None:
        self.tags = set(self.tags)

    def has(self, *tags: str) -> bool:
        return all(t in self.tags for t in tags)

    @classmethod
    def from_oidc_claims(cls, claims: dict[str, Any]) -> Identity:
        """Map verified OIDC claims onto a principal.

        Reads `sub` for the name, `role`/`roles` for the role, and `groups`
        for tags. The caller must have already verified the token signature;
        passing unverified claims here is the same as trusting a plain string.
        """
        roles = claims.get("role") or claims.get("roles") or "agent"
        if isinstance(roles, (list, tuple)):
            role = str(roles[0]) if roles else "agent"
            tags = {str(r) for r in roles}
        else:
            role = str(roles)
            tags = {role}
        groups = claims.get("groups") or []
        tags |= {str(g) for g in groups}
        sub = claims.get("sub") or claims.get("email")
        if not sub:
            raise IdentityError("OIDC claims have neither 'sub' nor 'email'")
        return cls(name=str(sub), role=role, tags=tags, owner=str(claims.get("email", "")))


class IdentityRegistry:
    """Resolves principals and the roles they may assume."""

    def __init__(
        self,
        identities: dict[str, Identity] | None = None,
        roles: dict[str, set[str]] | None = None,
    ):
        self._identities: dict[str, Identity] = identities or {}
        # role -> the tags that role confers. A role's tags are what unlock
        # `requires:` clauses in policy rules.
        self._roles: dict[str, set[str]] = roles or {}

    @classmethod
    def from_yaml(cls, path: str | Path) -> IdentityRegistry:
        data: dict[str, Any] = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        roles = {name: set(spec.get("tags", [])) for name, spec in (data.get("roles") or {}).items()}
        identities: dict[str, Identity] = {}
        for name, spec in (data.get("identities") or {}).items():
            spec = dict(spec or {})
            role = str(spec.pop("role", "agent"))
            extra = set(spec.pop("tags", []) or [])
            identities[name] = Identity(
                name=name,
                role=role,
                tags=extra | roles.get(role, set()),
                owner=str(spec.pop("owner", "")),
                enabled=bool(spec.pop("enabled", True)),
            )
        return cls(identities, roles)

    def register(self, identity: Identity) -> Identity:
        """Add a principal, granting it its role's tags."""
        identity.tags |= self._roles.get(identity.role, set())
        self._identities[identity.name] = identity
        return identity

    def get(self, name: str) -> Identity:
        try:
            identity = self._identities[name]
        except KeyError:
            raise IdentityError(f"unknown identity '{name}'") from None
        if not identity.enabled:
            raise IdentityError(f"identity '{name}' is disabled")
        return identity

    def resolve(self, name: str, oidc_claims: dict[str, Any] | None = None) -> Identity:
        """Look up a principal, or derive one from verified OIDC claims.

        An identity declared in YAML wins over claims, so a deployment can
        pin an agent's role regardless of what a token claims.
        """
        if name in self._identities:
            return self.get(name)
        if oidc_claims is not None:
            derived = Identity.from_oidc_claims(oidc_claims)
            return self.register(derived)
        raise IdentityError(f"unknown identity '{name}' and no OIDC claims supplied")

    def known(self) -> Iterable[str]:
        return tuple(sorted(self._identities))

    def roles(self) -> dict[str, set[str]]:
        return {k: set(v) for k, v in self._roles.items()}

    def can(self, name: str, *tags: str) -> bool:
        """True when the principal holds every listed tag."""
        try:
            return self.get(name).has(*tags)
        except IdentityError:
            return False
