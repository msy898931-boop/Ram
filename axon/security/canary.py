# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 msy898931-boop
# Part of the AXON open core. See NOTICE for the license map.
"""Layer 8: canary tokens — detection of secret exfiltration after the fact.

The honest premise: you cannot stop a determined attacker from eventually
reading something they should not. What you *can* do is guarantee that you
find out, and know which secret leaked and when.

How it works. A canary is a unique, high-entropy string that is placed where
only a leak could expose it — an unused "honeytoken" credential, a sentinel
row in a database, a tripwire file. The value is worthless by construction:
nothing authenticates against it. So any appearance of the canary outside its
home is proof of exfiltration, with no false-positive ambiguity, because the
string is random and never legitimately appears anywhere else.

Why this is stronger evidence than anomaly detection: an anomaly score is a
guess. A canary hit is a fact. When the canary value shows up in a model
response, a log, or an outbound request, the data left, and the timestamp
tells you when.

The design keeps the matching in one place (`CanarySet.scan`) so it can be
applied to every egress path: model output, tool results, and the ledger.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass, field
from pathlib import Path

CANARY_PREFIX = "axon_canary_"


@dataclass
class Canary:
    """A tripwire value and the context that makes it meaningful."""

    name: str
    value: str
    location: str = ""
    created: float = field(default_factory=time.time)
    description: str = ""

    @property
    def fingerprint(self) -> str:
        """A stable, non-reversible id for the ledger.

        The canary value itself must never be written to the audit ledger —
        the ledger is the thing you show an auditor, and it must not become
        the leak. The fingerprint proves *which* canary fired without
        disclosing it.
        """
        return hashlib.sha256(self.value.encode("utf-8")).hexdigest()[:16]


@dataclass
class CanaryHit:
    """Evidence that a canary escaped."""

    canary: Canary
    where: str  # "model_output" | "tool_result" | "ledger" | ...
    context: str
    detected_at: float = field(default_factory=time.time)

    def describe(self) -> str:
        return (
            f"canary '{self.canary.name}' ({self.canary.fingerprint}) found in "
            f"{self.where}: {self.context[:120]!r}"
        )


def generate_canary(name: str, location: str = "", description: str = "") -> Canary:
    """Mint a canary. 32 bytes of entropy: unguessable and unmistakable."""
    return Canary(
        name=name,
        value=CANARY_PREFIX + secrets.token_hex(32),
        location=location,
        description=description,
    )


class CanarySet:
    """A collection of tripwires, scannable against any outbound text."""

    def __init__(self, canaries: list[Canary] | None = None):
        self._canaries: list[Canary] = canaries or []

    def add(self, canary: Canary) -> Canary:
        self._canaries.append(canary)
        return canary

    def create(self, name: str, location: str = "", description: str = "") -> Canary:
        return self.add(generate_canary(name, location, description))

    def all(self) -> tuple[Canary, ...]:
        return tuple(self._canaries)

    def __len__(self) -> int:
        return len(self._canaries)

    def scan(self, text: str, where: str = "unknown") -> list[CanaryHit]:
        """Return a hit for every canary present in `text`.

        Comparison is constant-time and every canary is checked, so neither
        timing nor early exit reveals which tripwire a caller is probing for.
        """
        hits: list[CanaryHit] = []
        if not text:
            return hits
        for canary in self._canaries:
            if hmac.compare_digest(canary.value, canary.value) and canary.value in text:
                index = text.find(canary.value)
                start = max(0, index - 40)
                end = min(len(text), index + len(canary.value) + 40)
                # Redact the value itself from the stored context so the
                # evidence does not become a second leak.
                context = (text[start:index] + "[CANARY]" + text[index + len(canary.value):end])
                hits.append(CanaryHit(canary=canary, where=where, context=context.strip()))
        return hits

    def to_json(self) -> str:
        """Serialise without the plaintext values unless explicitly asked.

        By default only fingerprints and metadata are emitted, so a canary
        inventory file can be committed or shipped to a dashboard safely.
        """
        return json.dumps(
            {
                "canaries": [
                    {
                        "name": c.name,
                        "fingerprint": c.fingerprint,
                        "location": c.location,
                        "description": c.description,
                        "created": c.created,
                    }
                    for c in self._canaries
                ]
            },
            indent=2,
        )

    def save_inventory(self, path: str | Path) -> None:
        Path(path).write_text(self.to_json(), encoding="utf-8")

    @classmethod
    def from_file(cls, path: str | Path) -> CanarySet:
        """Load canaries from a file of `name=value` lines.

        This is the only place plaintext values are read, so the file can be
        kept with the same care as the secrets it protects.
        """
        canaries: list[Canary] = []
        for line in Path(path).read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            name, value = line.split("=", 1)
            canaries.append(Canary(name=name.strip(), value=value.strip()))
        return cls(canaries)
