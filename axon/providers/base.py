# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 msy898931-boop
# Part of the AXON open core. See NOTICE for the license map.
"""Shared provider primitives: usage, completion, errors, pricing."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Usage:
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0

    def __add__(self, other: Usage) -> Usage:
        return Usage(
            self.input_tokens + other.input_tokens,
            self.output_tokens + other.output_tokens,
            self.cost_usd + other.cost_usd,
        )


@dataclass
class Completion:
    text: str
    model: str
    usage: Usage = field(default_factory=Usage)
    raw: dict | None = None


class ProviderError(RuntimeError):
    """Base class for provider failures."""


class AuthError(ProviderError):
    """Missing or rejected credentials. Never retried."""


class RateLimitError(ProviderError):
    """Provider throttled us. Retried with backoff."""


class TransientError(ProviderError):
    """Network hiccup or 5xx. Retried with backoff."""


# USD per 1M tokens: (input, output). Illustrative, overridable per deployment.
PRICES: dict[str, tuple[float, float]] = {
    "mock": (0.0, 0.0),
    "claude-opus": (15.0, 75.0),
    "claude-sonnet": (3.0, 15.0),
    "claude-haiku": (0.80, 4.0),
    "gpt-4o-mini": (0.15, 0.60),
    "gpt-4o": (2.5, 10.0),
    "gpt-4.1": (2.0, 8.0),
    "o3": (2.0, 8.0),
    "gemini-flash": (0.30, 1.20),
    "gemini-pro": (1.25, 5.0),
    "qwen3": (0.20, 0.80),
    "deepseek-v3": (0.14, 0.28),
    "llama3-local": (0.0, 0.0),
}


def price_for(model: str, usage: Usage) -> float:
    """Longest-prefix match so 'gpt-4o-mini' never resolves to 'gpt-4o'."""
    key = max((k for k in PRICES if model.startswith(k)), key=len, default=None)
    if key is None:
        return 0.0
    inp, out = PRICES[key]
    return (usage.input_tokens / 1_000_000) * inp + (usage.output_tokens / 1_000_000) * out


def register_price(model: str, input_per_m: float, output_per_m: float) -> None:
    PRICES[model] = (input_per_m, output_per_m)
