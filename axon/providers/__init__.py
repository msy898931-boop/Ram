# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 msy898931-boop
# Part of the AXON open core. See NOTICE for the license map.
"""Model-agnostic provider layer.

AXON never locks you to a vendor. Every provider implements the same
`complete(prompt, model)` contract, so agents run on Anthropic, OpenAI,
Gemini, a local Ollama/vLLM server, or a deterministic mock.

    from axon.providers import get_provider
    provider = get_provider("anthropic")
"""

from __future__ import annotations

import os

from .anthropic import AnthropicProvider
from .base import (
    PRICES,
    AuthError,
    Completion,
    ProviderError,
    RateLimitError,
    TransientError,
    Usage,
    price_for,
    register_price,
)
from .openai import OpenAICompatibleProvider

__all__ = [
    "PRICES",
    "AnthropicProvider",
    "AuthError",
    "Completion",
    "MockProvider",
    "OpenAICompatibleProvider",
    "ProviderError",
    "RateLimitError",
    "TransientError",
    "Usage",
    "default_provider",
    "get_provider",
    "price_for",
    "register_price",
]


class MockProvider:
    """Deterministic provider for tests and offline demos. Costs nothing."""

    name = "mock"

    def complete(self, prompt: str, model: str = "mock", **kw) -> Completion:
        usage = Usage(
            input_tokens=len(prompt.split()),
            output_tokens=len(prompt.split()) // 2 + 1,
        )
        usage.cost_usd = price_for(model, usage)
        return Completion(text=f"[mock:{model}] {prompt[:80]}", model=model, usage=usage)


_PROVIDERS = {
    "mock": MockProvider,
    "anthropic": AnthropicProvider,
    "claude": AnthropicProvider,
    "openai": OpenAICompatibleProvider,
    "ollama": lambda **kw: OpenAICompatibleProvider(
        base_url=os.getenv("AXON_BASE_URL", "http://localhost:11434/v1"), requires_key=False, **kw
    ),
    "vllm": lambda **kw: OpenAICompatibleProvider(
        base_url=os.getenv("AXON_BASE_URL", "http://localhost:8000/v1"), requires_key=False, **kw
    ),
}


def get_provider(name: str, **kw):
    """Resolve a provider by name. Raises ValueError on unknown names."""
    try:
        factory = _PROVIDERS[name.lower()]
    except KeyError:
        raise ValueError(f"unknown provider '{name}'; choose from {sorted(_PROVIDERS)}") from None
    return factory(**kw)


def available_providers() -> list[str]:
    return sorted(_PROVIDERS)


def default_provider():
    """Auto-select from the environment: Anthropic > OpenAI > mock."""
    if os.getenv("AXON_ANTHROPIC_API_KEY") or os.getenv("ANTHROPIC_API_KEY"):
        return AnthropicProvider()
    if os.getenv("AXON_API_KEY") or os.getenv("OPENAI_API_KEY") or os.getenv("AXON_BASE_URL"):
        return OpenAICompatibleProvider()
    return MockProvider()
