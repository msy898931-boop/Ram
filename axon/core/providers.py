"""Model-agnostic provider layer.

AXON never locks you to a vendor. Every provider implements the same
`Provider.complete()` contract, so agents can run on Anthropic, OpenAI,
Gemini, a local Ollama/vLLM server, or a deterministic mock in tests.

Cost is computed per call from a price table, feeding AXON Observe's
cost-cap enforcement.
"""

from __future__ import annotations

import json
import os
import urllib.request
from dataclasses import dataclass, field
from typing import Protocol


@dataclass
class Usage:
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0


@dataclass
class Completion:
    text: str
    model: str
    usage: Usage = field(default_factory=Usage)


class Provider(Protocol):
    name: str

    def complete(self, prompt: str, model: str, **kw) -> Completion: ...


# USD per 1M tokens: (input, output). Illustrative defaults, overridable.
PRICES: dict[str, tuple[float, float]] = {
    "mock": (0.0, 0.0),
    "claude-sonnet": (3.0, 15.0),
    "gpt-4o": (2.5, 10.0),
    "gemini-flash": (0.30, 1.20),
    "qwen3": (0.20, 0.80),
    "deepseek-v3": (0.14, 0.28),
    "llama3-local": (0.0, 0.0),
}


def price_for(model: str, usage: Usage) -> float:
    key = next((k for k in PRICES if model.startswith(k)), None)
    if key is None:
        return 0.0
    inp, out = PRICES[key]
    return (usage.input_tokens / 1_000_000) * inp + (usage.output_tokens / 1_000_000) * out


class MockProvider:
    """Deterministic provider — used in tests and offline demos."""

    name = "mock"

    def complete(self, prompt: str, model: str = "mock", **kw) -> Completion:
        usage = Usage(
            input_tokens=len(prompt.split()),
            output_tokens=len(prompt.split()) // 2 + 1,
        )
        usage.cost_usd = price_for(model, usage)
        return Completion(text=f"[mock:{model}] {prompt[:80]}", model=model, usage=usage)


class OpenAICompatibleProvider:
    """Works with any OpenAI-compatible endpoint (OpenAI, Ollama, vLLM, ...)."""

    name = "openai-compatible"

    def __init__(self, base_url: str | None = None, api_key: str | None = None):
        self.base_url = (base_url or os.getenv("AXON_BASE_URL", "https://api.openai.com/v1")).rstrip("/")
        self.api_key = api_key or os.getenv("AXON_API_KEY", "")

    def complete(self, prompt: str, model: str, **kw) -> Completion:
        body = json.dumps(
            {"model": model, "messages": [{"role": "user", "content": prompt}]}
        ).encode()
        req = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=body,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read())
        text = data["choices"][0]["message"]["content"]
        u = data.get("usage", {})
        usage = Usage(u.get("prompt_tokens", 0), u.get("completion_tokens", 0))
        usage.cost_usd = price_for(model, usage)
        return Completion(text=text, model=model, usage=usage)


def default_provider() -> Provider:
    if os.getenv("AXON_API_KEY") or os.getenv("AXON_BASE_URL"):
        return OpenAICompatibleProvider()
    return MockProvider()
