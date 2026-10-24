"""Native Anthropic Messages API adapter."""

from __future__ import annotations

import os

from .base import AuthError, Completion, Usage, price_for
from .transport import post_json

DEFAULT_BASE = "https://api.anthropic.com/v1"
DEFAULT_MODEL = "claude-sonnet-4-20250514"
API_VERSION = "2023-06-01"


class AnthropicProvider:
    """Talks the Anthropic Messages API directly.

    Env: AXON_ANTHROPIC_API_KEY (or ANTHROPIC_API_KEY), AXON_ANTHROPIC_BASE.
    """

    name = "anthropic"

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
        *,
        timeout: float = 60.0,
        max_retries: int = 4,
        max_tokens: int = 1024,
    ):
        self.api_key = api_key or os.getenv("AXON_ANTHROPIC_API_KEY") or os.getenv("ANTHROPIC_API_KEY", "")
        self.base_url = (base_url or os.getenv("AXON_ANTHROPIC_BASE", DEFAULT_BASE)).rstrip("/")
        self.timeout = timeout
        self.max_retries = max_retries
        self.max_tokens = max_tokens

    def complete(self, prompt: str, model: str = DEFAULT_MODEL, **kw) -> Completion:
        if not self.api_key:
            raise AuthError("AXON_ANTHROPIC_API_KEY is not set")

        payload = {
            "model": model,
            "max_tokens": kw.get("max_tokens", self.max_tokens),
            "messages": [{"role": "user", "content": prompt}],
        }
        if system := kw.get("system"):
            payload["system"] = system
        if temperature := kw.get("temperature"):
            payload["temperature"] = temperature

        data = post_json(
            f"{self.base_url}/messages",
            payload,
            {
                "Content-Type": "application/json",
                "x-api-key": self.api_key,
                "anthropic-version": API_VERSION,
            },
            timeout=self.timeout,
            max_retries=self.max_retries,
        )

        text = "".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text")
        u = data.get("usage", {})
        usage = Usage(u.get("input_tokens", 0), u.get("output_tokens", 0))
        usage.cost_usd = price_for(model, usage)
        return Completion(text=text, model=data.get("model", model), usage=usage, raw=data)
