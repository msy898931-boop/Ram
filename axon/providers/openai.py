"""OpenAI-compatible adapter — OpenAI, Azure, Ollama, vLLM, Together, Groq..."""

from __future__ import annotations

import os

from .base import AuthError, Completion, Usage, price_for
from .transport import post_json

DEFAULT_BASE = "https://api.openai.com/v1"
DEFAULT_MODEL = "gpt-4o-mini"


class OpenAICompatibleProvider:
    """Works with any endpoint implementing POST /chat/completions.

    Env: AXON_API_KEY (or OPENAI_API_KEY), AXON_BASE_URL.
    Local servers (Ollama/vLLM) need no key — set only AXON_BASE_URL.
    """

    name = "openai"

    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        *,
        timeout: float = 60.0,
        max_retries: int = 4,
        max_tokens: int = 1024,
        requires_key: bool = True,
    ):
        self.base_url = (base_url or os.getenv("AXON_BASE_URL", DEFAULT_BASE)).rstrip("/")
        self.api_key = api_key or os.getenv("AXON_API_KEY") or os.getenv("OPENAI_API_KEY", "")
        self.timeout = timeout
        self.max_retries = max_retries
        self.max_tokens = max_tokens
        self.requires_key = requires_key

    def complete(self, prompt: str, model: str = DEFAULT_MODEL, **kw) -> Completion:
        if self.requires_key and not self.api_key:
            raise AuthError("AXON_API_KEY is not set")

        payload = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": kw.get("max_tokens", self.max_tokens),
        }
        if temperature := kw.get("temperature"):
            payload["temperature"] = temperature

        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        data = post_json(
            f"{self.base_url}/chat/completions",
            payload,
            headers,
            timeout=self.timeout,
            max_retries=self.max_retries,
        )

        choice = data["choices"][0]["message"]["content"] or ""
        u = data.get("usage", {})
        usage = Usage(u.get("prompt_tokens", 0), u.get("completion_tokens", 0))
        usage.cost_usd = price_for(model, usage)
        return Completion(text=choice, model=data.get("model", model), usage=usage, raw=data)
