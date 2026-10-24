"""Provider tests.

These exercise the real HTTP transport against a real local HTTP server —
no mocking of our own logic. The server speaks the wire format of each API,
so parsing, retries, and error mapping are all genuinely covered.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from axon.providers import (
    AnthropicProvider,
    AuthError,
    OpenAICompatibleProvider,
    ProviderError,
    RateLimitError,
    Usage,
    get_provider,
    price_for,
    register_price,
)


class _Handler(BaseHTTPRequestHandler):
    """Configurable fake API. Set `server.behaviour` per test."""

    def log_message(self, *a):  # silence
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        server = self.server
        server.requests.append(
            {"path": self.path, "headers": {k.lower(): v for k, v in self.headers.items()}}
        )

        status, payload = server.behaviour(self)
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def api():
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    server.requests = []
    server.behaviour = lambda h: (200, {})
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    server.server_close()


def base_url(api) -> str:
    return f"http://127.0.0.1:{api.server_address[1]}"


# ---------------------------------------------------------------- pricing

def test_price_uses_longest_prefix_match():
    u = Usage(1_000_000, 1_000_000)
    assert price_for("gpt-4o-mini", u) == 0.15 + 0.60
    assert price_for("gpt-4o", u) == 2.5 + 10.0


def test_price_unknown_model_is_free():
    assert price_for("some-future-model", Usage(10**9, 10**9)) == 0.0


def test_register_price_overrides():
    register_price("my-model", 1.0, 2.0)
    assert price_for("my-model", Usage(1_000_000, 1_000_000)) == 3.0


def test_usage_addition():
    total = Usage(10, 5, 0.1) + Usage(20, 7, 0.2)
    assert (total.input_tokens, total.output_tokens) == (30, 12)
    assert abs(total.cost_usd - 0.3) < 1e-9


# ---------------------------------------------------------------- registry

def test_registry_resolves_names():
    assert isinstance(get_provider("anthropic"), AnthropicProvider)
    assert isinstance(get_provider("openai"), OpenAICompatibleProvider)
    assert get_provider("claude").name == "anthropic"


def test_registry_unknown_provider_raises():
    with pytest.raises(ValueError, match="unknown provider"):
        get_provider("nope")


# ---------------------------------------------------------------- anthropic

def test_anthropic_parses_messages_response(api):
    api.behaviour = lambda h: (200, {
        "model": "claude-sonnet-4-20250514",
        "content": [{"type": "text", "text": "hello from claude"}],
        "usage": {"input_tokens": 1000, "output_tokens": 500},
    })
    p = AnthropicProvider(api_key="sk-ant-test", base_url=base_url(api))
    out = p.complete("hi", model="claude-sonnet")

    assert out.text == "hello from claude"
    assert out.usage.input_tokens == 1000
    assert out.usage.cost_usd == pytest.approx(3.0 * 0.001 + 15.0 * 0.0005)
    assert api.requests[0]["path"] == "/messages"
    assert api.requests[0]["headers"]["x-api-key"] == "sk-ant-test"
    assert api.requests[0]["headers"]["anthropic-version"]


def test_anthropic_joins_multiple_text_blocks(api):
    api.behaviour = lambda h: (200, {
        "content": [{"type": "text", "text": "part one "}, {"type": "text", "text": "part two"}],
        "usage": {"input_tokens": 1, "output_tokens": 1},
    })
    p = AnthropicProvider(api_key="k", base_url=base_url(api))
    assert p.complete("x", model="claude-sonnet").text == "part one part two"


def test_anthropic_requires_key(monkeypatch):
    monkeypatch.delenv("AXON_ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with pytest.raises(AuthError, match="not set"):
        AnthropicProvider(api_key="", base_url="http://127.0.0.1:1").complete("x")


def test_anthropic_401_is_auth_error_not_retried(api):
    api.behaviour = lambda h: (401, {"error": "bad key"})
    p = AnthropicProvider(api_key="bad", base_url=base_url(api), max_retries=4)
    with pytest.raises(AuthError):
        p.complete("x")
    assert len(api.requests) == 1  # never retried


# ---------------------------------------------------------------- openai

def test_openai_parses_chat_completion(api):
    api.behaviour = lambda h: (200, {
        "model": "gpt-4o-mini",
        "choices": [{"message": {"content": "hi from gpt"}}],
        "usage": {"prompt_tokens": 1000, "completion_tokens": 1000},
    })
    p = OpenAICompatibleProvider(api_key="sk-test", base_url=base_url(api))
    out = p.complete("hello", model="gpt-4o-mini")

    assert out.text == "hi from gpt"
    assert out.usage.cost_usd == pytest.approx(0.15 * 0.001 + 0.60 * 0.001)
    assert api.requests[0]["path"] == "/chat/completions"
    assert api.requests[0]["headers"]["authorization"] == "Bearer sk-test"


def test_openai_local_server_needs_no_key(api):
    api.behaviour = lambda h: (200, {
        "choices": [{"message": {"content": "local"}}],
        "usage": {"prompt_tokens": 5, "completion_tokens": 5},
    })
    p = OpenAICompatibleProvider(base_url=base_url(api), requires_key=False)
    assert p.complete("x", model="llama3-local").text == "local"
    assert "authorization" not in api.requests[0]["headers"]


def test_openai_retries_then_succeeds(api):
    calls = {"n": 0}

    def behaviour(h):
        calls["n"] += 1
        if calls["n"] < 3:
            return (503, {"error": "overloaded"})
        return (200, {"choices": [{"message": {"content": "finally"}}],
                      "usage": {"prompt_tokens": 1, "completion_tokens": 1}})

    api.behaviour = behaviour
    p = OpenAICompatibleProvider(api_key="k", base_url=base_url(api), max_retries=4)
    assert p.complete("x", model="gpt-4o-mini").text == "finally"
    assert calls["n"] == 3


def test_rate_limit_raises_after_exhausting_retries(api):
    api.behaviour = lambda h: (429, {"error": "slow down"})
    p = OpenAICompatibleProvider(api_key="k", base_url=base_url(api), max_retries=1)
    with pytest.raises(RateLimitError):
        p.complete("x")
    assert len(api.requests) == 2  # initial + 1 retry


def test_client_error_is_not_retried(api):
    api.behaviour = lambda h: (400, {"error": "bad request"})
    p = OpenAICompatibleProvider(api_key="k", base_url=base_url(api), max_retries=3)
    with pytest.raises(ProviderError) as exc:
        p.complete("x")
    assert not isinstance(exc.value, RateLimitError)
    assert len(api.requests) == 1


# ---------------------------------------------------------------- governed

def test_runtime_governs_a_real_provider_over_http(api, tmp_path):
    """The full loop: policy + budget + audit around a real HTTP model call."""
    from axon.core.audit import AuditLedger
    from axon.core.budget import Budget
    from axon.core.policy import PolicyEngine
    from axon.core.runtime import AgentRuntime

    api.behaviour = lambda h: (200, {
        "choices": [{"message": {"content": "done"}}],
        "usage": {"prompt_tokens": 2000, "completion_tokens": 1000},
    })
    provider = OpenAICompatibleProvider(api_key="k", base_url=base_url(api))
    runtime = AgentRuntime(
        agent_id="a1",
        ledger=AuditLedger(tmp_path / "l.jsonl"),
        policy=PolicyEngine.permissive(),
        budget=Budget(limit_usd=1.0),
        provider=provider,
    )
    result = runtime.run("do a thing", model="gpt-4o-mini")

    assert result.cost_usd > 0
    assert result.denied == 0
    assert api.requests  # a real HTTP call happened
    ok, msg = runtime.ledger.verify()
    assert ok, msg
