<div align="center">

# AXON

**The enterprise control plane for AI agents.**

Govern every agent. Audit every action. Cap every cost. Lock in no vendor.

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/tests-28%20passing-brightgreen.svg)](tests/)
[![CI](https://github.com/msy898931-boop/Ram/actions/workflows/ci.yml/badge.svg)](https://github.com/msy898931-boop/Ram/actions/workflows/ci.yml)
[![Providers](https://img.shields.io/badge/providers-anthropic%20%7C%20openai%20%7C%20ollama-8A2BE2.svg)](#real-model-providers)
[![Deny by default](https://img.shields.io/badge/policy-deny--by--default-critical.svg)](#why-it-is-different)

</div>

---

## The problem

Every company is deploying AI agents. Almost none can answer, on demand:

- **Who allowed this agent to do that?**
- **How much did that agent spend last month?**
- **Was any sensitive data sent to a third-party model?**
- **Can we prove to an auditor what the agent did?**

Vendors sell you an *agent*. Nobody sells you the **governor**.

## What AXON is

AXON is the layer that sits **around** your agents — Claude Code, Codex, Cursor,
Qwen, a local model, anything — and enforces three things no matter what:

| Module | What it does |
|---|---|
| 🛡️ **Shield** | Deny-by-default policy engine. No agent acts without an explicit grant. |
| 📊 **Observe** | Tamper-evident audit ledger + hard per-run cost caps. |
| 🔌 **Core** | Model-agnostic runtime. Swap Anthropic / OpenAI / Gemini / Ollama freely. |

## Quickstart

```bash
pip install -e ".[dev]"

# Run a governed task (offline mock by default)
axon run "read the changelog" --tool read_file=/sandbox/CHANGELOG.md --ledger ./audit.jsonl

# Verify the audit trail
axon audit --ledger ./audit.jsonl

# Test a policy decision
axon policy-check tool.read_file --target /home/deploy/secrets/db.txt
# -> DENY  matched rule: deny *:tool.*->*secrets*

# List providers and prices
axon models

# See the full governance demo
python3 examples/demo.py
```

## Real model providers

AXON is model-agnostic. Pick a provider by name, or let it auto-detect from
the environment.

```bash
export AXON_ANTHROPIC_API_KEY=sk-ant-...        # Anthropic Messages API
export AXON_API_KEY=sk-...                      # OpenAI / Azure / Groq / Together
export AXON_BASE_URL=http://localhost:11434/v1  # Ollama / vLLM (no key needed)

axon run "summarise the incident" --provider anthropic --model claude-sonnet --budget 0.25
axon run "summarise the incident" --provider openai --model gpt-4o-mini
axon run "summarise the incident" --provider ollama --model llama3-local
```

```python
from axon.providers import get_provider

provider = get_provider("anthropic")           # or "openai", "ollama", "vllm", "mock"
result = provider.complete("hello", model="claude-sonnet")
print(result.text, result.usage.cost_usd)
```

Every adapter speaks the vendor's real wire format over stdlib HTTP — no SDK
lock-in, installable in air-gapped environments. Failures are typed
(`AuthError`, `RateLimitError`, `TransientError`) with bounded exponential
backoff; auth and 4xx errors are never retried.

| Provider | Auth env | Notes |
|---|---|---|
| `anthropic` | `AXON_ANTHROPIC_API_KEY` | Native Messages API, `anthropic-version` pinned |
| `openai` | `AXON_API_KEY` | Any OpenAI-compatible endpoint |
| `ollama` / `vllm` | none | Local, keyless |
| `mock` | none | Deterministic, zero-cost — tests and demos |

## Why it is different

| | AXON | Typical agent tool |
|---|---|---|
| Model-agnostic | ✅ any provider | ❌ one vendor |
| Deny-by-default policy | ✅ | ❌ |
| Tamper-evident audit | ✅ hash-chained | ❌ logs you can edit |
| Hard cost caps | ✅ | ❌ surprise invoices |
| Self-hosted / air-gapped | ✅ | ❌ cloud only |

## How the audit ledger works

```
record_hash = SHA256(prev_hash || canonical_json(record))
```

Each record commits to the previous hash, so mutating or deleting any
historical record breaks every subsequent hash — an auditor can verify the
whole trail without trusting the operator. See `axon/core/audit.py`.

## Architecture

```
axon/
├── core/
│   ├── audit.py      # tamper-evident, hash-chained ledger
│   ├── policy.py     # deny-by-default rule engine
│   ├── budget.py     # hard cost caps
│   └── runtime.py    # the governed execution loop
├── providers/
│   ├── base.py       # usage, pricing, typed errors
│   ├── transport.py  # retries, backoff, error mapping
│   ├── anthropic.py  # native Messages API
│   ├── openai.py     # any OpenAI-compatible endpoint
│   └── __init__.py   # registry + auto-detection
├── policies/
│   └── default.yaml  # starter policy
└── cli.py            # run / models / audit / export-otel / policy-check
```

## Status

**v0.2.0** — governed single-agent runtime with live Anthropic and
OpenAI-compatible providers, deny-by-default policy, tamper-evident audit,
and hard cost caps. The multi-agent orchestrator, web dashboard, and
enterprise compliance packs build on this same primitive.

See [CHANGELOG.md](CHANGELOG.md) for what shipped and what is next.

## Documentation

- [Full business plan](AXON-PLAN.md)
- [Financial model](AXON-FINANCIALS.md)
- [Investor pitch + speaker notes](AXON-PITCH.md)
- [Pitch deck (interactive)](pitch/axon-deck.html)

## Contributing

We welcome contributions. See [CONTRIBUTING.md](CONTRIBUTING.md) and
[SECURITY.md](SECURITY.md).

## License

Apache-2.0. The governance modules (Shield/Observe/Vault) are developed in a
separate enterprise repository under a commercial license.
