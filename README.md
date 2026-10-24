<div align="center">

# AXON

**The enterprise control plane for AI agents.**

Govern every agent. Audit every action. Cap every cost. Lock in no vendor.

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/tests-12%20passing-brightgreen.svg)](tests/)

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

# Run a governed task
axon run "read the changelog" --tool read_file=/sandbox/CHANGELOG.md --ledger ./audit.jsonl

# Verify the audit trail
axon audit --ledger ./audit.jsonl

# Test a policy decision
axon policy-check tool.read_file --target /home/deploy/secrets/db.txt
# -> DENY  matched rule: deny *:tool.*->*secrets*

# See the full governance demo
python3 examples/demo.py
```

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
│   ├── providers.py  # model-agnostic adapters (OpenAI-compatible, mock)
│   └── runtime.py    # the governed execution loop
├── policies/
│   └── default.yaml  # starter policy
└── cli.py            # run / audit / export-otel / policy-check
```

## Status

**MVP (v0.1.0)** — single-agent governed runtime. The multi-agent
orchestrator, web dashboard, and enterprise compliance packs build on this
same primitive.

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
