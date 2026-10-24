<div align="center">

# AXON

**The enterprise control plane for AI agents.**

Govern every agent. Audit every action. Cap every cost. Lock in no vendor.

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/tests-332%20passing-brightgreen.svg)](tests/)
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
| 🛡️ **Shield** | Deny-by-default policy engine with three ready packs, and a checker that proves each pack refuses what it claims to. |
| 📊 **Observe** | Ed25519-signed, hash-chained audit ledger. Cost, denial, and integrity analytics. |
| 🔐 **Vault** | Secrets brokered as short-lived, single-use, policy-gated leases. Values never reach the ledger. |
| 🔌 **Core** | Model-agnostic runtime, RBAC, and a multi-agent orchestrator that keeps governance across delegation. |

## Quickstart

```bash
pip install -e ".[dev]"

# Run a governed task (offline mock by default)
axon run "read the changelog" --tool read_file=/sandbox/CHANGELOG.md --ledger ./audit.jsonl

# Verify the audit trail (supply the public key for strict verification)
axon keygen --key ./sign.key
axon audit --ledger ./audit.jsonl --pubkey ./sign.key.pub

# Check that each policy pack actually refuses what it claims to
axon shield

# Map compliance controls to the code and tests that implement them
axon compliance

# Open the governance dashboard over a real ledger
axon dashboard --ledger ./audit.jsonl --pubkey ./sign.key.pub

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
| Tamper-evident audit | ✅ hash-chained **and signed** | ❌ logs you can edit |
| Signature-stripping is caught | ✅ fail-closed verification | ❌ |
| Hard cost caps | ✅ shared across sub-agents | ❌ surprise invoices |
| Governed multi-agent delegation | ✅ | ❌ |
| Secret brokering | ✅ leased, never logged | ❌ env vars |
| Executable compliance mapping | ✅ 20 controls + evidence pack | ❌ a signed SOC 2 report |
| Self-hosted / air-gapped | ✅ | ❌ cloud only |

## How the audit ledger works

```
record_hash = SHA256(prev_hash || canonical_json(record))
signature   = Ed25519(seq || record_hash)
```

Each record commits to the previous hash, so mutating or deleting any
historical record breaks every subsequent hash. Hashing alone has a known
limit: whoever holds the file can rewrite the whole chain and re-hash it
consistently. Signing closes that gap, and `verify(public_key=...)` is
fail-closed — when the auditor supplies a key, every record must carry a
valid signature from it, so stripping signatures is detected rather than
ignored. The Ed25519 implementation is pure Python (RFC 8032), verified
against the RFC test vectors and cross-checked against `cryptography`.
See `axon/core/audit.py` and `axon/core/signing.py`.

## Architecture

```
axon/
├── core/
│   ├── audit.py         # hash-chained ledger with optional signatures
│   ├── signing.py       # pure-Python Ed25519 (RFC 8032)
│   ├── identity.py      # principals, roles, accountable owners
│   ├── policy.py        # deny-by-default rule engine
│   ├── budget.py        # hard cost caps, shared across delegation
│   ├── runtime.py       # the governed execution loop
│   └── orchestrator.py  # governed multi-agent delegation
├── providers/           # anthropic, openai-compatible, ollama, mock
├── policies/
│   ├── default.yaml     # starter policy
│   └── packs/           # development | production | regulated
├── shield.py            # policy packs + enforcement self-check
├── observe.py           # cost, risk, and integrity analytics
├── vault.py             # policy-gated secret leases
├── dashboard.py         # read-only HTTP dashboard (authenticated)
├── security/            # defence-in-depth: auth, OIDC, TLS, headers, injection
├── integrations.py      # guard_tool + LangChain/CrewAI/OpenHands adapters
├── compliance.py        # controls mapped to code and tests
└── cli.py               # run / audit / shield / observe / compliance / dashboard
```

## Security

AXON defends itself in depth. Nine layers, ordered by what an attacker
reaches first: authentication, federated identity, rate limiting, replay
defence, transport encryption, security headers, injection detection,
canary tokens, and self-verification.

```bash
axon token create --name operator --role operator --out tokens.yaml
axon canary honey-db --out canaries.txt
axon posture --tokens tokens.yaml --canaries canaries.txt   # per-layer status
axon scan --file untrusted-page.txt                         # injection check
```

The dashboard **refuses to bind a non-loopback address without an
authenticator**. Tokens are stored as SHA-256 digests and compared in
constant time; the plaintext is shown once and never persisted.

For an organisation that already has an identity provider, the dashboard can
federate instead of holding its own credential store, so deprovisioning
happens in the IdP:

```bash
axon dashboard --ledger axon-audit.jsonl \
  --oidc-issuer https://idp.example.com --oidc-audience axon-dashboard
```

And it can terminate TLS itself, so the transport layer is a control in the
code rather than a note in the deployment guide:

```bash
axon dashboard --ledger axon-audit.jsonl --tokens tokens.yaml \
  --tls-cert /etc/axon/tls.crt --tls-key /etc/axon/tls.key
```

The honest premise, stated up front: no system is unbreakable. The goal is
that a successful intrusion should be expensive, limited in scope, and
detectable — not impossible. `axon posture` says so in its own output.

See [docs/SECURITY-LAYERS.md](docs/SECURITY-LAYERS.md) for what each layer
stops, what it does not stop, and the gaps that remain.

## Status

**v0.2.0** — governed runtime for single and multi-agent systems, with
signed audit, RBAC, policy packs, secret brokering, an authenticated
dashboard, a nine-layer security stack, OIDC federation, in-process TLS,
framework adapters, and an executable compliance mapping. 332 tests.

Known limits, stated plainly: policy matching is glob-based rather than a
full expression language; the OIDC verifier does not call the provider's
introspection endpoint, so a token revoked before its expiry is accepted
until it expires — shorten `exp` if that window matters; the injection
detector matches a known corpus of attack shapes and novel phrasings will
get past it; `EnvResolver` is a local-development secret backend, not a
production one; and the orchestrator executes delegations sequentially, so
it is not yet a throughput play.

On compliance: `axon compliance` maps controls to code and tests, and
`axon compliance --evidence` writes a pack an auditor can sample. Neither is
a SOC 2 report. That is issued by a licensed CPA firm after an engagement
covering the whole organisation, and it cannot be produced by a repository.

See [CHANGELOG.md](CHANGELOG.md) for what shipped and what is next.

## Documentation

- [Full business plan](AXON-PLAN.md)
- [Security layers: what each one stops, and what it does not](docs/SECURITY-LAYERS.md)
- [Financial model](AXON-FINANCIALS.md)
- [Investor pitch + speaker notes](AXON-PITCH.md)
- [Pitch deck (interactive)](pitch/axon-deck.html)

## Contributing

We welcome contributions. See [CONTRIBUTING.md](CONTRIBUTING.md) and
[SECURITY.md](SECURITY.md).

## License

Apache-2.0. Everything in this repository — including Shield, Observe, and
Vault — is covered by that license, with no separate enterprise edition.
Commercial support and deployment assistance are available on request.
