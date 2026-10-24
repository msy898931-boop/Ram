# Changelog

All notable changes to AXON are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Signed audit ledger.** Optional Ed25519 signatures over each record hash,
  implemented in pure Python (RFC 8032) and verified against the RFC test
  vectors plus cross-checks against `cryptography`. `AuditLedger.verify()`
  gains a fail-closed mode: when the auditor supplies a public key, every
  record must carry a valid signature from it. New CLI: `axon keygen`,
  `axon audit --pubkey`.
- **RBAC.** Principals with roles, accountable owners, and tags
  (`axon/core/identity.py`, `axon/policies/identities.yaml`). Role tags feed
  the policy `requires:` mechanism, so a role can unlock a conditional allow
  but can never override a deny. Identity metadata is attached to every audit
  record. New CLI: `axon identities`.
- **Multi-agent orchestrator** (`axon/core/orchestrator.py`). Delegation is
  itself a deny-by-default policy action; children share the parent's
  `Budget` so a cost cap cannot be reset by spawning; depth and fan-out are
  bounded; every hop lands in one verifiable ledger. Strategies: `sequential`,
  `fan_out`, `nested`.
- **Shield policy packs** (`development`, `production`, `regulated`) that each
  declare probes describing what they should refuse, plus `Shield.check()` to
  test enforcement rather than assert it. New CLI: `axon shield [pack]`.
- **Observe analytics** (`axon/observe.py`): cost by agent and model, denials
  by actor and action, integrity status, run grouping. New CLI: `axon observe`.
- **Vault** (`axon/vault.py`): secrets brokered as short-lived, single-use,
  policy-gated leases. Values never reach the ledger, and issued values can be
  redacted out of model output. `AgentRuntime.read_secret()` routes through the
  same policy engine as every other action.
- **Dashboard** (`axon/dashboard.py` + `axon/static/dashboard.html`): a
  read-only stdlib HTTP server and single-page UI over a real ledger, with a
  live Shield check and a "why was this allowed or denied" explainer. New CLI:
  `axon dashboard`.
- **Framework integrations** (`axon/integrations.py`): a dependency-free
  `guard_tool` decorator plus LangChain, CrewAI, and OpenHands adapters. All
  refusals raise the same `PolicyDenied` type.
- **Compliance mapping** (`axon/compliance.py`): 11 controls across SOC 2,
  ISO/IEC 27001, and ISO/IEC 42001, each citing the code that implements it,
  the ledger evidence it produces, and the tests that prove it. New CLI:
  `axon compliance [--run]`.

### Fixed
- **Signature stripping was undetectable.** A hash chain alone lets whoever
  holds the ledger file delete every signature and re-hash the chain into a
  state that verified cleanly. Verification is now fail-closed when a public
  key is supplied. Reproduced and covered by `tests/test_signing.py`.
- **`PolicyEngine.allow_all()` removed.** It read as a legitimate policy
  choice while granting every action. Replaced by `permissive()`, which is
  named for what it does and documented as dev/test only, and `bootstrap()`,
  which denies tools by default.
- Audit records could be written without identity metadata, leaving the last
  record of a run unattributed. Metadata is now injected uniformly.

### Changed
- Test suite grew from 28 to 127 tests.
- `README.md` updated to describe the shipped surface, with known limits
  stated explicitly.

## [0.2.0] — 2026-10-20

### Added
- **Real model providers.** Native Anthropic Messages API adapter and a
  hardened OpenAI-compatible adapter (OpenAI, Azure, Groq, Together, Ollama,
  vLLM). Both speak the vendor wire format over stdlib HTTP — no SDK
  dependency, installable in air-gapped environments.
- **Provider registry** with name resolution, auto-detection from the
  environment, and `axon models` to list providers and prices.
- **Bounded retries with exponential backoff and jitter**, honouring
  `Retry-After`. Auth and 4xx errors are never retried.
- **Typed provider errors**: `AuthError`, `RateLimitError`, `TransientError`,
  with clean CLI exit codes (2 = blocked, 4 = provider error, 5 = bad input).
- **Extended price table** across Anthropic, OpenAI, Gemini, Qwen, DeepSeek and
  local models, with longest-prefix matching so `gpt-4o-mini` never resolves to
  `gpt-4o`.
- `examples/real_provider.py` — governed run against a live provider.
- `.env.example`, CI workflow (Python 3.10–3.13 + wheel smoke test), issue and
  PR templates, Code of Conduct.

### Changed
- `axon run` gains `--provider` and resolves the default model per provider.
- `axon.core.providers` is now a compatibility shim; the implementation lives
  in the `axon.providers` package.
- Test suite grew from 12 to 28 tests. Provider tests run against a real local
  HTTP server rather than mocks, covering parsing, retries, and error mapping.

## [0.1.0] — 2026-10-20

### Added
- Initial release: governed agent runtime, deny-by-default policy engine,
  tamper-evident hash-chained audit ledger, hard per-run cost caps.
- CLI: `run`, `audit`, `policy-check`, `export-otel`.
- Apache-2.0 licence, README, SECURITY, CONTRIBUTING, Dockerfile.

[Unreleased]: https://github.com/msy898931-boop/Ram/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/msy898931-boop/Ram/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/msy898931-boop/Ram/releases/tag/v0.1.0
