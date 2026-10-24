# Changelog

All notable changes to AXON are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
