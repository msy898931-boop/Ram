# Contributing to AXON

Thanks for helping govern AI agents safely.

## Development setup

```bash
git clone https://github.com/msy898931-boop/Ram
cd axon
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest -q
```

No API keys are needed: tests run against the deterministic `mock` provider
and a real local HTTP server, so the full transport is exercised offline.

## What we need most

1. **Model adapters** — Gemini, Bedrock, Mistral, Groq, vLLM tuning.
2. **Policy backends** — an OPA/Rego evaluator alongside the built-in engine.
3. **Sandbox drivers** — gVisor / Firecracker execution backends.
4. **Observability** — real OpenTelemetry exporter, Grafana dashboards.
5. **Docs** — tutorials, threat-model writeups, compliance mappings.

## Ground rules

- **Tests required.** Every change ships with a test that exercises real code
  paths. We do not mock our own logic — provider tests run against a real
  local HTTP server.
- **Fail closed.** Any new decision point must default to deny.
- **Audit everything.** New privileged actions must write to the ledger.
- **Small PRs.** One concern per pull request.

## Adding a provider

1. Add `axon/providers/<name>.py` implementing `complete(prompt, model, **kw)`.
2. Reuse `axon.providers.transport.post_json` for retries and typed errors.
3. Register it in `axon/providers/__init__.py` (`_PROVIDERS`).
4. Add prices to `PRICES` in `axon/providers/base.py`.
5. Add tests in `tests/test_providers.py` using the local HTTP fixture.

## Commit style

Conventional Commits: `feat:`, `fix:`, `docs:`, `test:`, `refactor:`.

## Security

Do not open public issues for vulnerabilities — see [SECURITY.md](SECURITY.md).

## License

By contributing you agree your work is licensed under Apache-2.0.
