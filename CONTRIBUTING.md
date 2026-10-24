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

This repository is dual-licensed. Which license applies to your contribution
depends on the file you are changing — see [NOTICE](NOTICE) for the map:

- Files in the **open core** are Apache-2.0. Contributions to them are
  accepted under Apache-2.0.
- Files in the **commercial modules** (`axon/shield.py`, `observe.py`,
  `vault.py`, `compliance.py`, `dashboard.py`, `integrations.py`) are
  BUSL-1.1. Contributions to them are accepted under BUSL-1.1, plus the
  inbound grant below.

### Inbound license grant (required for commercial-module changes)

By submitting a contribution to any file covered by BUSL-1.1, you grant the
Licensor a perpetual, worldwide, non-exclusive, royalty-free, irrevocable
license to reproduce, prepare derivative works of, publicly display, publicly
perform, sublicense, and distribute your contribution and such derivative
works, and to license the contribution under any license terms the Licensor
chooses, including a paid commercial license.

This grant is what makes dual licensing possible. Without it the Licensor
cannot sell a commercial license covering a file that contains your code, and
the file would have to be reverted instead. It does not take away your own
rights to use your contribution.

If you are contributing on behalf of an employer, confirm you have permission
to make the grant. If you cannot, contribute to the open core instead — that
half needs no such grant.
