# Contributing to AXON

Thanks for helping govern AI agents safely.

## Development setup

```bash
git clone https://github.com/axon-agents/axon
cd axon
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest -q
```

## What we need most

1. **Model adapters** — Anthropic, Gemini, Bedrock, vLLM, Ollama.
2. **Policy backends** — an OPA/Rego evaluator alongside the built-in engine.
3. **Sandbox drivers** — gVisor / Firecracker execution backends.
4. **Observability** — real OpenTelemetry exporter, Grafana dashboards.
5. **Docs** — tutorials, threat-model writeups, compliance mappings.

## Ground rules

- **Tests required.** Every change ships with a test that exercises real code
  paths. We do not mock our own logic.
- **Fail closed.** Any new decision point must default to deny.
- **Audit everything.** New privileged actions must write to the ledger.
- **Small PRs.** One concern per pull request.

## Commit style

Conventional Commits: `feat:`, `fix:`, `docs:`, `test:`, `refactor:`.

## Security

Do not open public issues for vulnerabilities — see [SECURITY.md](SECURITY.md).

## License

By contributing you agree your work is licensed under Apache-2.0.
