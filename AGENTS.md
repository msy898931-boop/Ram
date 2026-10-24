# AGENTS.md — repository notes

## What this repo is

**AXON** — an open-core control plane for AI agents: deny-by-default policy,
tamper-evident audit ledger, hard per-run cost caps, model-agnostic runtime.
Apache-2.0 core; Shield/Observe/Vault are the commercial layer.

## Layout

| Path | Purpose |
|---|---|
| `axon/core/` | `policy.py` (rule engine), `audit.py` (hash-chained ledger), `budget.py` (cost caps), `runtime.py` (governed loop) |
| `axon/providers/` | `base.py`, `transport.py` (retries + typed errors), `anthropic.py`, `openai.py`, `__init__.py` (registry) |
| `axon/core/providers.py` | Compatibility shim — do not add logic here |
| `axon/cli.py` | `run`, `models`, `audit`, `policy-check`, `export-otel` |
| `tests/` | Provider tests use a **real local HTTP server**, not mocks — keep it that way |
| `pitch/` | Arabic RTL investor deck (`axon-deck.html` + generated `AXON-Deck.pdf`) |
| `data/` | GitHub market research + raw verified dataset |
| `scripts/launch.sh` | Idempotent repo create / push / topics / release |

## Commands

```bash
pip install -e ".[dev]"
python -m pytest -q                     # 28 tests, ~7s
python -m axon.cli --version
python -m axon.cli models               # provider + price table
python -m axon.cli run "task" --provider mock --budget 0.5
python -m axon.cli policy-check tool.read_file --target /home/x/secrets/k
python -m axon.cli audit --ledger ./audit.jsonl
```

## CLI exit codes (contract — tests and CI depend on these)

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | audit chain verification FAILED (tamper detected) |
| 2 | policy denied |
| 3 | policy denied via `policy-check` |
| 4 | provider error |
| 5 | bad input (unknown provider/model) |

## Conventions

- Deny-by-default: an action with no matching allow rule is denied.
- No vendor SDKs — providers speak the wire format over stdlib `urllib`.
  This keeps the package installable in air-gapped environments.
- Price lookup uses longest-prefix match so `gpt-4o-mini` never resolves to `gpt-4o`.
- Provider tests must not use mocks; spin up a real HTTP server instead.
- Regenerating the deck PDF:

```bash
python3 -m http.server 12000 &
chromium --headless --disable-gpu --no-sandbox --no-pdf-header-footer \
  --print-to-pdf=pitch/AXON-Deck.pdf --virtual-time-budget=10000 \
  http://localhost:12000/pitch/axon-deck.html
```

- After editing the deck, verify in a headless browser: 15 sections, zero
  scroll overflow, zero console errors. Both have regressed before.

## Environment notes

- `pip install` of `pytest` / `pyyaml` may be needed after a sandbox reset.
- Live provider calls need `AXON_ANTHROPIC_API_KEY` or `AXON_API_KEY`;
  `mock` and `ollama` work offline.
- `GITHUB_TOKEN` here is a GitHub **App** token: it can push to existing repos
  but **cannot create repositories**. Use `scripts/launch.sh` with a token that
  has `administration: write` (or a classic PAT with `repo`).
