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
python -m pytest -q                     # 128 tests, ~13s
python -m ruff check .                  # lint gate, must be clean
python -m axon.cli --version
python -m axon.cli models               # provider + price table
python -m axon.cli run "task" --provider mock --budget 0.5
python -m axon.cli policy-check tool.read_file --target /home/x/secrets/k
python -m axon.cli audit --ledger ./audit.jsonl
```

## Notes for future sessions

- The preview site is generated: edit `scripts/build_preview.py`, then run
  `python scripts/build_preview.py`. Never hand-edit `preview/*.html`.
- Metrics quoted in docs (`preview/index.html`, README) are measured, not
  estimated. When LOC or the test count changes, re-measure and update them;
  do not let the published numbers drift from the tree.
- `ruff check` is only reproducible because `[tool.ruff.lint] select` is
  explicit in `pyproject.toml`. Do not remove it — a bare config makes the
  enabled rules depend on the installed ruff version.
- The honest evaluation lives in `preview/index.html` (generated from
  `scripts/build_preview.py`). Keep it honest: the repo has real engineering
  strength and no paying customers, and the document must say both.

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
- **This project is published at https://github.com/msy898931-boop/Ram** (public,
  branch `main`). CI is green there across Python 3.10-3.13.
- Publish with `./scripts/push-to-ram.sh`. It scans for secrets, probes write
  access, pushes, then sets description/topics.
- `GITHUB_TOKEN` here is a GitHub **App** token for the `openhands-ai` app,
  installed with `repository_selection: selected`. It can push only to the
  repos ticked in that installation - `Ram` is now included, but `smc-*`,
  `gold-smc-bot` and others are not.
- The app token can push (`contents: write`) but **cannot** create repos or
  edit metadata (`administration: write` is missing), so the description and
  topics calls in the publish script return 403. Set them by hand in the UI,
  or use a classic PAT with `repo` scope.
