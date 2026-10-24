# AGENTS.md — repository notes

## What this repo is

**AXON** — an open-core control plane for AI agents: deny-by-default policy,
tamper-evident audit ledger, hard per-run cost caps, model-agnostic runtime.
Apache-2.0 core; Shield/Observe/Vault are the commercial layer.

## Layout

| Path | Purpose |
|---|---|
| `axon/core/` | `policy.py` (rule engine), `audit.py` (hash-chained ledger), `budget.py` (cost caps), `runtime.py` (governed loop) |
| `axon/security/` | `auth.py` (tokens, rate limit, replay), `oidc.py` (JWT/JWKS verification, key rotation), `tls.py` (in-process TLS, cert/key pair check), `injection.py` (prompt-injection scan), `canary.py` (exfiltration tripwires), `headers.py` (HTTP headers + `Posture`) |
| `axon/providers/` | `base.py`, `transport.py` (retries + typed errors), `anthropic.py`, `openai.py`, `__init__.py` (registry) |
| `axon/core/providers.py` | Compatibility shim — do not add logic here |
| `axon/cli.py` | `run`, `models`, `audit`, `policy-check`, `export-otel`, `token`, `canary`, `posture`, `scan`, `compliance`, `dashboard` |
| `docs/SECURITY-LAYERS.md` | What each security layer stops, and what it does not |
| `tests/` | Provider tests use a **real local HTTP server**, not mocks — keep it that way. Security tests attack a real server on an ephemeral port |
| `pitch/` | Arabic RTL investor deck (`axon-deck.html` + generated `AXON-Deck.pdf`) |
| `data/` | GitHub market research + raw verified dataset |
| `scripts/launch.sh` | Idempotent repo create / push / topics / release |

## Commands

```bash
pip install -e ".[dev]"
python -m pytest -q                     # 348 tests, ~38s
python -m pytest tests/test_security_*.py -q   # 197 adversarial security tests
python -m ruff check .                  # lint gate, must be clean
python -m axon.cli --version
python -m axon.cli models               # provider + price table
python -m axon.cli run "task" --provider mock --budget 0.5
python -m axon.cli policy-check tool.read_file --target /home/x/secrets/k
python -m axon.cli audit --ledger ./audit.jsonl
python -m axon.cli token create --name operator --out tokens.yaml
python -m axon.cli posture --tokens tokens.yaml --canaries canaries.txt
python -m axon.cli scan --file untrusted.txt
```

## Security invariants (do not weaken these)

- The dashboard **refuses** a non-loopback bind without an authenticator. Do
  not turn that into a warning; a warning does not stop the breach. An OIDC
  verifier counts as an authenticator; that is deliberate, so federation is
  not blocked by the check.
- The OIDC verifier must never accept `alg: none`, must never let the token's
  own header choose the verification key family (algorithm confusion), and
  must never use a key marked `use: enc` for signature. Each of those has a
  test that would fail loudly.
- JWKS refetch is rate-limited (`_MIN_REFETCH_INTERVAL`). Removing the limit
  turns unknown-`kid` tokens into a denial-of-service against the provider.
- `verify_pair` must compare the certificate and key, and record the full
  256-bit fingerprint. A truncated fingerprint is not an identity.
- `/healthz` is the only unauthenticated route. Do not add another.
- Tokens are stored as digests, never plaintext. Never write a token value to
  a file, a log, or the ledger.
- Canary values never reach the ledger. Only the fingerprint and a redacted
  context are recorded, so the evidence cannot become a second leak.
- Response headers must be written **before** `end_headers()`. Writing them
  after silently drops them — this bug shipped once and was caught by
  `test_security_dashboard.py`.
- Error responses must not echo exception text; it names internal paths.
- `axon posture` must keep saying that 100/100 means "every control is on",
  not "unbreakable". Do not let the honesty get optimised away.
- The injection detector's accuracy is asserted by tests
  (`test_security_injection.py`): every attack denied, no benign document
  denied. A detector that denies everything is useless, so the
  false-positive test matters as much as the attack test.
- Published figures are the ones that go stale, because nothing re-checks
  them. Two shipped wrong: the detector was advertised as "16/16 attacks,
  0/15 benign" long after the corpus reached 20 and 18, and a pricing claim
  said "$19/mo" where the page said $0.02 per browser hour. Both flattered the
  project. If a number appears in prose, either derive it or guard it.

## Notes for future sessions

- The preview site is generated: edit `scripts/build_preview.py`, then run
  `python scripts/build_preview.py`. Never hand-edit `preview/*.html`.
- Metrics quoted in docs (`preview/index.html`, README) are measured, not
  estimated. `build_preview.py` now measures them at build time (LOC, collected
  test counts, detector accuracy), so the site cannot drift on its own. Numbers
  that are still hand-written in Markdown (`docs/`, `README.md`, this file) are
  snapshots — update them when the tree changes. `tests/test_preview_consistency.py`
  fails if the published page or the market report disagrees with its source.
- `data/REPORT.md`'s growth table is generated from
  `data/github-verified-2026-10-20.json`. Regenerate the JSON by re-querying
  the API, then rebuild the table; never edit a row by hand. The guard test
  compares the quoted star count against the snapshot.
- Repos get renamed. `sst/opencode` → `anomalyco/opencode` and
  `All-Hands-AI/OpenHands` → `OpenHands/OpenHands` both 301 now. Follow
  redirects (`curl -L`) when verifying, and store the canonical name.
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
- The app token also **cannot** enable GitHub Pages (`pages: write` is
  missing), so `POST /repos/:owner/:repo/pages` returns 403. The live site is
  served from the sandbox runtime host instead:
  `https://work-1-crlbmrzuyhaloibb.prod-runtime.all-hands.dev/`. Pages must be
  requested **with** the `.html` suffix; the bare path 404s, and only `/` and
  `AXON-Deck.pdf` resolve without it.
