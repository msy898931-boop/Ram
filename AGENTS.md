# AGENTS.md — repository notes

## What this repo is

**AXON** — an open-core control plane for AI agents: deny-by-default policy,
tamper-evident audit ledger, hard per-run cost caps, model-agnostic runtime.
Dual-licensed, split by file: Apache-2.0 core (`axon/core/`, `axon/security/`,
`axon/providers/`, `axon/cli.py`); BUSL-1.1 commercial modules (`shield.py`,
`observe.py`, `vault.py`, `compliance.py`, `dashboard.py`, `integrations.py`).
`NOTICE` is the authoritative map — read it before touching a license claim.
The core must stay runnable with the commercial files deleted, and
`tests/test_licensing.py` enforces that.

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
python -m pytest -q                     # 374 tests, ~45s
python scripts/check_skips.py           # fails on any silently skipped test
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
| 6 | signing error |
| 7 | identity error |
| 8 | command exists but its BUSL-1.1 commercial module is not installed |

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

## Launch traps found the hard way

- **An env var that nothing reads is a lie in a config file.**
  `docker-compose.yml` set `AXON_LEDGER` while `--ledger` hardcoded
  `./axon-audit.jsonl`, so `docker compose up` wrote the audit trail inside
  the container and threw it away on exit. Any path a container is meant to
  mount must come from `os.getenv`, and the read has to happen at call time:
  argparse builds its defaults inside `main()`, so a module-level constant
  would freeze the value before a test could set it.
- **Ship the license files in every artifact.** The image copied only
  `LICENSE` and so distributed the BUSL-1.1 modules without
  `LICENSE-COMMERCIAL` or `NOTICE`. `tests/test_licensing.py` asserts each is
  named on a `COPY` line.
- **Never advertise an install that does not exist.** `pip install axon-agents`
  is not on PyPI; the honest instruction is the `git clone` + `pip install -e`
  in the README. Release notes are the first thing a visitor checks.
- **`launch.sh` pushed `master`; the default branch is `main`.** A publish
  script that names a branch must be run once against the real repo before
  launch, or it creates the repo and dies on the first push.
- The app token cannot set description, topics, or enable Pages. Do those by
  hand in the UI.

## The first run is the funnel — test it as a subprocess

The most damaging bug found in this repository was not in the security code.
It was that the README quickstart, run literally, ended with
`verify: FAILED — signature stripped or chain rewritten`. A visitor following
the docs step by step was told the product had caught an attack on their own
empty ledger, and left.

Three lessons, all now covered by `tests/test_first_run.py`:

1. **Run the documented commands as a subprocess, in order, as a user would.**
   Importing functions in a test hides the bugs that live in argument
   plumbing, entry points, and file paths. Every README command is now a test.
2. **A flag that creates a file must create the file the docs tell the user to
   read next.** `run --key` created the private key but not `<key>.pub`, so
   `audit --pubkey <key>.pub` crashed. If one half of a key pair is written,
   the other is too.
3. **A missing input file is not a crash, it is a message.** A bare
   `FileNotFoundError` with a stack trace reads as a broken product. Check,
   print what is wrong and how to fix it, exit with a distinct code.

When adding a command, add its documented invocation to `test_first_run.py`
in the same commit. The suite is green either way; the funnel is not.

## The signed-ledger differentiator, and how it was verified

The one claim AXON can make that a competitor cannot copy cheaply is that its
audit ledger is *signed*, not merely hash-chained. Before marketing that, the
claim was checked against the nearest competitor rather than assumed:

- **microsoft/agent-governance-toolkit** (~6.5k stars, MIT, closest match to
  AXON's positioning) implements its audit chain as
  `sha256(json.dumps(body, sort_keys=True))` with `previous_hash` linking —
  an **unkeyed** chain (`agent-mesh/src/agentmesh/governance/audit.py`,
  `compute_hash` / `verify_hash`). `hmac.compare_digest` appears there, but
  that is a timing-safe comparison, not a key: it adds no secret, so anyone
  with write access can edit a record and recompute every hash.
- Their Ed25519 code (`marketplace/signing.py`) signs **plugin manifests**,
  not audit records.
- Their external-anchoring Commitment Engine is documented as
  *"Not implemented in this release."*

So the gap is real. Keep it honest anyway: the README does not name or
disparage the competitor. It tells the reader to run
`examples/signed_ledger_proof.py` against any vendor's ledger, which is a
test they can apply to AXON too. Do not turn this into a hit piece — the
credibility comes from the demo being runnable and the comparison being
fair (the script's own tests assert the unkeyed chain really does accept the
forgery, so it is not a straw man).
