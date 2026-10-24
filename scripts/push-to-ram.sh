#!/usr/bin/env bash
# Publish AXON to msy898931-boop/Ram
#
# Why this is a script and not already done:
#   The GitHub App installed on this workspace is scoped to a *selected* set of
#   repositories. `Ram` is not in that set, so every write is rejected with
#   "Resource not accessible by integration" (403) even though the REST API
#   reports admin:true. Pushes to `asp` succeed, which confirms the scope is
#   the only problem.
#
# Fix it one of two ways, then run this script.
#
#   Option A (recommended) - grant the app access:
#     1. https://github.com/apps/openhands-ai/installations/new
#     2. Choose the msy898931-boop account
#     3. Select "Only select repositories" -> tick `Ram` (or pick "All")
#     4. Save. Re-run this script.
#
#   Option B - use your own classic token (repo scope):
#     GITHUB_TOKEN=<your_pat> ./scripts/push-to-ram.sh
#
set -uo pipefail

REPO="${REPO:-msy898931-boop/Ram}"
BRANCH="${BRANCH:-main}"
TOKEN="${GITHUB_TOKEN:?GITHUB_TOKEN is not set}"

cd "$(dirname "$0")/.."

echo "==> target: $REPO (branch: $BRANCH)"

# 1. Refuse to publish if anything looks like a live credential.
echo "==> scanning for secrets"
if git grep -nE "sk-ant-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9]{30,}|gh[pous]_[A-Za-z0-9]{30,}|AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY" -- . >/dev/null 2>&1; then
  echo "!! aborting: possible credential committed" >&2
  exit 1
fi
echo "    clean"

# 2. Probe write access before doing anything.
echo "==> checking push permission"
if ! git push --dry-run "https://x-access-token:${TOKEN}@github.com/${REPO}.git" \
     "HEAD:refs/heads/${BRANCH}" >/dev/null 2>&1; then
  cat >&2 <<'MSG'

!! push denied.
   The token cannot write to this repository. See the header of this script
   for the two ways to fix it (grant the app access, or use your own PAT).
MSG
  exit 1
fi
echo "    ok"

# 3. Push.
echo "==> pushing"
git push "https://x-access-token:${TOKEN}@github.com/${REPO}.git" "HEAD:refs/heads/${BRANCH}"

# 4. Describe the repo.
echo "==> setting description and topics"
curl -sS -X PATCH \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Accept: application/vnd.github+json" \
  "https://api.github.com/repos/${REPO}" \
  -d '{"description":"AXON — enterprise control plane for AI agents: deny-by-default policy, tamper-evident audit ledger, hard cost caps, model-agnostic runtime.","homepage":"https://github.com/msy898931-boop/Ram"}' \
  -o /dev/null -w "    description: HTTP %{http_code}\n"

curl -sS -X PUT \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Accept: application/vnd.github+json" \
  "https://api.github.com/repos/${REPO}/topics" \
  -d '{"names":["ai-agents","ai-governance","audit-log","policy-engine","llm","agent-runtime","cost-control","open-core","python"]}' \
  -o /dev/null -w "    topics: HTTP %{http_code}\n"

echo
echo "Done -> https://github.com/${REPO}"
