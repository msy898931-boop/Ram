#!/usr/bin/env bash
# AXON open-source launch — idempotent, safe to re-run.
#
# Creates the public repo (if absent), pushes, sets topics, and cuts the
# release. Requires a token with repo-creation permission (classic PAT with
# `repo` scope, or a GitHub App granted administration: write).
#
#   OWNER=my-org ./scripts/launch.sh
set -euo pipefail

OWNER="${OWNER:-$(gh api user --jq .login)}"
REPO="${REPO:-axon}"
SLUG="$OWNER/$REPO"
VERSION="$(python3 -c 'import axon; print(axon.__version__)' 2>/dev/null || echo 0.2.0)"
TAG="v$VERSION"

DESC="AXON — enterprise control plane for AI agents: deny-by-default policy, tamper-evident audit ledger, hard cost caps, and a model-agnostic runtime (Anthropic, OpenAI, Ollama)."
TOPICS=(ai-agents ai-governance llm-security audit-log policy-engine agent-runtime observability cost-control compliance python anthropic openai)

echo "==> target: $SLUG ($TAG)"

if gh api "repos/$SLUG" >/dev/null 2>&1; then
  echo "==> repo exists, reusing"
else
  echo "==> creating public repo"
  gh repo create "$SLUG" --public --description "$DESC"
fi

BRANCH="${BRANCH:-main}"

echo "==> pushing $BRANCH"
git remote remove origin 2>/dev/null || true
git remote add origin "https://github.com/$SLUG.git"
git push -u origin "$BRANCH"

echo "==> setting topics"
for t in "${TOPICS[@]}"; do gh api --method PUT "repos/$SLUG/topics" -f "names[]=$t" >/dev/null; done
gh api "repos/$SLUG/topics" --jq '.names | join(", ")'

echo "==> enabling features"
gh api --method PATCH "repos/$SLUG" \
  -F has_wiki=false -F has_projects=false -F has_discussions=true \
  -F allow_squash_merge=true -F allow_merge_commit=false -F allow_rebase_merge=true \
  -F delete_branch_on_merge=true >/dev/null

echo "==> release $TAG"
if gh release view "$TAG" --repo "$SLUG" >/dev/null 2>&1; then
  echo "==> release already exists"
else
  gh release create "$TAG" --repo "$SLUG" --title "AXON $TAG" --generate-notes
fi

echo "==> done: https://github.com/$SLUG"
