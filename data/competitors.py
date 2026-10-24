#!/usr/bin/env python3
"""Competitive intelligence on AI agent harness / coding agent platforms."""
import json
import subprocess
import sys
from datetime import datetime, timezone

COMPETITORS = ["anthropics/claude-code", "openai/codex", "microsoft/vscode-copilot-chat", "OpenHands/OpenHands", "paul-gauthier/aider", "cline/cline", "continuedev/continue", "block/goose", "google-gemini/gemini-cli", "QwenLM/qwen-code", "deepseek-ai/deepseek-harness", "xai-org/grok-build", "sourcegraph/cody", "anomalyco/opencode", "getAsterisk/claudia", "RooCodeInc/Roo-Code", "kilo-org/kilocode", "charmbracelet/crush", "agentclientprotocol/agent-client-protocol", "modelcontextprotocol/servers", "langchain-ai/langgraph", "crewAIInc/crewAI", "microsoft/autogen", "openai/swarm", "geekan/MetaGPT", "Significant-Gravitas/AutoGPT", "n8n-io/n8n", "langgenius/dify", "activepieces/activepieces", "nomic-ai/gpt4all", "ollama/ollama", "vllm-project/vllm"]

now = datetime.now(timezone.utc)
rows = []
for full in COMPETITORS:
    r = subprocess.run(["gh","api",f"repos/{full}"],capture_output=True,text=True)
    if r.returncode != 0:
        print("MISS", full, r.stderr.strip()[:60], file=sys.stderr)
        continue
    d = json.loads(r.stdout)
    created = datetime.fromisoformat(d["created_at"].replace("Z","+00:00"))
    age = max((now-created).days,1)
    rows.append({
        "repo": full, "stars": d["stargazers_count"], "age": age,
        "spd": round(d["stargazers_count"]/age,1),
        "forks": d["forks_count"], "issues": d["open_issues_count"],
        "lang": d.get("language"), "lic": (d.get("license") or {}).get("spdx_id") or "None",
        "home": d.get("homepage") or "", "created": d["created_at"][:10],
        "pushed": d["pushed_at"][:10], "org": d["owner"]["login"],
        "desc": (d.get("description") or "")[:110],
    })
rows.sort(key=lambda x:-x["stars"])
with open("/workspace/project/data/competitors.json","w") as fh:
    json.dump(rows, fh, indent=1)
print(f"{'repo':44}{'stars':>8}{'age':>6}{'st/d':>7}{'forks':>7}{'issues':>7}  {'lic':13} lang")
for r in rows:
    print(f"{r['repo']:44}{r['stars']:>8}{r['age']:>6}{r['spd']:>7}{r['forks']:>7}{r['issues']:>7}  {r['lic']:13} {r['lang']}")
