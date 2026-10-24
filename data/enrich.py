#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 msy898931-boop
# Part of the AXON open core. See NOTICE for the license map.
import json
import subprocess
import sys
from datetime import datetime, timezone

REPOS = ["deepseek-ai/deepseek-harness", "storytold/photocraft", "bilawalsidhu/gods-eye-view", "boykopovar/AnyPS5", "JustVugg/colibri", "NandhaKishorM/laya", "anywhere-labs/dsh-desktop", "Niko1221/Strata", "xai-org/grok-build", "guillaumemeyer/watermarks-remover", "hypit-ai/hypit", "browser-use/jev-ultrafast", "firecrawl/anydoc", "lexmount/moli", "andrewyng/openworker", "img2threejs/img2threejs", "robbietilton/Compositor", "yetone/magpie", "langchain-ai/openwiki", "yc-software/qm", "KKKKhazix/AIHOT", "KnifeLemon/Filee", "NousResearch/hermes-agent", "Panniantong/Agent-Reach", "career-ops-hq/career-ops", "ZhuLinsen/daily_stock_analysis", "hugohe3/ppt-master", "HKUDS/nanobot", "zhayujie/CowAgent", "codewhale-hq/Codewhale", "can1357/oh-my-pi", "HKUDS/Vibe-Trading", "esengine/DeepSeek-Reasonix", "agentscope-ai/QwenPaw", "Twigpine/openclaude", "iOfficeAI/AionUi", "feder-cr/invisible_dots", "googleworkspace/cli", "jackwener/OpenCLI", "TencentCloud/TencentDB-Agent-Memory", "titanwings/distilly", "JCodesMore/ai-website-cloner-template", "wasp-lang/open-saas", "OpenByteInc/QuantDinger", "polarsource/polar", "Jakeschincariol/replica-skill", "HeyPuter/everything", "every-app/open-seo", "coreyhaines31/marketingskills", "AgriciDaniel/claude-seo", "yaojingang/GEOFlow", "genspark-ai/genoffice", "yi1108/printfilm", "SenteLabsAI/OpenExecutive", "LosaLosSantos/aurelio-finance", "melgarafael/DeskcommCRM", "alam00000/bentopdf", "rmyndharis/OpenWA", "oblien/openship", "liketrek/TREK", "DuarteSantos8/openGym", "jub0t/Concat", "lightningpixel/modly", "dograh-hq/dograh", "oomol-lab/open-connector", "talivia-group/talivia", "langgenius/dify", "n8n-io/n8n"]

now = datetime.now(timezone.utc)
out = []
for full in REPOS:
    try:
        raw = subprocess.run(["gh","api",f"repos/{full}"],capture_output=True,text=True,timeout=30)
        if raw.returncode != 0:
            print("MISS", full, raw.stderr.strip()[:80], file=sys.stderr)
            continue
        d = json.loads(raw.stdout)
    except Exception as e:
        print("ERR", full, e, file=sys.stderr)
        continue
    created = datetime.fromisoformat(d["created_at"].replace("Z","+00:00"))
    age = max((now-created).days, 1)
    stars = d["stargazers_count"]
    lic = (d.get("license") or {}).get("spdx_id") or "None"
    out.append({
        "repo": full,
        "stars": stars,
        "age_days": age,
        "stars_per_day": round(stars/age, 1),
        "forks": d["forks_count"],
        "issues": d["open_issues_count"],
        "lang": d.get("language"),
        "license": lic,
        "homepage": d.get("homepage") or "",
        "topics": d.get("topics") or [],
        "created": d["created_at"][:10],
        "pushed": d["pushed_at"][:10],
        "desc": (d.get("description") or "")[:150],
        "archived": d.get("archived"),
    })

out.sort(key=lambda x: -x["stars_per_day"])
with open("/workspace/project/data/enriched.json","w") as fh:
    json.dump(out, fh, indent=1)
print(f"{'repo':45} {'stars':>7} {'age':>5} {'st/day':>7} {'forks':>6} {'lic':12} home")
for r in out:
    print(f"{r['repo']:45} {r['stars']:>7} {r['age_days']:>5} {r['stars_per_day']:>7} {r['forks']:>6} {r['license']:12} {'Y' if r['homepage'] else '-'}")
