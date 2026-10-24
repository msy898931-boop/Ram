"""Run a governed agent against a REAL model provider.

Setup (pick one):
    export AXON_ANTHROPIC_API_KEY=sk-ant-...      # Anthropic
    export AXON_API_KEY=sk-...                    # OpenAI
    export AXON_BASE_URL=http://localhost:11434/v1 # Ollama / vLLM (no key)

Run:
    python3 examples/real_provider.py
"""

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from axon.core.audit import AuditLedger
from axon.core.budget import Budget
from axon.core.policy import PolicyEngine
from axon.core.runtime import AgentRuntime
from axon.providers import ProviderError, default_provider

POLICY = Path(__file__).resolve().parent.parent / "axon" / "policies" / "default.yaml"


def main():
    provider = default_provider()
    print(f"provider: {provider.name}")

    if provider.name == "mock":
        print("No API key found. Set one to run against a real model:")
        print("  export AXON_ANTHROPIC_API_KEY=sk-ant-...")
        print("  export AXON_API_KEY=sk-...")
        return 1

    runtime = AgentRuntime(
        agent_id="analyst",
        ledger=AuditLedger(Path(tempfile.mkdtemp()) / "audit.jsonl"),
        policy=PolicyEngine.from_yaml(POLICY),
        budget=Budget(limit_usd=0.25),
        provider=provider,
    )

    try:
        result = runtime.run(
            "In one sentence, what does a deny-by-default policy engine do?",
            model="claude-sonnet" if provider.name == "anthropic" else "gpt-4o-mini",
            tools={"read_file": ("/sandbox/notes.txt", lambda: "notes: ship the MVP")},
        )
    except ProviderError as exc:
        print(f"provider failed ({type(exc).__name__}): {exc}")
        return 4

    print(f"\nanswer:\n  {result.outputs[-1]}\n")
    print(f"cost:   ${result.cost_usd:.6f}")
    print(f"denied: {result.denied}")
    ok, msg = runtime.ledger.verify()
    print(f"audit:  {'OK' if ok else 'FAILED'} — {msg}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
