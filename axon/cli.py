"""AXON CLI — govern, run, and audit agents from the terminal."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .core.audit import AuditLedger
from .core.budget import Budget, BudgetExceeded
from .core.policy import PolicyEngine
from .core.providers import default_provider
from .core.runtime import AgentRuntime, PolicyDenied

DEFAULT_POLICY = Path(__file__).resolve().parent / "policies" / "default.yaml"


def _runtime(args) -> AgentRuntime:
    ledger = AuditLedger(args.ledger)
    policy = PolicyEngine.from_yaml(args.policy or DEFAULT_POLICY)
    return AgentRuntime(
        agent_id=args.agent,
        ledger=ledger,
        policy=policy,
        budget=Budget(limit_usd=args.budget),
        provider=default_provider(),
    )


def cmd_run(args) -> int:
    rt = _runtime(args)
    tools = {}
    for spec in args.tool or []:
        name, _, target = spec.partition("=")
        tools[name] = (target or f"/sandbox/{name}", lambda: f"<stub output for {name}>")
    try:
        res = rt.run(args.task, model=args.model, tools=tools)
    except (PolicyDenied, BudgetExceeded) as exc:
        print(f"blocked: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({
        "run_id": res.run_id,
        "outputs": res.outputs,
        "tools": [{"name": t.name, "allowed": t.allowed, "output": t.output} for t in res.tool_results],
        "cost_usd": round(res.cost_usd, 6),
        "denied": res.denied,
    }, indent=2))
    return 0


def cmd_audit(args) -> int:
    ledger = AuditLedger(args.ledger)
    ok, msg = ledger.verify()
    print(f"verify: {'OK' if ok else 'FAILED'} — {msg}")
    for rec in ledger.records():
        print(f"#{rec.seq:<4} {rec.decision:<6} {rec.actor:<16} {rec.action:<22} {rec.target[:40]}")
    return 0 if ok else 1


def cmd_export_otel(args) -> int:
    ledger = AuditLedger(args.ledger)
    print(json.dumps(ledger.to_otel_spans(), indent=2))
    return 0


def cmd_policy_check(args) -> int:
    engine = PolicyEngine.from_yaml(args.policy or DEFAULT_POLICY)
    tags = set(args.tag or [])
    d = engine.evaluate(args.actor, args.action, args.target, tags)
    print(f"{'ALLOW' if d.allowed else 'DENY '}  {d.reason}")
    return 0 if d.allowed else 3


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="axon", description="Enterprise control plane for AI agents")
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="run a governed agent task")
    r.add_argument("task")
    r.add_argument("--agent", default="agent-1")
    r.add_argument("--model", default="mock")
    r.add_argument("--budget", type=float, default=1.0)
    r.add_argument("--ledger", default="./axon-audit.jsonl")
    r.add_argument("--policy", default=None)
    r.add_argument("--tool", action="append", help="name=target (repeatable)")
    r.set_defaults(func=cmd_run)

    a = sub.add_parser("audit", help="verify and print the audit ledger")
    a.add_argument("--ledger", default="./axon-audit.jsonl")
    a.set_defaults(func=cmd_audit)

    o = sub.add_parser("export-otel", help="export the ledger as OpenTelemetry spans")
    o.add_argument("--ledger", default="./axon-audit.jsonl")
    o.set_defaults(func=cmd_export_otel)

    c = sub.add_parser("policy-check", help="test a single policy decision")
    c.add_argument("action")
    c.add_argument("--actor", default="agent-1")
    c.add_argument("--target", default="")
    c.add_argument("--tag", action="append")
    c.add_argument("--policy", default=None)
    c.set_defaults(func=cmd_policy_check)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
