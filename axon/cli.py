"""AXON CLI — govern, run, and audit agents from the terminal."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .core.audit import AuditLedger
from .core.budget import Budget, BudgetExceeded
from .core.identity import IdentityError, IdentityRegistry
from .core.policy import PolicyEngine
from .core.runtime import AgentRuntime, PolicyDenied
from .core.signing import SignatureError, Signer, signer_from_file
from .providers import ProviderError, available_providers, default_provider, get_provider

DEFAULT_POLICY = Path(__file__).resolve().parent / "policies" / "default.yaml"
DEFAULT_IDENTITIES = Path(__file__).resolve().parent / "policies" / "identities.yaml"
DEFAULT_KEY = Path("./axon-signing.key")


def _registry(args) -> IdentityRegistry | None:
    """Load the identity registry. `--no-rbac` opts out for local dev."""
    if getattr(args, "no_rbac", False):
        return None
    path = getattr(args, "identities", None)
    if path:
        return IdentityRegistry.from_yaml(path)
    return IdentityRegistry.from_yaml(DEFAULT_IDENTITIES)


def _signer(args, *, create: bool) -> Signer | None:
    """Resolve the signing key. Returns None when signing is not requested."""
    key_path = getattr(args, "key", None)
    if not key_path:
        return None
    path = Path(key_path)
    if not path.exists() and not create:
        raise SignatureError(f"signing key {path} not found")
    return signer_from_file(path)


def _ledger(args, *, create: bool = False) -> AuditLedger:
    return AuditLedger(args.ledger, signer=_signer(args, create=create))


def _runtime(args) -> AgentRuntime:
    ledger = _ledger(args, create=True)
    policy = PolicyEngine.from_yaml(args.policy or DEFAULT_POLICY)
    provider = get_provider(args.provider) if args.provider else default_provider()
    return AgentRuntime(
        agent_id=args.agent,
        ledger=ledger,
        policy=policy,
        budget=Budget(limit_usd=args.budget),
        provider=provider,
        registry=_registry(args),
    )


def cmd_run(args) -> int:
    rt = _runtime(args)
    tools = {}
    for spec in args.tool or []:
        name, _, target = spec.partition("=")
        tools[name] = (
            target or f"/sandbox/{name}",
            lambda name=name: f"<stub output for {name}>",
        )
    model = args.model or ("mock" if rt.provider.name == "mock" else _default_model(rt.provider.name))
    try:
        res = rt.run(args.task, model=model, tools=tools)
    except (PolicyDenied, BudgetExceeded) as exc:
        print(f"blocked: {exc}", file=sys.stderr)
        return 2
    except ProviderError as exc:
        print(f"provider error ({type(exc).__name__}): {exc}", file=sys.stderr)
        return 4
    print(json.dumps({
        "run_id": res.run_id,
        "provider": rt.provider.name,
        "model": model,
        "outputs": res.outputs,
        "tools": [{"name": t.name, "allowed": t.allowed, "output": t.output} for t in res.tool_results],
        "cost_usd": round(res.cost_usd, 6),
        "denied": res.denied,
    }, indent=2, ensure_ascii=False))
    return 0


def _default_model(provider_name: str) -> str:
    from .providers.anthropic import DEFAULT_MODEL as ANTHROPIC_MODEL
    from .providers.openai import DEFAULT_MODEL as OPENAI_MODEL

    return {"anthropic": ANTHROPIC_MODEL}.get(provider_name, OPENAI_MODEL)


def cmd_models(args) -> int:
    from .providers.base import PRICES

    print(f"providers: {', '.join(available_providers())}\n")
    print(f"{'model':<22}{'input $/1M':>12}{'output $/1M':>13}")
    print("-" * 47)
    for model, (inp, out) in sorted(PRICES.items(), key=lambda kv: kv[1][0]):
        print(f"{model:<22}{inp:>12.2f}{out:>13.2f}")
    return 0


def cmd_audit(args) -> int:
    ledger = _ledger(args)
    pub = None
    if getattr(args, "pubkey", None):
        pub = Path(args.pubkey).read_bytes()
        pub = bytes.fromhex(pub.decode().strip()) if len(pub.strip()) == 64 else pub
    ok, msg = ledger.verify(public_key=pub)
    print(f"verify: {'OK' if ok else 'FAILED'} — {msg}")
    for rec in ledger.records():
        mark = "S" if rec.signature else "-"
        print(f"#{rec.seq:<4} {mark} {rec.decision:<6} {rec.actor:<16} {rec.action:<22} {rec.target[:40]}")
    return 0 if ok else 1


def cmd_keygen(args) -> int:
    path = Path(args.key)
    if path.exists() and not args.force:
        print(f"error: {path} already exists (use --force to overwrite)", file=sys.stderr)
        return 5
    signer = signer_from_file(path)
    pub_path = Path(args.pubkey or str(path) + ".pub")
    pub_path.write_text(signer.public_key.hex() + "\n", encoding="utf-8")
    print(f"private key : {path}  (keep secret, 0600)")
    print(f"public key  : {pub_path}")
    print(f"fingerprint : {signer.fingerprint}")
    print("\nGive the public key to your auditor. They run:")
    print(f"  axon audit --ledger <ledger> --pubkey {pub_path}")
    return 0


def cmd_identities(args) -> int:
    reg = _registry(args)
    if reg is None:
        print("RBAC disabled (--no-rbac)")
        return 0
    roles = reg.roles()
    print("roles:")
    for role, tags in sorted(roles.items()):
        print(f"  {role:<12} tags: {', '.join(sorted(tags)) or '(none)'}")
    print("\nidentities:")
    print(f"  {'name':<16}{'role':<12}{'owner':<26}tags")
    print("  " + "-" * 68)
    for name in reg.known():
        try:
            ident = reg.get(name)
        except IdentityError:
            print(f"  {name:<16}{'(disabled)':<12}")
            continue
        print(f"  {ident.name:<16}{ident.role:<12}{ident.owner or '-':<26}"
              f"{', '.join(sorted(ident.tags)) or '(none)'}")
    return 0


def cmd_dashboard(args) -> int:
    from .dashboard import serve

    pub = None
    if getattr(args, "pubkey", None):
        raw = Path(args.pubkey).read_bytes().strip()
        pub = bytes.fromhex(raw.decode()) if len(raw) == 64 else raw
    print(f"AXON dashboard on http://{args.host}:{args.port}")
    print(f"  ledger: {args.ledger}")
    if pub:
        print("  enforcing signatures against the supplied public key")
    try:
        serve(args.ledger, host=args.host, port=args.port, public_key=pub)
    except KeyboardInterrupt:
        print("\nstopped")
    return 0


def cmd_shield(args) -> int:
    from .shield import available_packs, check_pack

    if args.pack:
        report = check_pack(args.pack)
        for finding in report.findings:
            print(finding.describe())
        print(f"\n{'PASS' if report.ok else 'FAIL'}: {args.pack} "
              f"({len(report.findings) - len(report.failures)}/{len(report.findings)} probes)")
        return 0 if report.ok else 1

    packs = available_packs()
    print(f"available packs: {', '.join(packs) or '(none)'}")
    failed = False
    for name in packs:
        report = check_pack(name)
        failed |= not report.ok
        status = "PASS" if report.ok else "FAIL"
        print(f"  {name:<14} {status}  "
              f"({len(report.findings) - len(report.failures)}/{len(report.findings)})")
    return 1 if failed else 0


def cmd_observe(args) -> int:
    from .observe import Observer

    pub = None
    if getattr(args, "pubkey", None):
        raw = Path(args.pubkey).read_bytes().strip()
        pub = bytes.fromhex(raw.decode()) if len(raw) == 64 else raw
    print(json.dumps(Observer(AuditLedger(args.ledger)).summary(public_key=pub), indent=2))
    return 0


def cmd_compliance(args) -> int:
    from .compliance import evaluate, report, run_tests

    results = evaluate()
    for r in results:
        c = r.control
        status = "PASS" if r.ok else "FAIL"
        print(f"[{status}] {c.id:<10} {c.framework:<14} {c.title}")
        print(f"          implementation: {', '.join(c.implementation)}")
        print(f"          evidence: {c.evidence}")
        print(f"          tests: {', '.join(c.tests)}")
        if args.run and r.ok:
            passed = run_tests(c.tests)
            print(f"          executed: {'passing' if passed else 'FAILING'}")
            if not passed:
                status = "FAIL"
        print()

    if args.json:
        print(json.dumps(report(), indent=2))

    failing = [r.control.id for r in results if not r.ok]
    total = len(results)
    print(f"{total - len(failing)}/{total} controls map to present code and tests")
    if failing:
        print(f"incomplete: {', '.join(failing)}")
        return 1
    return 0


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
    p.add_argument("--version", action="version", version=f"axon {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="run a governed agent task")
    r.add_argument("task")
    r.add_argument("--agent", default="agent-1")
    r.add_argument("--model", default=None, help="model id (default depends on provider)")
    r.add_argument("--provider", default=None,
                   help=f"one of: {', '.join(available_providers())} (default: auto-detect)")
    r.add_argument("--budget", type=float, default=1.0)
    r.add_argument("--ledger", default="./axon-audit.jsonl")
    r.add_argument("--policy", default=None)
    r.add_argument("--tool", action="append", help="name=target (repeatable)")
    r.add_argument("--key", default=None,
                   help=f"Ed25519 signing key for the ledger (created if missing; "
                        f"default path when set: {DEFAULT_KEY})")
    r.add_argument("--identities", default=None, help="identity/role registry YAML")
    r.add_argument("--no-rbac", action="store_true",
                   help="skip the identity registry (local dev only; roles not enforced)")
    r.set_defaults(func=cmd_run)

    m = sub.add_parser("models", help="list providers and model prices")
    m.set_defaults(func=cmd_models)

    a = sub.add_parser("audit", help="verify and print the audit ledger")
    a.add_argument("--ledger", default="./axon-audit.jsonl")
    a.add_argument("--pubkey", default=None,
                   help="auditor's public key; enforces that every record is signed by it")
    a.add_argument("--key", default=None, help=argparse.SUPPRESS)
    a.set_defaults(func=cmd_audit)

    k = sub.add_parser("keygen", help="generate an Ed25519 signing key pair")
    k.add_argument("--key", default="./axon-signing.key")
    k.add_argument("--pubkey", default=None)
    k.add_argument("--force", action="store_true")
    k.set_defaults(func=cmd_keygen)

    i = sub.add_parser("identities", help="list roles and identities from the registry")
    i.add_argument("--identities", default=None)
    i.add_argument("--no-rbac", action="store_true", help=argparse.SUPPRESS)
    i.set_defaults(func=cmd_identities)

    d = sub.add_parser("dashboard", help="serve the governance dashboard")
    d.add_argument("--ledger", default="./axon-audit.jsonl")
    d.add_argument("--host", default="127.0.0.1")
    d.add_argument("--port", type=int, default=8080)
    d.add_argument("--pubkey", default=None,
                   help="public key; when given, the dashboard verifies every signature")
    d.set_defaults(func=cmd_dashboard)

    sh = sub.add_parser("shield", help="check policy packs against what they claim to refuse")
    sh.add_argument("pack", nargs="?", default=None, help="pack name (omit to check all)")
    sh.set_defaults(func=cmd_shield)

    ob = sub.add_parser("observe", help="print cost, risk, and integrity analytics")
    ob.add_argument("--ledger", default="./axon-audit.jsonl")
    ob.add_argument("--pubkey", default=None)
    ob.set_defaults(func=cmd_observe)

    cp = sub.add_parser("compliance", help="map controls to the code and tests that implement them")
    cp.add_argument("--run", action="store_true", help="also execute each control's cited tests")
    cp.add_argument("--json", action="store_true", help="print the full mapping as JSON")
    cp.set_defaults(func=cmd_compliance)

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
    try:
        return args.func(args)
    except SignatureError as exc:
        print(f"signing error: {exc}", file=sys.stderr)
        return 6
    except IdentityError as exc:
        print(f"identity error: {exc}", file=sys.stderr)
        return 7
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 5


if __name__ == "__main__":
    raise SystemExit(main())
