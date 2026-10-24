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
    from .security.auth import Authenticator
    from .security.canary import CanarySet

    pub = None
    if getattr(args, "pubkey", None):
        raw = Path(args.pubkey).read_bytes().strip()
        pub = bytes.fromhex(raw.decode()) if len(raw) == 64 else raw

    auth = None
    if getattr(args, "tokens", None):
        auth = Authenticator.from_yaml(args.tokens)
    elif args.host not in {"127.0.0.1", "::1", "localhost"} and not args.allow_unauthenticated:
        print(f"refusing to serve on {args.host} without --tokens")
        print("  create one with: axon token create --name operator --out tokens.yaml")
        print("  or pass --allow-unauthenticated to override (not recommended)")
        return 2

    canaries = None
    if getattr(args, "canaries", None):
        canaries = CanarySet.from_file(args.canaries)

    print(f"AXON dashboard on http://{args.host}:{args.port}")
    print(f"  ledger: {args.ledger}")
    print(f"  authentication: {'ON' if auth and auth.enabled else 'off'}")
    if pub:
        print("  enforcing signatures against the supplied public key")
    if canaries:
        print(f"  canaries loaded: {len(canaries)}")
    try:
        serve(
            args.ledger, host=args.host, port=args.port, public_key=pub,
            authenticator=auth, canaries=canaries,
            allow_unauthenticated_public=getattr(args, "allow_unauthenticated", False),
        )
    except KeyboardInterrupt:
        print("\nstopped")
    except Exception as exc:
        print(f"dashboard refused to start: {exc}")
        return 2
    return 0


def cmd_token(args) -> int:
    """Issue a token; store only its digest, print the plaintext once."""
    from .security.auth import Token

    token, plaintext = Token.issue(
        args.name, role=args.role, scopes=set(args.scope or []),
    )
    if args.out:
        path = Path(args.out)
        existing = {}
        if path.exists():
            import yaml as _yaml
            existing = _yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        tokens = existing.setdefault("tokens", {})
        tokens[args.name] = {
            "digest": token.digest,
            "role": args.role,
            "scopes": sorted(token.scopes),
        }
        existing.setdefault("enabled", True)
        import yaml as _yaml
        path.write_text(_yaml.safe_dump(existing, sort_keys=False), encoding="utf-8")
        path.chmod(0o600)
        print(f"token '{args.name}' written to {path} (mode 0600)")
        print("the digest is stored; the token itself is not")
    print()
    print("token (shown once, store it now):")
    print(f"  {plaintext}")
    print()
    print("use it with:  curl -H 'Authorization: Bearer <token>' http://host:port/api/summary")
    return 0


def cmd_canary(args) -> int:
    """Mint canaries, or scan text for a leak."""
    from .security.canary import CanarySet

    if args.scan:
        canaries = CanarySet.from_file(args.scan)
        text = sys.stdin.read()
        hits = canaries.scan(text, where="stdin")
        if not hits:
            print(f"no canary found ({len(canaries)} checked)")
            return 0
        for hit in hits:
            print(hit.describe())
        return 1

    canaries = CanarySet()
    for name in args.name or ["default"]:
        canaries.create(name, location=args.location, description=args.description or "")
    if args.out:
        # Write the plaintext values to a file the operator protects, and the
        # fingerprint inventory to a companion file that is safe to share.
        lines = "\n".join(f"{c.name}={c.value}" for c in canaries.all())
        Path(args.out).write_text(lines + "\n", encoding="utf-8")
        Path(args.out).chmod(0o600)
        inv = Path(args.out).with_suffix(".inventory.json")
        canaries.save_inventory(inv)
        print(f"canaries written to {args.out} (mode 0600, keep secret)")
        print(f"shareable inventory written to {inv} (fingerprints only)")
    else:
        for c in canaries.all():
            print(f"{c.name}={c.value}")
    return 0


def cmd_posture(args) -> int:
    """Report which security layers a configuration actually enforces."""
    from .security.auth import Authenticator
    from .security.canary import CanarySet
    from .security.headers import LayerStatus, Posture

    layers: list[LayerStatus] = []

    if args.tokens and Path(args.tokens).exists():
        try:
            auth = Authenticator.from_yaml(args.tokens)
            layers.append(LayerStatus(
                "authentication", auth.enabled,
                f"{len(auth.token_names())} token(s), enabled={auth.enabled}",
            ))
        except Exception as exc:
            layers.append(LayerStatus("authentication", False, f"unreadable: {exc}"))
    else:
        layers.append(LayerStatus(
            "authentication", False,
            "no token file supplied (--tokens); the ledger is open to anyone "
            "who can reach the port",
        ))

    public = args.host not in {"127.0.0.1", "::1", "localhost"}
    layers.append(LayerStatus(
        "rate limiting", True, "token bucket, per principal (built in)",
    ))
    layers.append(LayerStatus(
        "replay defence", True, "nonce + timestamp window (built in)",
    ))
    layers.append(LayerStatus(
        "security headers", True, "CSP, X-Frame-Options, nosniff, no-referrer (built in)",
    ))
    layers.append(LayerStatus(
        "transport", not public, "loopback only" if not public else
        f"bound to {args.host}: use TLS in front of this",
    ))
    layers.append(LayerStatus(
        "signature enforcement", bool(args.pubkey),
        "public key supplied" if args.pubkey else "no --pubkey: records are not signature-checked",
    ))

    if args.canaries and Path(args.canaries).exists():
        canaries = CanarySet.from_file(args.canaries)
        layers.append(LayerStatus("canaries", True, f"{len(canaries)} tripwire(s) loaded"))
    else:
        layers.append(LayerStatus(
            "canaries", False, "no canary file supplied; leaks would go undetected",
        ))

    layers.append(LayerStatus(
        "injection detection", True,
        "prompt-injection scanner available (axon scan)",
    ))

    posture = Posture(layers)
    print(posture.describe())
    print()
    print("honest reading: this is defence in depth, not immunity. No layer here")
    print("makes compromise impossible; together they make it harder, narrower,")
    print("and detectable. Treat 100/100 as 'every control is switched on', not")
    print("as 'unbreakable'.")
    return 0 if posture.fully_hardened else 1


def cmd_scan(args) -> int:
    """Scan untrusted text for prompt injection before an agent consumes it."""
    from .security.injection import scan, verdict

    if args.file:
        text = Path(args.file).read_text(encoding="utf-8", errors="replace")
        source = args.file
    else:
        text = sys.stdin.read()
        source = "<stdin>"

    result = scan(text)
    decision = verdict(result, threshold=args.threshold)
    print(f"{source}: {decision} (score {result.score}, worst {result.worst})")
    if result.truncated:
        print("  note: input was truncated; the tail was not scanned")
    for finding in result.findings:
        print(f"  {finding.describe()}")
    if not result.findings:
        print("  no known injection pattern matched")
    return 1 if decision == "deny" else 0


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
    d.add_argument("--tokens", default=None,
                   help="token file; required for any non-loopback bind")
    d.add_argument("--canaries", default=None,
                   help="canary file; enables leak detection on served records")
    d.add_argument("--allow-unauthenticated", action="store_true",
                   help="override the refusal to serve publicly without tokens")
    d.set_defaults(func=cmd_dashboard)

    tok = sub.add_parser("token", help="issue a dashboard access token")
    tok_sub = tok.add_subparsers(dest="token_cmd")
    tok_create = tok_sub.add_parser("create", help="create a token")
    tok_create.add_argument("--name", required=True)
    tok_create.add_argument("--role", default="viewer")
    tok_create.add_argument("--scope", action="append", default=None)
    tok_create.add_argument("--out", default=None, help="token file to update (mode 0600)")
    tok_create.set_defaults(func=cmd_token)
    tok.set_defaults(func=cmd_token, name=None, role="viewer", scope=None, out=None)

    can = sub.add_parser("canary", help="mint canary tokens or scan for a leak")
    can.add_argument("name", nargs="*", help="names for new canaries")
    can.add_argument("--out", default=None, help="write canaries here (mode 0600)")
    can.add_argument("--location", default="")
    can.add_argument("--description", default=None)
    can.add_argument("--scan", default=None, metavar="FILE",
                     help="scan stdin for canaries listed in FILE")
    can.set_defaults(func=cmd_canary)

    pos = sub.add_parser("posture", help="report which security layers are actually enforcing")
    pos.add_argument("--tokens", default=None)
    pos.add_argument("--canaries", default=None)
    pos.add_argument("--pubkey", default=None)
    pos.add_argument("--host", default="127.0.0.1")
    pos.set_defaults(func=cmd_posture)

    sc = sub.add_parser("scan", help="scan untrusted text for prompt injection")
    sc.add_argument("--file", default=None, help="file to scan (default: stdin)")
    sc.add_argument("--threshold", type=float, default=0.4)
    sc.set_defaults(func=cmd_scan)

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
