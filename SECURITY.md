# Security Policy

AXON governs privileged AI-agent actions, so we treat security reports as
top priority.

## Reporting a vulnerability

**Do not open a public GitHub issue.**

Email **security@axon.dev** with:
- a description and impact assessment,
- reproduction steps or a proof of concept,
- affected versions / commit hash.

We acknowledge within **48 hours** and aim to ship a fix within **7 days**
for critical issues. We will credit reporters unless you ask otherwise.

## Scope

In scope:
- policy-engine bypasses (any action allowed without a matching grant),
- audit-ledger tampering that `verify()` fails to detect,
- cost-cap bypasses,
- provider adapters leaking credentials or data.

Out of scope:
- vulnerabilities in third-party models or providers themselves,
- issues requiring a pre-compromised host.

## Design guarantees we defend

1. **Deny by default.** An unmatched request is denied.
2. **Tamper-evident history.** `SHA256(prev_hash || record)` chain.
3. **Fail closed.** Errors never widen permissions.
