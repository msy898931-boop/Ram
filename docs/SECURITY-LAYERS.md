# AXON security layers

This document describes the defence-in-depth layers that protect an AXON
deployment, what each one actually stops, and — importantly — what it does
not stop. Every claim here is backed by code and by a test that fails if the
control stops working.

## The honest premise

No system is unbreakable. Not this one, not any other. A security layer is
worth building when it makes an attack **harder**, **narrower**, or
**visible**. The goal is not immunity; it is that a successful intrusion
should be expensive, limited in scope, and detectable.

Anyone who tells you a system cannot be breached is either mistaken or
selling something. This document will not do that.

## The nine layers

These are the nine layers `axon posture` reports on, in the order it prints
them. That is deliberate: a layer this document describes but the command
cannot see is a layer nobody will notice going off.

| # | Layer | Module | Stops | Does not stop |
|---|---|---|---|---|
| 1 | Authentication | `security/auth.py` | Unauthenticated reads of the ledger; forged tokens | A stolen valid token |
| 2 | Federated identity | `security/oidc.py` | Locally-forged accounts; access that survives an offboarding | A token revoked before its `exp` (no introspection call) |
| 3 | Rate limiting | `security/auth.py` | Credential stuffing, scraping, request floods | A slow, patient attacker |
| 4 | Replay defence | `security/auth.py` | Re-use of a captured request | A live attacker with the signing key |
| 5 | Security headers | `security/headers.py` | XSS execution, clickjacking, MIME sniffing | A browser that ignores headers |
| 6 | Transport encryption | `security/tls.py` | Eavesdropping, path tampering, protocol downgrade | An endpoint whose private key is stolen |
| 7 | Signature enforcement | `core/signing.py` | Silent edits to the ledger; a rewritten audit trail | A deployment that never supplied a public key |
| 8 | Canary tokens | `security/canary.py` | Nothing — it *detects* that a specific secret left | The leak itself; it reports it |
| 9 | Injection detection | `security/injection.py` | Known prompt-injection shapes in tool output | Novel phrasing; it is a detector, not a proof |

## How you check any of this

Self-verification is not a tenth layer, it is the reason the list above can
be trusted. `axon posture` inspects a live configuration and reports, per
layer, whether it is actually enforcing. A control that exists in code but is
switched off in the deployment is worse than no control, because it creates
false confidence.

The command exits non-zero when any layer is off, and its output says
explicitly that 100/100 means "every control is switched on", not
"unbreakable". An empty canary file counts as a gap: reporting ON for zero
tripwires would be the exact silent failure the command exists to catch.

## What each layer is worth

### 1. Authentication

Tokens are issued by `axon token create`, which stores only a SHA-256
digest. The plaintext is printed once and never written to disk. Comparison
is constant-time and does not exit early, so response timing does not reveal
which token matched.

The failure path is deliberately uniform: every rejection returns the same
message, because distinguishing "no such token" from "wrong token" tells an
attacker which half of a guess was correct.

### 2. Federated identity

Holding a local credential store means every offboarding is a change here,
and any missed one is access that outlives the person's employment. When an
organisation already runs an identity provider, the dashboard can verify the
provider's tokens instead, so deprovisioning happens where it is already
happening.

What the verifier refuses: `alg: none`; algorithm confusion (a token claiming
an algorithm the key cannot support); keys marked `use: enc` used for
signature; a signature that does not match the key the `kid` names; wrong
issuer, wrong audience, expired or not-yet-valid tokens.

Key rotation is handled by re-fetching the provider's JWKS when an unknown
`kid` appears, rate-limited so a flood of unknown key ids cannot turn into a
denial of service against the provider.

What it does not do: call the provider's introspection endpoint. A token
revoked before its stated expiry is accepted until it expires. Shorten `exp`
in the provider's token policy if that window matters more than the extra
round-trip.

### 3. Rate limiting

A token bucket per principal, refilled continuously. A fixed window would
let a caller spend its whole budget at the end of one window and the start
of the next, doubling the burst; a bucket cannot, because the bucket is the
ceiling.

### 4. Replay defence

A signed request carries a timestamp and a single-use nonce. The timestamp
bounds how long a capture stays useful; the nonce stops a capture being used
twice inside that window. Both halves are required. The signature covers the
method, path, timestamp, nonce, and body digest, so a captured request cannot
be re-pointed at a different endpoint or payload.

### 5. Security headers

The dashboard renders attacker-influenced text — an agent's action name, a
target path, an actor. A strict `Content-Security-Policy` with
`default-src 'none'` turns a markup-injection bug from a compromise into a
blocked request. `frame-ancestors 'none'` and `X-Frame-Options: DENY` close
clickjacking. These are applied to error responses too, because an injected
error page is still a page.

### 6. Transport encryption

The dashboard terminates TLS itself when given a certificate and key, rather
than requiring a proxy in front. A control that lives in the code is one that
`axon posture` can see and report on; one that lives in a deployment guide is
one that gets skipped.

The pair is validated at startup — the certificate and key must match, and
the fingerprint is recorded — so a mismatch fails before the first request
rather than during the first handshake, which is when it would otherwise be
found by a user. TLS 1.2 is the floor, NULL and export-grade ciphers are
refused, and HSTS is sent.

Where no certificate is supplied, `axon posture` still reports this layer as
ON if the dashboard is bound to loopback only, and OFF if it is bound to a
public address over plain HTTP. The distinction is the point: "no TLS needed
because nothing off this host can reach it" is a real answer, and "exposed on
0.0.0.0 without TLS" is not.

### 7. Signature enforcement

The ledger is append-only, but append-only is a property of the writer, not
of the file. Anyone who can edit the file can rewrite history. Ed25519
signatures (`core/signing.py`, implemented from RFC 8032 with no third-party
crypto dependency) make each record carry proof of who wrote it and what it
said, so a rewritten entry fails verification instead of being read as fact.

This layer is only ON when a public key was actually supplied to check
against. A ledger that is signed but never verified is a ledger whose
integrity nobody has established, so `axon posture` reports it as a gap
rather than assuming the signature implies verification.

### 8. Canary tokens

A canary is a random string placed where only a leak could expose it — an
unused credential, a sentinel row, a tripwire file. It authenticates nothing,
so any appearance of it outside its home is proof of exfiltration with no
ambiguity, because the string never legitimately appears anywhere else.

This is stronger evidence than anomaly detection. An anomaly score is a
guess; a canary hit is a fact, and the timestamp says when.

The canary's value is never written to the ledger. The ledger records a
fingerprint and a redacted context, so the audit trail does not become a
second copy of the secret.

### 9. Injection detection

An agent that reads a web page, an issue, or a file is consuming text an
attacker can influence. The attacker does not need to break into the host;
they need the agent to read one sentence.

This layer is **detection, not prevention**. It matches named attack shapes:
instruction override, role hijack, system-prompt leak, secret exfiltration,
destructive tool use, privilege escalation, policy bypass, delimiter
spoofing, authority claims, and hidden characters.

Its accuracy is measured, not claimed. `tests/test_security_injection.py`
asserts that every attack in its corpus is denied and that no benign
document in its corpus is denied. A detector that denies everything is
useless, so the false-positive test is as important as the attack test.

Negation is handled explicitly: "we must not delete the database" is a
policy statement, not an order, and is not flagged.

## Running the tests

```bash
python -m pytest tests/test_security_*.py -q
python -m axon.cli posture --tokens tokens.yaml --canaries canaries.txt --pubkey pub.hex
python -m axon.cli compliance --run
```

## What is still missing

Being explicit about gaps is part of the design:

- **Token introspection** is not implemented. A token revoked at the
  provider before its `exp` is accepted until it expires. Verification is
  offline by design — an introspection call per request would add a network
  dependency to the hot path — but deployments that need immediate revocation
  should shorten `exp`.
- **External audit** (SOC 2, ISO 27001 certification) is not obtained, and
  cannot be obtained by writing code. A SOC 2 report is issued by a licensed
  CPA firm after an engagement covering the whole organisation — governance,
  personnel, vendors, facilities — not just the technical controls in a
  repository. What the repository can do is be ready for that engagement:
  `axon compliance` maps each control to its code and tests, and
  `axon compliance --evidence` writes a pack with content digests and the
  ledger's integrity state for an auditor to sample. Neither is a
  certificate, and neither should be read as one.
- **Certificate rotation and revocation** are manual. The dashboard reads a
  certificate at startup; a deployment that rotates certificates on a
  schedule needs a reload mechanism (a restart, or a supervisor that does
  it).
- **The injection detector has a known corpus, not a guarantee.** It catches
  what it has patterns for. New phrasings will get through until a pattern is
  added, which is why layer 6 exists: what gets past layer 5 should still be
  visible.
