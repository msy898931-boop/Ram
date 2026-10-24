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

## The seven layers

Ordered by what an attacker reaches first.

| # | Layer | Module | Stops | Does not stop |
|---|---|---|---|---|
| 1 | Authentication | `security/auth.py` | Unauthenticated reads of the ledger; forged tokens | A stolen valid token |
| 2 | Rate limiting | `security/auth.py` | Credential stuffing, scraping, request floods | A slow, patient attacker |
| 3 | Replay defence | `security/auth.py` | Re-use of a captured request | A live attacker with the signing key |
| 4 | Security headers | `security/headers.py` | XSS execution, clickjacking, MIME sniffing | A browser that ignores headers |
| 5 | Injection detection | `security/injection.py` | Known prompt-injection shapes in tool output | Novel phrasing; it is a detector, not a proof |
| 6 | Canary tokens | `security/canary.py` | Nothing — it *detects* that a specific secret left | The leak itself; it reports it |
| 7 | Self-verification | `security/headers.py` (`Posture`) | Silent failure: a control that is off but assumed on | Nothing; it is a reporting layer |

## What each layer is worth

### 1. Authentication

Tokens are issued by `axon token create`, which stores only a SHA-256
digest. The plaintext is printed once and never written to disk. Comparison
is constant-time and does not exit early, so response timing does not reveal
which token matched.

The failure path is deliberately uniform: every rejection returns the same
message, because distinguishing "no such token" from "wrong token" tells an
attacker which half of a guess was correct.

### 2. Rate limiting

A token bucket per principal, refilled continuously. A fixed window would
let a caller spend its whole budget at the end of one window and the start
of the next, doubling the burst; a bucket cannot, because the bucket is the
ceiling.

### 3. Replay defence

A signed request carries a timestamp and a single-use nonce. The timestamp
bounds how long a capture stays useful; the nonce stops a capture being used
twice inside that window. Both halves are required. The signature covers the
method, path, timestamp, nonce, and body digest, so a captured request cannot
be re-pointed at a different endpoint or payload.

### 4. Security headers

The dashboard renders attacker-influenced text — an agent's action name, a
target path, an actor. A strict `Content-Security-Policy` with
`default-src 'none'` turns a markup-injection bug from a compromise into a
blocked request. `frame-ancestors 'none'` and `X-Frame-Options: DENY` close
clickjacking. These are applied to error responses too, because an injected
error page is still a page.

### 5. Injection detection

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

### 6. Canary tokens

A canary is a random string placed where only a leak could expose it — an
unused credential, a sentinel row, a tripwire file. It authenticates nothing,
so any appearance of it outside its home is proof of exfiltration with no
ambiguity, because the string never legitimately appears anywhere else.

This is stronger evidence than anomaly detection. An anomaly score is a
guess; a canary hit is a fact, and the timestamp says when.

The canary's value is never written to the ledger. The ledger records a
fingerprint and a redacted context, so the audit trail does not become a
second copy of the secret.

### 7. Self-verification

`axon posture` inspects a live configuration and reports, per layer, whether
it is actually enforcing. A control that exists in code but is switched off
in the deployment is worse than no control, because it creates false
confidence.

The command exits non-zero when any layer is off, and its output says
explicitly that 100/100 means "every control is switched on", not
"unbreakable".

## Running the tests

```bash
python -m pytest tests/test_security_*.py -q
python -m axon.cli posture --tokens tokens.yaml --canaries canaries.txt --pubkey pub.hex
python -m axon.cli compliance --run
```

## What is still missing

Being explicit about gaps is part of the design:

- **TLS termination** is the deployment's responsibility. `axon posture`
  flags a non-loopback bind without it.
- **SSO/OIDC** is not implemented. `Identity.from_oidc_claims()` maps
  verified claims onto a principal, but token verification is left to a JWT
  library the deployment supplies.
- **External audit** (SOC 2, ISO 27001 certification) is not obtained. The
  compliance mapping shows where the code and tests for each control live; it
  is not a certificate, and it should not be read as one.
- **The injection detector has a known corpus, not a guarantee.** It catches
  what it has patterns for. New phrasings will get through until a pattern is
  added, which is why layer 6 exists: what gets past layer 5 should still be
  visible.
