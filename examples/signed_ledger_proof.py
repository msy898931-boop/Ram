"""Why the ledger is signed, not just hash-chained.

A hash chain proves a log is *internally consistent*. It does not prove the
log is *original*, because the hash is unkeyed: anyone who can write the file
can also recompute every hash after editing it. This script runs that attack
against two ledgers:

  1. a plain SHA-256 chain, built the way unkeyed audit chains are built, and
  2. AXON's Ed25519-signed ledger.

Both are attacked identically. The plain chain reports OK. The signed one
reports FAILED and names the record.

Run:  python3 examples/signed_ledger_proof.py
"""

import hashlib
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from axon.core.audit import AuditLedger
from axon.core.signing import generate_seed, public_key_from_seed

GENESIS = "0" * 64


def banner(text):
    print(f"\n\033[1;36m{'=' * 66}\n  {text}\n{'=' * 66}\033[0m")


# --------------------------------------------------------------------------
# A plain, unkeyed hash chain. This is the design the whole point is about:
# each entry hashes its body plus the previous hash, and verification is just
# "recompute and compare". No secret participates, so nothing distinguishes
# the original author's hashes from an attacker's recomputation.
# --------------------------------------------------------------------------
def plain_hash(entry):
    body = {k: v for k, v in entry.items() if k != "hash"}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256((entry["prev"] + canonical).encode()).hexdigest()


def build_plain_chain(events):
    chain, prev = [], GENESIS
    for i, (actor, action, decision) in enumerate(events, start=1):
        entry = {
            "seq": i,
            "actor": actor,
            "action": action,
            "decision": decision,
            "prev": prev,
        }
        entry["hash"] = plain_hash(entry)
        prev = entry["hash"]
        chain.append(entry)
    return chain


def verify_plain_chain(chain):
    """Recompute every hash and every link. This is the strongest check an
    unkeyed chain can make, and it is exactly what it cannot win."""
    prev = GENESIS
    for entry in chain:
        if entry["prev"] != prev:
            return False, f"broken link at record {entry['seq']}"
        if entry["hash"] != plain_hash(entry):
            return False, f"tampered record {entry['seq']}"
        prev = entry["hash"]
    return True, f"chain intact ({len(chain)} records)"


def rewrite_plain_chain(chain, target_seq, new_decision):
    """The attack: edit one record, then recompute every hash from that point
    on. No key is needed, because none was used to write them."""
    for entry in chain:
        if entry["seq"] == target_seq:
            entry["decision"] = new_decision
        entry["hash"] = plain_hash(entry)
        # Re-link the following record to the hash we just forged.
        nxt = next((e for e in chain if e["seq"] == entry["seq"] + 1), None)
        if nxt is not None:
            nxt["prev"] = entry["hash"]
    return chain


# --------------------------------------------------------------------------
EVENTS = [
    ("support-agent", "tool.read_file", "allow"),
    ("support-agent", "tool.send_email", "allow"),
    ("support-agent", "tool.drop_table", "deny"),      # <- the record we forge
    ("support-agent", "tool.read_file", "allow"),
]

SECRET = "the denial an attacker wants erased"


def attack_plain(tmp):
    banner("1. Plain SHA-256 chain (unkeyed) — the attacker wins")
    chain = build_plain_chain(EVENTS)
    ok, msg = verify_plain_chain(chain)
    print(f"  before tamper : {'OK' if ok else 'FAILED'} — {msg}")
    print(f"  record 3 says : {chain[2]['decision']!r}  ({SECRET})")

    rewrite_plain_chain(chain, 3, "allow")

    ok, msg = verify_plain_chain(chain)
    print("  attacker edits record 3 to 'allow' and recomputes the chain")
    print(f"  after tamper  : {'OK' if ok else 'FAILED'} — {msg}")
    print(f"  record 3 says : {chain[2]['decision']!r}")
    verdict = "UNDETECTED" if ok else "detected"
    print(f"\n  \033[1;31mverdict: {verdict}\033[0m — the denial is gone and the log still verifies.")


def attack_signed(tmp):
    banner("2. AXON Ed25519-signed ledger — the attacker is caught")
    seed = generate_seed()
    pub = public_key_from_seed(seed)
    path = Path(tmp) / "signed.jsonl"
    ledger = AuditLedger(path, signer=_signer(seed))
    for actor, action, decision in EVENTS:
        ledger.append(actor, action, decision=decision)

    ok, msg = ledger.verify(public_key=pub)
    print(f"  before tamper : {'OK' if ok else 'FAILED'} — {msg}")
    print(f"  record 3 says : {ledger.records()[2].decision!r}  ({SECRET})")

    # Same attacker, same powers: rewrite the file and recompute the hashes.
    lines = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    for rec in lines:
        if rec["seq"] == 3:
            rec["decision"] = "allow"
    # Recompute hashes exactly as the unkeyed attacker does.
    prev = GENESIS
    for rec in lines:
        rec["prev_hash"] = prev
        body = {k: v for k, v in rec.items() if k not in ("record_hash", "signature")}
        canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        rec["record_hash"] = hashlib.sha256((prev + canonical).encode()).hexdigest()
        prev = rec["record_hash"]
    path.write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in lines))

    reopened = AuditLedger(path)
    ok, msg = reopened.verify(public_key=pub)
    print("  attacker edits record 3 to 'allow' and recomputes every hash")
    print(f"  after tamper  : {'OK' if ok else 'FAILED'} — {msg}")
    verdict = "UNDETECTED" if ok else "detected"
    print(f"\n  \033[1;32mverdict: {verdict}\033[0m — the recomputed hash cannot forge the signature.")

    banner("3. Stripping the signatures does not help either")
    for rec in lines:
        rec["signature"] = ""
    path.write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in lines))
    ok, msg = AuditLedger(path).verify(public_key=pub)
    print("  signatures removed, chain re-hashed cleanly")
    print(f"  result        : {'OK' if ok else 'FAILED'} — {msg}")
    print("\n  Strict mode refuses a ledger whose signatures vanished, so 'delete")
    print("  the proof' fails closed instead of looking tidy.")


def _signer(seed):
    from axon.core.signing import Signer

    return Signer(seed=seed)


def main():
    banner("Can you prove what happened?  Hash chain vs signed ledger")
    print("""
  Both ledgers below are attacked the same way: an actor with write access
  edits a 'deny' to an 'allow' and recomputes the chain. The difference is
  whether recomputing is enough to make the edit look original.
""")
    tmp = tempfile.mkdtemp()
    attack_plain(tmp)
    attack_signed(tmp)
    banner("The takeaway")
    print("""
  A hash chain answers "is this file internally consistent?"
  A signature answers "did the key holder write this?"

  Only the second survives an attacker who can write the file. If your
  audit trail is the thing you show a regulator, that is the difference
  between evidence and a story.
""")


if __name__ == "__main__":
    main()
