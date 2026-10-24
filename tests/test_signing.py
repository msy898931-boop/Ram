# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 msy898931-boop
# Part of the AXON open core. See NOTICE for the license map.
"""Ed25519 signing tests — RFC 8032 vectors plus real forgery attempts.

The forgery tests are the point of this file. A hash chain alone can be
rewritten wholesale by whoever holds the ledger file; these tests assert
that supplying the auditor's public key closes that hole, and that a
stripped-signature ledger is rejected rather than silently accepted.
"""

import hashlib
import json
import tempfile
from pathlib import Path

import pytest

from axon.core import signing
from axon.core.audit import GENESIS, AuditLedger, canonical
from axon.core.signing import SignatureError, Signer, generate_seed

# RFC 8032 section 7.1: (seed, public key, message, signature)
RFC8032 = [
    (
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    ),
    (
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
        "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    ),
    (
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "af82",
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
        "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    ),
]


@pytest.mark.parametrize("seed_hex,pub_hex,msg_hex,sig_hex", RFC8032)
def test_rfc8032_vectors(seed_hex, pub_hex, msg_hex, sig_hex):
    seed, msg = bytes.fromhex(seed_hex), bytes.fromhex(msg_hex)
    assert signing.public_key_from_seed(seed).hex() == pub_hex
    sig = signing.sign(msg, seed)
    assert sig.hex() == sig_hex
    assert signing.verify(msg, sig, bytes.fromhex(pub_hex))


def test_verify_rejects_wrong_message_signature_and_key():
    seed = generate_seed()
    pub = signing.public_key_from_seed(seed)
    sig = signing.sign(b"hello", seed)
    assert signing.verify(b"hello", sig, pub)
    assert not signing.verify(b"hell0", sig, pub)
    assert not signing.verify(b"hello", bytes([sig[0] ^ 1]) + sig[1:], pub)
    assert not signing.verify(b"hello", sig, signing.public_key_from_seed(generate_seed()))


def test_verify_rejects_malformed_input():
    pub = signing.public_key_from_seed(generate_seed())
    assert not signing.verify(b"m", b"short", pub)
    assert not signing.verify(b"m", b"\x00" * 64, b"short")


def test_signatures_are_deterministic():
    seed = generate_seed()
    assert signing.sign(b"same", seed) == signing.sign(b"same", seed)


def test_signer_from_file_creates_and_reloads():
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "k.key"
        first = signing.signer_from_file(p)
        assert p.exists()
        second = signing.signer_from_file(p)
        assert first.seed == second.seed
        assert first.public_key == second.public_key


def test_signer_from_file_rejects_bad_seed():
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "bad.key"
        p.write_text("not-hex\n")
        with pytest.raises(SignatureError):
            signing.signer_from_file(p)


# --- ledger integration ---------------------------------------------------

def _signed_ledger(path, n=4):
    signer = Signer(generate_seed())
    led = AuditLedger(path, signer=signer)
    for i in range(n):
        led.append("agent-1", f"act.{i}", target=f"/t/{i}", decision="allow", reason="ok")
    return signer, led


def test_signed_ledger_verifies_with_public_key():
    with tempfile.TemporaryDirectory() as d:
        signer, led = _signed_ledger(Path(d) / "a.jsonl")
        assert all(r.signature for r in led.records())
        ok, msg = AuditLedger(Path(d) / "a.jsonl").verify(public_key=signer.public_key)
        assert ok, msg
        assert "signed and verified" in msg


def test_unsigned_ledger_still_verifies_for_backward_compatibility():
    """Ledgers written before signing existed must not report a false tamper."""
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "legacy.jsonl"
        legacy = AuditLedger(path)
        legacy.append("a", "run.start", decision="allow")
        # Re-serialise without the new fields, exactly as an old version would.
        rec = legacy.records()[0]
        old = {
            "seq": rec.seq, "timestamp": rec.timestamp, "actor": rec.actor,
            "action": rec.action, "target": rec.target, "decision": rec.decision,
            "reason": rec.reason, "metadata": rec.metadata,
            "prev_hash": rec.prev_hash,
        }
        old_body = json.dumps(old, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        old["record_hash"] = hashlib.sha256((GENESIS + old_body).encode()).hexdigest()
        path.write_text(json.dumps(old, sort_keys=True, separators=(",", ":")) + "\n")
        ok, msg = AuditLedger(path).verify()
        assert ok, msg


def test_stripping_signatures_is_detected_when_key_is_supplied():
    """The attack that makes naive signing worthless: delete every signature
    and re-hash the chain. Hashes alone accept it; the public key rejects it."""
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "a.jsonl"
        signer, _ = _signed_ledger(path)
        raw = [json.loads(line) for line in path.read_text().splitlines()]
        prev = GENESIS
        for r in raw:
            r["reason"] = "forged"
            r["prev_hash"] = prev
            r["signature"] = ""
            r["key_fingerprint"] = ""
            body = {k: v for k, v in r.items() if k not in ("record_hash", "signature")}
            r["record_hash"] = hashlib.sha256((prev + canonical(body)).encode()).hexdigest()
            prev = r["record_hash"]
        path.write_text("\n".join(canonical(r) for r in raw) + "\n")

        reloaded = AuditLedger(path)
        assert reloaded.verify()[0] is True  # hashes alone cannot tell
        ok, msg = reloaded.verify(public_key=signer.public_key)
        assert not ok
        assert "signature stripped" in msg


def test_resigning_with_attacker_key_is_detected():
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "a.jsonl"
        signer, _ = _signed_ledger(path)
        evil = Signer(generate_seed())
        raw = [json.loads(line) for line in path.read_text().splitlines()]
        prev = GENESIS
        for r in raw:
            r["reason"] = "forged"
            r["prev_hash"] = prev
            r["key_fingerprint"] = evil.fingerprint
            body = {k: v for k, v in r.items() if k not in ("record_hash", "signature")}
            r["record_hash"] = hashlib.sha256((prev + canonical(body)).encode()).hexdigest()
            r["signature"] = evil.sign(f"{r['seq']}:{r['record_hash']}".encode()).hex()
            prev = r["record_hash"]
        path.write_text("\n".join(canonical(r) for r in raw) + "\n")

        ok, msg = AuditLedger(path).verify(public_key=signer.public_key)
        assert not ok
        assert "signed by key" in msg


def test_payload_edit_breaks_chain_even_when_signed():
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "a.jsonl"
        signer, _ = _signed_ledger(path)
        raw = [json.loads(line) for line in path.read_text().splitlines()]
        raw[1]["decision"] = "deny"
        path.write_text("\n".join(canonical(r) for r in raw) + "\n")
        ok, msg = AuditLedger(path).verify(public_key=signer.public_key)
        assert not ok and "tampered" in msg


def test_signed_records_export_signature_state_to_otel():
    with tempfile.TemporaryDirectory() as d:
        _, led = _signed_ledger(Path(d) / "a.jsonl")
        spans = led.to_otel_spans()
        assert all(s["attributes"]["axon.signed"] is True for s in spans)
