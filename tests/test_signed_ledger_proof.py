# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 msy898931-boop
# Part of the AXON open core. See NOTICE for the license map.
"""The proof script must actually prove something.

`examples/signed_ledger_proof.py` is what a reader runs to decide whether
AXON's ledger is real. A demo that printed reassuring text without performing
the attack would be worse than no demo, because it would be believed. These
tests run the script for real and assert it observes the difference: the
unkeyed chain accepts a forged rewrite, and the signed ledger refuses it.
"""

from __future__ import annotations

import importlib.util
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "examples" / "signed_ledger_proof.py"


def _load():
    spec = importlib.util.spec_from_file_location("signed_ledger_proof", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules["signed_ledger_proof"] = module
    spec.loader.exec_module(module)
    return module


def test_the_proof_script_runs_and_shows_both_outcomes(capsys):
    module = _load()
    module.main()
    out = capsys.readouterr().out
    assert "UNDETECTED" in out, "the unkeyed chain must be shown accepting the forgery"
    assert "detected" in out, "the signed ledger must be shown refusing the forgery"
    assert "invalid signature on record 3" in out
    assert "signature stripped" in out


def test_a_plain_chain_really_does_accept_a_forged_rewrite():
    """The attack must genuinely succeed against the unkeyed design, or the
    comparison is a straw man and the demo is dishonest."""
    module = _load()
    chain = module.build_plain_chain(module.EVENTS)
    assert module.verify_plain_chain(chain)[0] is True

    module.rewrite_plain_chain(chain, 3, "allow")

    ok, _ = module.verify_plain_chain(chain)
    assert ok is True, "an unkeyed chain cannot detect a recomputed rewrite"
    assert chain[2]["decision"] == "allow"


def test_the_signed_ledger_refuses_the_same_rewrite(tmp_path):
    """Same attack, signed ledger: the recomputed hash does not carry a
    signature, so verification fails and names the record."""
    module = _load()
    from axon.core.audit import AuditLedger
    from axon.core.signing import Signer, generate_seed, public_key_from_seed

    seed = generate_seed()
    ledger = AuditLedger(tmp_path / "s.jsonl", signer=Signer(seed=seed))
    for actor, action, decision in module.EVENTS:
        ledger.append(actor, action, decision=decision)

    pub = public_key_from_seed(seed)
    assert ledger.verify(public_key=pub)[0] is True

    # Rewrite the record the way the unkeyed attacker does.
    import hashlib
    import json

    lines = [json.loads(x) for x in (tmp_path / "s.jsonl").read_text().splitlines() if x.strip()]
    for rec in lines:
        if rec["seq"] == 3:
            rec["decision"] = "allow"
    prev = module.GENESIS
    for rec in lines:
        rec["prev_hash"] = prev
        body = {k: v for k, v in rec.items() if k not in ("record_hash", "signature")}
        canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        rec["record_hash"] = hashlib.sha256((prev + canonical).encode()).hexdigest()
        prev = rec["record_hash"]
    (tmp_path / "s.jsonl").write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in lines))

    ok, msg = AuditLedger(tmp_path / "s.jsonl").verify(public_key=pub)
    assert not ok
    assert "invalid signature on record 3" in msg
