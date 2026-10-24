"""Adversarial tests for canary tokens (exfiltration detection)."""

from __future__ import annotations

import json

from axon.security.canary import (
    CANARY_PREFIX,
    Canary,
    CanarySet,
    generate_canary,
)


def test_generated_canary_is_high_entropy_and_prefixed():
    c = generate_canary("honey-db")
    assert c.value.startswith(CANARY_PREFIX)
    # 32 random bytes rendered as hex.
    assert len(c.value) == len(CANARY_PREFIX) + 64


def test_generated_canaries_are_unique():
    values = {generate_canary("x").value for _ in range(200)}
    assert len(values) == 200


def test_clean_text_produces_no_hits():
    cs = CanarySet([generate_canary("a")])
    assert cs.scan("a perfectly ordinary model response") == []


def test_leaked_canary_is_detected():
    cs = CanarySet()
    c = cs.create("honey-aws", location="unused IAM key")
    hits = cs.scan(f"here is the key: {c.value} use it", where="model_output")
    assert len(hits) == 1
    assert hits[0].canary.name == "honey-aws"
    assert hits[0].where == "model_output"


def test_every_leaked_canary_is_reported_not_just_the_first():
    cs = CanarySet()
    a = cs.create("a")
    b = cs.create("b")
    hits = cs.scan(f"{a.value} and also {b.value}")
    assert {h.canary.name for h in hits} == {"a", "b"}


def test_hit_context_redacts_the_value_itself():
    """The evidence must not become a second copy of the secret."""
    cs = CanarySet()
    c = cs.create("x")
    hits = cs.scan(f"prefix text {c.value} suffix text")
    assert c.value not in hits[0].context
    assert "[CANARY]" in hits[0].context


def test_fingerprint_is_stable_and_not_the_value():
    c = generate_canary("x")
    assert c.fingerprint == c.fingerprint
    assert c.fingerprint != c.value
    assert c.value not in c.fingerprint


def test_inventory_does_not_disclose_plaintext_values():
    """The inventory is meant to be shareable; it must not leak the tripwires."""
    cs = CanarySet()
    c = cs.create("honey", location="vault")
    payload = json.loads(cs.to_json())
    assert payload["canaries"][0]["fingerprint"] == c.fingerprint
    assert c.value not in cs.to_json()


def test_inventory_roundtrip_keeps_metadata(tmp_path):
    cs = CanarySet()
    c = cs.create("honey", location="unused key", description="db tripwire")
    path = tmp_path / "inv.json"
    cs.save_inventory(path)
    loaded = json.loads(path.read_text())
    assert loaded["canaries"][0]["location"] == "unused key"
    assert loaded["canaries"][0]["fingerprint"] == c.fingerprint


def test_from_file_reads_values_and_skips_comments(tmp_path):
    path = tmp_path / "canaries.txt"
    path.write_text("# comment\n\nalpha=axon_canary_deadbeef\nbeta=axon_canary_cafe\n", encoding="utf-8")
    cs = CanarySet.from_file(path)
    assert len(cs) == 2
    assert cs.scan("we leaked axon_canary_deadbeef")[0].canary.name == "alpha"


def test_partial_canary_does_not_trigger():
    """A truncated value is not proof of exfiltration."""
    cs = CanarySet()
    c = cs.create("x")
    assert cs.scan(c.value[: len(c.value) - 4]) == []


def test_empty_and_none_text_is_safe():
    cs = CanarySet([generate_canary("x")])
    assert cs.scan("") == []


def test_scan_works_across_egress_paths():
    cs = CanarySet()
    c = cs.create("x")
    for where in ["model_output", "tool_result", "ledger", "http_response"]:
        assert cs.scan(f"leak {c.value}", where=where)[0].where == where


def test_manual_canary_can_be_constructed():
    c = Canary(name="manual", value="axon_canary_manual_value")
    cs = CanarySet([c])
    assert cs.scan("axon_canary_manual_value")[0].canary.name == "manual"


def test_hit_describe_does_not_include_the_value():
    cs = CanarySet()
    c = cs.create("x")
    hit = cs.scan(f"leak {c.value}")[0]
    assert c.value not in hit.describe()
    assert c.fingerprint in hit.describe()
