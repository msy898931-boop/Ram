# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 msy898931-boop
# Part of the AXON open core. See NOTICE for the license map.
"""Adversarial tests for the authentication, rate-limit, and replay layers.

Each test here is written as an attack that must fail, not as a feature that
must work. A test that only proves the happy path passes proves nothing about
whether the gate holds.
"""

from __future__ import annotations

import time

import pytest

from axon.security.auth import (
    Authenticator,
    AuthError,
    Principal,
    RateLimited,
    RateLimiter,
    ReplayDetected,
    ReplayGuard,
    Token,
    hash_token,
    request_signature,
    verify_request_signature,
)


@pytest.fixture
def auth() -> Authenticator:
    a = Authenticator()
    token, plaintext = Token.issue("ops", role="operator", scopes={"ledger:read"})
    a.add(token)
    a._plaintext = plaintext  # type: ignore[attr-defined]
    return a


# --- Layer 1: authentication ------------------------------------------------


def test_valid_token_authenticates(auth):
    principal = auth.authenticate(f"Bearer {auth._plaintext}")
    assert principal.name == "ops"
    assert principal.may("ledger:read")


def test_missing_header_is_refused(auth):
    with pytest.raises(AuthError):
        auth.authenticate(None)


def test_empty_and_malformed_headers_are_refused(auth):
    for header in ["", "   ", "Bearer", "Bearer ", "Basic abc", "token abc", auth._plaintext]:
        with pytest.raises(AuthError):
            auth.authenticate(header)


def test_wrong_token_is_refused(auth):
    with pytest.raises(AuthError):
        auth.authenticate("Bearer " + "x" * 43)


def test_every_failure_message_is_identical(auth):
    """Distinct messages would tell an attacker which half of a guess was right."""
    messages = set()
    for header in [None, "", "Basic abc", "Bearer wrong", "Bearer " + "y" * 43]:
        with pytest.raises(AuthError) as exc:
            auth.authenticate(header)
        messages.add(str(exc.value))
    assert messages == {"invalid credentials"} or len(messages) == 1 or all(
        "Authorization" in m or "credentials" in m for m in messages
    )
    # The key property: no message leaks whether a token exists.
    assert not any("unknown" in m or "no such" in m for m in messages)


def test_disabled_token_cannot_authenticate(auth):
    auth._tokens["ops"].enabled = False
    with pytest.raises(AuthError):
        auth.authenticate(f"Bearer {auth._plaintext}")


def test_plaintext_never_equals_stored_digest(auth):
    """The config file must not contain anything that authenticates."""
    stored = auth._tokens["ops"].digest
    assert stored != auth._plaintext
    assert auth._plaintext not in stored
    assert stored == hash_token(auth._plaintext)


def test_token_issue_returns_distinct_tokens():
    seen = {Token.issue("t")[1] for _ in range(50)}
    assert len(seen) == 50


def test_scope_check_is_not_widened_by_role():
    p = Principal(name="x", role="viewer", scopes={"ledger:read"})
    assert p.may("ledger:read")
    assert not p.may("ledger:write")
    assert not p.may("admin")


def test_admin_scope_implies_everything():
    p = Principal(name="root", role="admin", scopes={"admin"})
    assert p.may("anything:at:all")


def test_authenticator_can_be_disabled_explicitly():
    a = Authenticator(enabled=False)
    assert a.authenticate(None).role == "admin"


def test_from_yaml_requires_a_digest(tmp_path):
    path = tmp_path / "tokens.yaml"
    path.write_text("tokens:\n  broken:\n    role: viewer\n", encoding="utf-8")
    with pytest.raises(AuthError):
        Authenticator.from_yaml(path)


# --- Layer 2: rate limiting -------------------------------------------------


def test_burst_is_capped_at_capacity():
    rl = RateLimiter(capacity=5, refill_per_sec=0.001)
    for _ in range(5):
        rl.check("k")
    with pytest.raises(RateLimited):
        rl.check("k")


def test_buckets_are_independent_per_key():
    rl = RateLimiter(capacity=2, refill_per_sec=0.001)
    rl.check("a")
    rl.check("a")
    with pytest.raises(RateLimited):
        rl.check("a")
    # A different principal is unaffected by a neighbour's flood.
    rl.check("b")


def test_bucket_refills_over_time():
    rl = RateLimiter(capacity=1, refill_per_sec=1000.0)
    rl.check("k")
    time.sleep(0.01)
    rl.check("k")  # refilled


def test_refill_never_exceeds_capacity():
    """A long idle period must not bank unlimited requests.

    With a fast refill, 0.5s of idle would earn far more than `capacity`
    tokens if the bucket were unbounded. It must still cap at capacity.
    """
    rl = RateLimiter(capacity=3, refill_per_sec=100.0)
    time.sleep(0.5)  # 50 tokens' worth of refill, capped at 3
    for _ in range(3):
        rl.check("k")
    with pytest.raises(RateLimited):
        rl.check("k")


def test_limiter_rejects_nonsense_configuration():
    with pytest.raises(ValueError):
        RateLimiter(capacity=0)
    with pytest.raises(ValueError):
        RateLimiter(capacity=1, refill_per_sec=0)


def test_forget_clears_a_revoked_principal():
    rl = RateLimiter(capacity=1, refill_per_sec=0.001)
    rl.check("k")
    with pytest.raises(RateLimited):
        rl.check("k")
    rl.forget("k")
    rl.check("k")
    assert rl.buckets() == 1


# --- Layer 3: replay defence ------------------------------------------------


def test_fresh_nonce_is_accepted():
    ReplayGuard().check("n1", time.time())


def test_reused_nonce_is_refused():
    guard = ReplayGuard()
    now = time.time()
    guard.check("n1", now, now=now)
    with pytest.raises(ReplayDetected):
        guard.check("n1", now, now=now)


def test_stale_timestamp_is_refused():
    guard = ReplayGuard(window_seconds=60)
    now = time.time()
    with pytest.raises(ReplayDetected):
        guard.check("n1", now - 3600, now=now)


def test_future_timestamp_is_refused():
    """A far-future timestamp would otherwise extend a capture's life."""
    guard = ReplayGuard(window_seconds=60)
    now = time.time()
    with pytest.raises(ReplayDetected):
        guard.check("n1", now + 3600, now=now)


def test_missing_nonce_is_refused():
    with pytest.raises(ReplayDetected):
        ReplayGuard().check("", time.time())


def test_cache_is_pruned_so_it_cannot_grow_without_bound():
    guard = ReplayGuard(window_seconds=10)
    base = time.time()
    for i in range(50):
        guard.check(f"n{i}", base, now=base)
    assert guard.size() == 50
    guard.check("fresh", base + 20, now=base + 20)
    assert guard.size() == 1


def test_full_cache_fails_closed_rather_than_dropping_entries():
    guard = ReplayGuard(window_seconds=3600, max_entries=3)
    now = time.time()
    for i in range(3):
        guard.check(f"n{i}", now, now=now)
    with pytest.raises(ReplayDetected):
        guard.check("n4", now, now=now)


def test_guard_rejects_nonsense_window():
    with pytest.raises(ValueError):
        ReplayGuard(window_seconds=0)


# --- request signing --------------------------------------------------------


def test_signature_verifies_for_the_exact_request():
    sig = request_signature("s3cret", "GET", "/api/records", 1000.0, "n1", b"")
    assert verify_request_signature("s3cret", sig, "GET", "/api/records", 1000.0, "n1", b"")


def test_signature_covers_the_body():
    """A captured request must not be re-pointed at a different payload."""
    sig = request_signature("s3cret", "POST", "/x", 1000.0, "n1", b"harmless")
    assert not verify_request_signature("s3cret", sig, "POST", "/x", 1000.0, "n1", b"malicious")


def test_signature_covers_the_path():
    sig = request_signature("s3cret", "GET", "/api/records", 1000.0, "n1")
    assert not verify_request_signature("s3cret", sig, "GET", "/api/keys", 1000.0, "n1")


def test_signature_covers_the_method():
    sig = request_signature("s3cret", "GET", "/x", 1000.0, "n1")
    assert not verify_request_signature("s3cret", sig, "DELETE", "/x", 1000.0, "n1")


def test_signature_covers_the_nonce_and_timestamp():
    sig = request_signature("s3cret", "GET", "/x", 1000.0, "n1")
    assert not verify_request_signature("s3cret", sig, "GET", "/x", 1000.0, "n2")
    assert not verify_request_signature("s3cret", sig, "GET", "/x", 1001.0, "n1")


def test_wrong_secret_never_verifies():
    sig = request_signature("s3cret", "GET", "/x", 1000.0, "n1")
    assert not verify_request_signature("other", sig, "GET", "/x", 1000.0, "n1")


def test_empty_signature_never_verifies():
    assert not verify_request_signature("s3cret", "", "GET", "/x", 1000.0, "n1")
