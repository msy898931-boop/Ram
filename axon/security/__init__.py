"""Layer 1-3: authentication, rate limiting, and replay defence.

AXON's policy engine decides what an *agent* may do. This package decides who
may reach AXON at all, and how often. The two are deliberately separate: the
authenticator runs before the router, so no policy rule — and no ledger
endpoint — is reachable by an unauthenticated caller.

The primitives here are implemented on the standard library alone, matching
the rest of the project, and every one of them is exercised by an adversarial
test rather than a happy-path test.
"""
