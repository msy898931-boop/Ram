"""Layer 1-5: authentication, federated identity, rate limiting, replay
defence, and transport encryption.

AXON's policy engine decides what an *agent* may do. This package decides who
may reach AXON at all, how often, and over what transport. The two are
deliberately separate: the authenticator runs before the router, so no policy
rule — and no ledger endpoint — is reachable by an unauthenticated caller.

The primitives here are implemented on the standard library alone, matching
the rest of the project, and every one of them is exercised by an adversarial
test rather than a happy-path test. The OIDC verifier is the one exception to
"standard library only": it hand-rolls RSASSA-PKCS1-v1_5 verification rather
than depending on a JWT library, and cross-checks itself against
`cryptography` in the tests.
"""
