"""Layer 4: HTTP security headers. Layer 7: the self-verification posture check.

Why headers are a layer and not an afterthought: the dashboard renders
attacker-influenced text (an agent's action, a target path, an actor name).
If that text is ever interpreted as markup, the auditor's browser runs the
attacker's code with the auditor's session. A strict Content-Security-Policy
turns that class of bug from a compromise into a blocked request, and the
other headers close clickjacking, MIME sniffing, and referrer leakage.

Why the posture check exists: a security layer that is present in the code
but switched off in the deployment is worse than no layer, because it creates
false confidence. `Posture` inspects a live configuration and reports, per
layer, whether it is actually enforcing — so "we have authentication" is
replaced with "authentication is enabled, 3 tokens, 0 without a digest".
"""

from __future__ import annotations

from dataclasses import dataclass, field

# A deny-by-default CSP. `'unsafe-inline'` is present for the dashboard's
# inline script; a deployment serving the JS as a separate file can drop it.
# Everything not named here is refused, which is what makes this useful
# against an injected tag.
CSP = (
    "default-src 'none'; "
    "script-src 'self' 'unsafe-inline'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "font-src 'self'; "
    "base-uri 'none'; "
    "form-action 'none'; "
    "frame-ancestors 'none'; "
    "object-src 'none'"
)

SECURITY_HEADERS: dict[str, str] = {
    "Content-Security-Policy": CSP,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=(), payment=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cache-Control": "no-store",
}

# Only sent when the dashboard is reached over TLS; sending HSTS over plain
# HTTP is meaningless and can break a local deployment.
HSTS = {"Strict-Transport-Security": "max-age=63072000; includeSubDomains"}


def headers_for(secure: bool = False) -> dict[str, str]:
    headers = dict(SECURITY_HEADERS)
    if secure:
        headers.update(HSTS)
    return headers


@dataclass
class LayerStatus:
    layer: str
    enforcing: bool
    detail: str

    def describe(self) -> str:
        mark = "ON " if self.enforcing else "OFF"
        return f"[{mark}] {self.layer}: {self.detail}"


@dataclass
class Posture:
    """The result of inspecting a live deployment's defences."""

    layers: list[LayerStatus] = field(default_factory=list)

    @property
    def enforcing(self) -> int:
        return sum(1 for layer in self.layers if layer.enforcing)

    @property
    def total(self) -> int:
        return len(self.layers)

    @property
    def score(self) -> float:
        return round(100.0 * self.enforcing / self.total, 1) if self.total else 0.0

    @property
    def fully_hardened(self) -> bool:
        return self.enforcing == self.total

    def gaps(self) -> list[LayerStatus]:
        return [layer for layer in self.layers if not layer.enforcing]

    def describe(self) -> str:
        lines = [f"posture: {self.enforcing}/{self.total} layers enforcing ({self.score}/100)"]
        lines += [f"  {layer.describe()}" for layer in self.layers]
        for gap in self.gaps():
            lines.append(f"  gap: {gap.layer} — {gap.detail}")
        return "\n".join(lines)
