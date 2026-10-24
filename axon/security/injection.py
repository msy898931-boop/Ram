# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 msy898931-boop
# Part of the AXON open core. See NOTICE for the license map.
"""Layer 9: detection of prompt injection and agent-goal hijacking.

Why this layer matters more than the network ones: an agent that reads a
web page, an issue, a PDF, or a tool result is consuming *attacker-reachable
text*. The attacker does not need to break into the host; they need the agent
to read one sentence and act on it. Classic perimeter security does not see
that sentence at all.

The honest framing: this is **detection, not prevention**. A detector that
claims to catch every injection is lying. Language is unbounded and a
determined attacker will find a phrasing that slips through. What this buys:

  * known attack shapes are caught and attributed, so the attempt is visible
    in the ledger rather than silently succeeding;
  * a positive detection can escalate to a hard denial through policy;
  * the score is a signal an operator can tune, not a binary guarantee.

Everything here is deliberately explainable: each finding names the pattern
that fired and the text that matched, so a security team can audit why a
result was flagged instead of trusting a black box.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field


@dataclass
class Finding:
    """One suspicious pattern, with the evidence that triggered it."""

    kind: str
    severity: str  # "low" | "medium" | "high"
    pattern: str
    evidence: str
    offset: int

    def describe(self) -> str:
        return f"[{self.severity}] {self.kind}: matched {self.pattern!r} at {self.offset}"


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    text: str = ""
    score: float = 0.0
    truncated: bool = False

    @property
    def suspicious(self) -> bool:
        return bool(self.findings)

    @property
    def worst(self) -> str:
        order = {"low": 0, "medium": 1, "high": 2}
        return max((f.severity for f in self.findings), key=lambda s: order[s], default="none")

    def by_kind(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.kind] = counts.get(f.kind, 0) + 1
        return counts


# Severity weights used to fold findings into a single score. These are
# deliberately conservative: it is better to under-score a real attack than to
# let a benign string look like a certainty.
_WEIGHT = {"low": 0.15, "medium": 0.4, "high": 0.9}

# Invisible and bidirectional control characters. These have no legitimate
# reason to appear in tool output and are a known way to smuggle instructions
# past a human reviewer reading the same text.
_INVISIBLE = {
    "\u200b", "\u200c", "\u200d", "\u2060", "\ufeff",
    "\u202a", "\u202b", "\u202c", "\u202d", "\u202e",
    "\u2066", "\u2067", "\u2068", "\u2069",
}

_INJECTION_PATTERNS: list[tuple[str, str, str]] = [
    # (kind, severity, regex)
    ("instruction_override", "high",
     r"\b(ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}\b"
     r"(previous|prior|above|earlier|all|any|your)\b[^.\n]{0,30}\b"
     r"(instruction|rule|prompt|direction|guideline|constraint)s?\b"),
    ("instruction_override", "high",
     r"\b(new|updated|revised)\s+(instruction|rule|system\s+prompt|directive)s?\s*[:\-]"),
    ("role_hijack", "high",
     r"\byou\s+are\s+(now|no\s+longer)\b"),
    ("role_hijack", "medium",
     r"\b(act|behave|pretend|respond)\s+(as|like)\s+(if\s+you\s+are\s+)?"
     r"(an?\s+)?(unrestricted|unfiltered|jailbroken|different|new)\b"),
    ("system_prompt_leak", "high",
     r"\b(reveal|show|print|output|repeat|dump|expose)\b[^.\n]{0,30}\b"
     r"(system\s+prompt|initial\s+prompt|your\s+instructions|hidden\s+rules|developer\s+message)\b"),
    ("secret_exfiltration", "high",
     r"\b(send|post|upload|exfiltrate|leak|email|forward|curl|wget|share)\b[^.\n]{0,60}\b"
     r"(api[\s_-]?key|secret|token|password|credential|private[\s_-]?key|"
     r"id_rsa|ssh[\s_-]?key|env[\s_-]?file|keychain)\b"),
    # Separate pattern: a leading `\b` cannot precede a literal dot, so the
    # dotfile alternatives need their own boundary-free prefix.
    ("secret_exfiltration", "high",
     r"\b(send|post|upload|exfiltrate|leak|email|forward|curl|wget|share)\b[^.\n]{0,60}"
     r"(\.env\b|\.pem\b|\.ssh\b|/etc/passwd|\.aws/credentials)"),
    ("secret_exfiltration", "high",
     r"\b(api[\s_-]?key|secret|password|credential)s?\b[^.\n]{0,40}\b"
     r"(to|at|via)\s+(https?://|[\w.-]+@)"),
    ("tool_abuse", "high",
     r"\b(delete|drop|truncate|rm\s+-rf|format|wipe|destroy)\b[^.\n]{0,40}\b"
     r"(all|every|entire|database|table|backup|repository|repo)s?\b"),
    ("tool_abuse", "medium",
     r"\b(run|execute|exec|invoke|call)\b[^.\n]{0,30}\b"
     r"(shell|bash|cmd|powershell|eval|system)\b"),
    ("privilege_escalation", "high",
     r"\b(grant|give|escalate|elevate|assign)\b[^.\n]{0,30}\b"
     r"(admin|root|sudo|superuser|owner|unrestricted)\b[^.\n]{0,20}\b"
     r"(access|role|permission|privilege|rights)?\b"),
    ("policy_bypass", "high",
     r"\b(disable|turn\s+off|remove|skip|ignore|bypass|circumvent|evade|get\s+around)\b[^.\n]{0,30}\b"
     r"(policy|policies|guardrail|safety|filter|approval|audit|logging|monitoring|"
     r"requirement|restriction|control|check)\b"),
    ("delimiter_spoof", "medium",
     r"(<\|?(system|assistant|user|im_start|im_end)\|?>|\[/?INST\]|###\s*System\s*:)"),
    ("delimiter_spoof", "medium",
     r"^\s*(system|assistant)\s*:\s*",),
    ("authority_claim", "medium",
     r"\b(I\s+am|this\s+is)\s+(the\s+)?(developer|administrator|admin|owner|operator|anthropic|openai)\b"),
    ("urgency_pressure", "low",
     r"\b(urgent|immediately|right\s+now|before\s+you\s+(continue|proceed))\b[^.\n]{0,40}\b"
     r"(must|need|have\s+to|required?)\b"),
]

_COMPILED: list[tuple[str, str, re.Pattern[str]]] = [
    (kind, sev, re.compile(rx, re.IGNORECASE | re.MULTILINE))
    for kind, sev, rx in _INJECTION_PATTERNS
]

# A destructive verb preceded by a negation is usually description, not an
# order: "we must *not* delete the database" is a policy statement, not an
# attack. Without this guard the most security-conscious documents in a
# corpus are the ones that get quarantined.
_NEGATIONS = re.compile(
    r"\b(not|never|no|don'?t|doesn'?t|won'?t|shouldn'?t|cannot|can'?t|mustn'?t|"
    r"avoid|prevent|forbid|prohibit|without)\b[^.\n]{0,25}$",
    re.IGNORECASE,
)

# Only these kinds are destructive-verb patterns where negation flips meaning.
_NEGATION_AWARE = {"tool_abuse", "policy_bypass"}


def _is_negated(text: str, start: int) -> bool:
    """True when a negation appears in the clause immediately before `start`."""
    window = text[max(0, start - 40):start]
    return bool(_NEGATIONS.search(window))



def normalise(text: str) -> str:
    """Fold away tricks that hide a phrase from a naive matcher.

    NFKC collapses full-width and mathematical-alphabet lookalikes onto their
    ASCII forms, and case-folding makes matching case-insensitive in one place
    rather than in every pattern.
    """
    return unicodedata.normalize("NFKC", text).casefold()


def scan(text: str, max_chars: int = 200_000) -> ScanResult:
    """Scan untrusted text for injection and exfiltration shapes.

    `max_chars` bounds the work: an attacker who can hand the agent a
    gigabyte of text should not be able to stall the scanner. When the input
    is longer, it is truncated and the result says so rather than silently
    reporting a clean bill of health for the part it never looked at.
    """
    truncated = len(text) > max_chars
    body = text[:max_chars]
    folded = normalise(body)

    findings: list[Finding] = []

    for kind, severity, pattern in _COMPILED:
        for match in pattern.finditer(folded):
            if kind in _NEGATION_AWARE and _is_negated(folded, match.start()):
                continue
            findings.append(Finding(
                kind=kind,
                severity=severity,
                pattern=pattern.pattern,
                evidence=body[max(0, match.start() - 20):match.end() + 20].strip(),
                offset=match.start(),
            ))

    for index, char in enumerate(body):
        if char in _INVISIBLE:
            findings.append(Finding(
                kind="invisible_characters",
                severity="medium",
                pattern=f"U+{ord(char):04X}",
                evidence=f"invisible {unicodedata.name(char, 'unknown')}",
                offset=index,
            ))

    score = min(1.0, sum(_WEIGHT[f.severity] for f in findings))
    return ScanResult(findings=findings, text=body, score=round(score, 3), truncated=truncated)


def verdict(result: ScanResult, threshold: float = 0.4) -> str:
    """Fold a score into the three-state answer the runtime consumes.

    Three states rather than two, because "quarantine for review" is a real
    outcome: silently proceeding is wrong, and hard-failing on every
    suspicious-looking document would make the system unusable.
    """
    if not result.findings:
        return "allow"
    if result.score >= threshold or result.worst == "high":
        return "deny"
    return "review"
