"""Detect credentials and API keys (well-known formats + private key blocks)."""
import math
import re
from collections import Counter
from typing import List

from .core import Finding, Guard

_RULES = {
    "aws_access_key": re.compile(r"(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])"),
    "github_token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    "slack_token": re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
    "google_api_key": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    "stripe_key": re.compile(r"\b[sr]k_(?:live|test)_[0-9A-Za-z]{16,}\b"),
    "private_key": re.compile(r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
}
_ASSIGN = re.compile(
    r"(?i)\b(?:api[_-]?key|secret|token|passwd|password)\b\s*[:=]\s*['\"]?([A-Za-z0-9_\-/+=]{16,})['\"]?")


def _entropy(s: str) -> float:
    c = Counter(s)
    return -sum(v / len(s) * math.log2(v / len(s)) for v in c.values())


class SecretsGuard(Guard):
    name = "secrets"

    def __init__(self, min_entropy: float = 3.0):
        self.min_entropy = min_entropy

    def scan(self, text: str) -> List[Finding]:
        out: List[Finding] = []
        for rule, rx in _RULES.items():
            for m in rx.finditer(text):
                out.append(Finding("secrets", rule, m.start(), m.end(), m.group()))
        for m in _ASSIGN.finditer(text):
            val = m.group(1)
            if _entropy(val) >= self.min_entropy:
                out.append(Finding("secrets", "generic_assignment", m.start(1), m.end(1), val))
        return out
