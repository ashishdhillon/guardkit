"""Core types: Finding, Result, Guard base class."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

ACTION_RANK = {"allow": 0, "warn": 1, "redact": 2, "block": 3}


@dataclass(frozen=True)
class Finding:
    guard: str          # e.g. "pii"
    rule: str           # e.g. "aadhaar"
    start: int
    end: int
    text: str
    score: float = 1.0
    action: str = "warn"  # filled in by the pipeline from the policy

    def to_dict(self):
        return {"guard": self.guard, "rule": self.rule, "start": self.start,
                "end": self.end, "score": self.score, "action": self.action}


@dataclass
class Result:
    action: str                     # allow | warn | redact | block
    text: str                       # text after redaction (original if none)
    findings: List[Finding] = field(default_factory=list)

    @property
    def blocked(self) -> bool:
        return self.action == "block"

    def to_dict(self, include_text: bool = True):
        d = {"action": self.action, "findings": [f.to_dict() for f in self.findings]}
        if include_text:
            d["text"] = self.text
        return d


class Guard:
    """A guard inspects text and returns findings. Subclasses set `name`."""
    name = "guard"

    def scan(self, text: str) -> List[Finding]:  # pragma: no cover - interface
        raise NotImplementedError
