"""Pipeline: run configured guards on text and apply block / redact / warn actions."""
from typing import Dict, List, Optional, Tuple

from .core import ACTION_RANK, Finding, Guard, Result
from .pii import PIIGuard
from .secrets import SecretsGuard
from .injection import InjectionGuard
from .content import TopicGuard, JSONGuard

GUARDS = {"pii": PIIGuard, "secrets": SecretsGuard, "injection": InjectionGuard,
          "topics": TopicGuard, "json": JSONGuard}


class Stage:
    """An ordered list of (guard, action)."""

    def __init__(self, items: List[Tuple[Guard, str]]):
        for _, a in items:
            if a not in ("block", "redact", "warn"):
                raise ValueError(f"invalid action: {a}")
        self.items = items

    def run(self, text: str) -> Result:
        findings: List[Finding] = []
        for guard, action in self.items:
            for f in guard.scan(text):
                findings.append(Finding(f.guard, f.rule, f.start, f.end, f.text, f.score, action))
        findings.sort(key=lambda f: (f.start, -(f.end - f.start)))
        worst = max((ACTION_RANK[f.action] for f in findings), default=0)
        action = {v: k for k, v in ACTION_RANK.items()}[worst]
        return Result(action, _redact(text, findings) if action != "block" else text, findings)


def _redact(text: str, findings: List[Finding]) -> str:
    spans = [(f.start, f.end, f"[REDACTED:{f.rule.upper()}]") for f in findings if f.action == "redact"]
    out, pos = [], 0
    for s, e, label in sorted(spans):
        if s < pos:          # overlapping/contained span already covered
            continue
        out.append(text[pos:s]); out.append(label); pos = e
    out.append(text[pos:])
    return "".join(out)


class Pipeline:
    def __init__(self, input_stage: Optional[Stage] = None, output_stage: Optional[Stage] = None):
        self.input = input_stage or Stage([])
        self.output = output_stage or Stage([])

    def check_input(self, text: str) -> Result:
        return self.input.run(text)

    def check_output(self, text: str) -> Result:
        return self.output.run(text)
