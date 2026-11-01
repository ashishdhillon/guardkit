"""Rule-based prompt-injection / jailbreak detector. Text is normalised first
(NFKC, zero-width and control characters removed, case folded) so simple
obfuscation does not bypass the rules."""
import re
import unicodedata
from typing import List

from .core import Finding, Guard

_ZW = dict.fromkeys(map(ord, "​‌‍⁠﻿­"), None)

# (rule name, regex, weight)
_RULES = [
    ("override_previous", r"\b(?:ignore|disregard|forget|override|bypass)\b.{0,30}\b(?:previous|prior|above|earlier|all|any|your)\b.{0,20}\b(?:instructions?|rules?|prompts?|guidelines?|directions?)\b", 1.0),
    ("set_aside_guidance", r"\bset aside\b.{0,30}\b(?:instructions?|guidance|rules?)\b", 0.8),
    ("reveal_system_prompt", r"\b(?:reveal|show|print|output|repeat|leak|display)\b.{0,25}\b(?:system|hidden|initial|original)\b.{0,10}\b(?:prompt|instructions?|message)\b", 1.0),
    ("role_override", r"\byou are (?:now|no longer)\b.{0,40}\b(?:dan|developer mode|jailbroken|unrestricted|without (?:any )?restrictions?)\b", 1.0),
    ("developer_mode", r"\b(?:developer|debug|god|sudo) mode\b", 0.7),
    ("system_override_tag", r"(?:\bsystem\s*(?:override|prompt)\s*:|\[\s*system\s*\]|<\s*/?\s*system\s*>)", 0.9),
    ("exfiltrate", r"\b(?:send|forward|post|upload|email|transmit)\b.{0,40}\b(?:conversation|chat history|history|credentials?|passwords?|api keys?|secrets?|emails?)\b.{0,30}\b(?:to|at)\b.{0,30}(?:https?://|@|\.com|\.example)", 1.0),
    ("hide_from_user", r"\b(?:do not|don't|never)\b.{0,20}\b(?:mention|tell|inform|reveal|notify)\b.{0,20}\b(?:this|it)\b.{0,15}\b(?:to the user|to the human|to anyone)\b", 0.9),
    ("new_priority", r"\b(?:new|updated|important)\b.{0,15}\b(?:priority )?instructions?\b.{0,25}\b(?:from|for)\b.{0,25}\b(?:admin|administrator|developer|system|assistant|ai)\b", 0.8),
    ("pay_no_attention", r"\bpay no attention to\b.{0,30}\b(?:rules?|instructions?|above|previous)\b", 0.9),
]
_COMPILED = [(n, re.compile(p, re.S), w) for n, p, w in _RULES]


def normalise(text: str) -> str:
    t = unicodedata.normalize("NFKC", text).translate(_ZW)
    t = "".join(ch for ch in t if ch in "\n\t " or unicodedata.category(ch)[0] != "C")
    return t.casefold()


class InjectionGuard(Guard):
    name = "injection"

    def __init__(self, threshold: float = 0.8, mode: str = "both", model_threshold: float = 0.5):
        """mode: 'rules' (regex rules only), 'model' (trained classifier only) or 'both' (either fires)."""
        if mode not in ("rules", "model", "both"):
            raise ValueError("mode must be rules, model or both")
        self.threshold, self.mode, self.model_threshold = threshold, mode, model_threshold
        self._model = None
        if mode != "rules":
            from .classifier import LogReg
            self._model = LogReg.load()

    def scan(self, text: str) -> List[Finding]:
        out: List[Finding] = []
        if self._model is not None:
            sc = self._model.score(text)
            if sc >= self.model_threshold:
                out.append(Finding("injection", "classifier", 0, len(text), text, score=round(sc, 3)))
            if self.mode == "model":
                return out
        norm = normalise(text)
        # normalisation can change length (NFKC); only keep spans when lengths match
        same_len = len(norm) == len(text)
        for name, rx, weight in _COMPILED:
            m = rx.search(norm)
            if m and weight >= self.threshold:
                s, e = (m.start(), m.end()) if same_len else (0, len(text))
                out.append(Finding("injection", name, s, e, text[s:e], score=weight))
        return out
