"""Topic restriction and JSON-schema-lite output validation."""
import json
import re
from typing import Dict, Iterable, List, Optional

from .core import Finding, Guard


class TopicGuard(Guard):
    """Flags text matching any banned keyword/regex (case-insensitive)."""
    name = "topics"

    def __init__(self, banned: Iterable[str]):
        self._rx = [(b, re.compile(r"\b" + re.escape(b) + r"\b", re.I)) for b in banned]

    def scan(self, text: str) -> List[Finding]:
        out = []
        for word, rx in self._rx:
            for m in rx.finditer(text):
                out.append(Finding("topics", word, m.start(), m.end(), m.group()))
        return out


_TYPES = {"string": str, "number": (int, float), "integer": int, "boolean": bool, "array": list, "object": dict}


class JSONGuard(Guard):
    """Requires the text to be a JSON object with required keys and basic types."""
    name = "json"

    def __init__(self, required: Optional[Iterable[str]] = None, types: Optional[Dict[str, str]] = None):
        self.required = list(required or [])
        self.types = dict(types or {})
        bad = set(self.types.values()) - set(_TYPES)
        if bad:
            raise ValueError(f"unknown JSON types: {sorted(bad)}")

    def scan(self, text: str) -> List[Finding]:
        def f(rule, detail=""):
            return [Finding("json", rule, 0, len(text), detail or text[:40])]
        try:
            obj = json.loads(text)
        except ValueError:
            return f("invalid_json")
        if not isinstance(obj, dict):
            return f("not_object")
        out = []
        for k in self.required:
            if k not in obj:
                out += f("missing_key", k)
        for k, t in self.types.items():
            if k in obj:
                ok = isinstance(obj[k], _TYPES[t]) and not (t in ("number", "integer") and isinstance(obj[k], bool))
                if not ok:
                    out += f("wrong_type", k)
        return out
