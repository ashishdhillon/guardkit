"""Load a YAML policy into a Pipeline.

input:
  - {guard: injection, action: block}
  - {guard: pii, action: redact, types: [email, aadhaar]}
output:
  - {guard: secrets, action: redact}
"""
from typing import Any, Dict

import yaml

from .pipeline import GUARDS, Pipeline, Stage


def _stage(entries) -> Stage:
    items = []
    for e in entries or []:
        e = dict(e)
        name = e.pop("guard", None)
        action = e.pop("action", "block")
        if name not in GUARDS:
            raise ValueError(f"unknown guard {name!r}; choose from {sorted(GUARDS)}")
        items.append((GUARDS[name](**e), action))
    return Stage(items)


def from_dict(cfg: Dict[str, Any]) -> Pipeline:
    unknown = set(cfg) - {"input", "output"}
    if unknown:
        raise ValueError(f"unknown policy keys: {sorted(unknown)}")
    return Pipeline(_stage(cfg.get("input")), _stage(cfg.get("output")))


def load(path: str) -> Pipeline:
    with open(path, "r", encoding="utf-8") as fh:
        return from_dict(yaml.safe_load(fh) or {})
