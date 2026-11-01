"""Tiny dependency-free text classifier: hashed word uni/bi-grams + logistic regression.
Weights ship in guardkit/data/injection_lr.json (trained by scripts/train_injection.py)."""
import json
import math
import os
import re
import zlib

from .injection import normalise

DIM = 1 << 16
_TOK = re.compile(r"[^\W_]+(?:'[a-z]+)?", re.U)


def featurize(text: str):
    toks = _TOK.findall(normalise(text))
    feats = {}
    grams = toks + [a + " " + b for a, b in zip(toks, toks[1:])]
    for g in grams:
        i = zlib.crc32(g.encode("utf-8")) % DIM
        feats[i] = feats.get(i, 0.0) + 1.0
    norm = math.sqrt(sum(v * v for v in feats.values())) or 1.0
    return {i: v / norm for i, v in feats.items()}


class LogReg:
    def __init__(self, w=None, b=0.0):
        self.w = w or {}
        self.b = b

    def score(self, text: str) -> float:
        z = self.b + sum(self.w.get(i, 0.0) * v for i, v in featurize(text).items())
        return 1.0 / (1.0 + math.exp(-max(min(z, 30), -30)))

    def save(self, path):
        with open(path, "w") as fh:
            json.dump({"dim": DIM, "b": self.b, "w": {str(k): round(v, 5) for k, v in self.w.items() if abs(v) > 1e-4}}, fh)

    @classmethod
    def load(cls, path=None):
        path = path or os.path.join(os.path.dirname(__file__), "data", "injection_lr.json")
        with open(path) as fh:
            d = json.load(fh)
        assert d["dim"] == DIM
        return cls({int(k): v for k, v in d["w"].items()}, d["b"])
