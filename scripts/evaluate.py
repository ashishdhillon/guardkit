"""Evaluate injection detectors on eval/injection_eval.jsonl. Usage: python scripts/evaluate.py"""
import json, sys
sys.path.insert(0, ".")
from guardkit import InjectionGuard


def load(path="eval/injection_eval.jsonl"):
    return [json.loads(l) for l in open(path, encoding="utf-8")]


def prf(rows, pred):
    tp = sum(1 for r in rows if r["label"] == 1 and pred(r["text"]))
    fp = sum(1 for r in rows if r["label"] == 0 and pred(r["text"]))
    fn = sum(1 for r in rows if r["label"] == 1 and not pred(r["text"]))
    p = tp / (tp + fp) if tp + fp else 0.0
    rc = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * p * rc / (p + rc) if p + rc else 0.0
    return dict(tp=tp, fp=fp, fn=fn, precision=round(p, 3), recall=round(rc, 3), f1=round(f1, 3))


if __name__ == "__main__":
    for name in ("eval/injection_eval.jsonl", "eval/injection_test.jsonl"):
        rows = load(name)
        print(f"{name}: n={len(rows)} (pos={sum(r['label'] for r in rows)})")
        for mode in ("rules", "model", "both"):
            g = InjectionGuard(mode=mode)
            print(" ", mode, prf(rows, lambda t: bool(g.scan(t))))
