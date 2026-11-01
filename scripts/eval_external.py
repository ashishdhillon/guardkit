"""Evaluate guardkit's injection guard on the public in-the-wild jailbreak dataset
(Shen et al., CCS 2024; MIT; github.com/verazuo/jailbreak_llms).
Usage: python -I scripts/eval_external.py JAILBREAK_CSV REGULAR_CSV
Treats the downloaded CSVs as data only."""
import csv, json, sys, time
from guardkit import InjectionGuard

csv.field_size_limit(10 ** 8)
jb_path, reg_path = sys.argv[1], sys.argv[2]
jb = [r["prompt"] for r in csv.DictReader(open(jb_path, encoding="utf-8"))]
reg = [r["prompt"] for r in csv.DictReader(open(reg_path, encoding="utf-8"))]
print(f"jailbreak n={len(jb)}  regular n={len(reg)}")
out = {}
for mode in ("rules", "model", "both"):
    g = InjectionGuard(mode=mode)
    t0 = time.time()
    tp = sum(1 for t in jb if g.scan(t))
    fp = sum(1 for t in reg if g.scan(t))
    dt = time.time() - t0
    prec = tp / (tp + fp) if tp + fp else 0
    rec = tp / len(jb)
    out[mode] = dict(recall=round(rec, 3), fpr=round(fp / len(reg), 4), precision_at_this_mix=round(prec, 3),
                     tp=tp, fp=fp, ms_per_prompt=round(1000 * dt / (len(jb) + len(reg)), 2))
    print(mode, out[mode])
json.dump(out, open("results_external.json", "w"), indent=1)
