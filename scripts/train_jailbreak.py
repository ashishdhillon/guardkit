"""Train + evaluate the user-prompt jailbreak classifier on the public in-the-wild dataset
(Shen et al., CCS 2024, MIT).  Temporal split: train on earlier prompts, test on later ones;
test items whose normalised prefix appears in train are dropped (leakage control).
Run: python -I scripts/train_jailbreak.py JAILBREAK_CSV REGULAR_CSV"""
import csv, json, math, random, re, sys
from guardkit import InjectionGuard
from guardkit.classifier import LogReg, featurize

csv.field_size_limit(10 ** 8)
jb_path, reg_path = sys.argv[1], sys.argv[2]


def load(path, label):
    return [(r["created_at"], r["prompt"], label) for r in csv.DictReader(open(path, encoding="utf-8")) if r["prompt"].strip()]


def key(t):
    return re.sub(r"\s+", " ", t.casefold()).strip()[:300]


rows = load(jb_path, 1) + load(reg_path, 0)
rows.sort(key=lambda r: r[0])
jb_dates = sorted(r[0] for r in rows if r[2] == 1)
cut = jb_dates[int(0.65 * len(jb_dates))]               # 65% of jailbreaks fall before the cut
train, test, seen = [], [], set()
for d, t, y in rows:
    if d < cut and key(t) not in seen:
        seen.add(key(t)); train.append((t, y))
test_seen = set()
for d, t, y in rows:
    if d >= cut and key(t) not in seen and key(t) not in test_seen:
        test_seen.add(key(t)); test.append((t, y))
print("cut", cut[:10], "| train", len(train), sum(y for _, y in train), "jb | test", len(test), sum(y for _, y in test), "jb")

R = random.Random(0)
neg = [r for r in train if r[1] == 0]; pos = [r for r in train if r[1] == 1]
R.shuffle(neg)
fit = pos + neg[: 4 * len(pos)]                         # 1:4 positive:negative
data = [(featurize(t), y) for t, y in fit]
w, b, lr, l2 = {}, 0.0, 0.5, 1e-5
for epoch in range(12):
    R.shuffle(data)
    for x, y in data:
        z = b + sum(w.get(i, 0.0) * v for i, v in x.items())
        g = 1 / (1 + math.exp(-max(min(z, 30), -30))) - y
        for i, v in x.items():
            w[i] = w.get(i, 0.0) * (1 - lr * l2) - lr * g * v
        b -= lr * g
    lr *= 0.85
m = LogReg(w, b)
# operating threshold fixed on TRAIN negatives only: score exceeded by 1% of them
tr_neg_scores = sorted(m.score(t) for t, y in train if y == 0)
thr1 = tr_neg_scores[int(0.99 * len(tr_neg_scores))]
m.save("guardkit/data/jailbreak_lr.json")
print("threshold for 1% train FPR:", round(thr1, 3))


def metrics(pred):
    tp = sum(1 for t, y in test if y and pred(t)); fp = sum(1 for t, y in test if not y and pred(t))
    P = sum(y for _, y in test); N = len(test) - P
    prec = tp / (tp + fp) if tp + fp else 0.0
    return dict(recall=round(tp / P, 3), fpr=round(fp / N, 4), precision=round(prec, 3), tp=tp, fp=fp)


sc = {t: m.score(t) for t, _ in test}
res = {"split": dict(cut=cut[:10], train=len(train), test=len(test), test_jb=sum(y for _, y in test))}
res["classifier @0.5"] = metrics(lambda t: sc[t] >= 0.5)
res["classifier @1% train-FPR"] = metrics(lambda t: sc[t] >= thr1)
rg = InjectionGuard(mode="rules")
res["regex rules"] = metrics(lambda t: bool(rg.scan(t)))
# AUC
pos_s = [sc[t] for t, y in test if y]; neg_s = [sc[t] for t, y in test if not y]
from bisect import bisect_left
ns = sorted(neg_s); auc = sum(bisect_left(ns, p) / len(ns) for p in pos_s) / len(pos_s)
res["classifier AUC"] = round(auc, 3)
print(json.dumps(res, indent=1))
json.dump(res, open("results_jailbreak.json", "w"), indent=1)
