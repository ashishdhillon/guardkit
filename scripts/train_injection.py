"""Train the logistic-regression injection classifier (pure Python SGD)."""
import json, math, random, sys
sys.path.insert(0, ".")
from guardkit.classifier import LogReg, featurize

rows = [json.loads(l) for l in open("eval/train_injection.jsonl", encoding="utf-8")]
data = [(featurize(r["text"]), r["label"]) for r in rows]
R = random.Random(0)
w, b, lr, l2 = {}, 0.0, 0.8, 1e-5
for epoch in range(30):
    R.shuffle(data)
    for x, y in data:
        z = b + sum(w.get(i, 0.0) * v for i, v in x.items())
        p = 1 / (1 + math.exp(-max(min(z, 30), -30)))
        g = p - y
        for i, v in x.items():
            w[i] = w.get(i, 0.0) * (1 - lr * l2) - lr * g * v
        b -= lr * g
    lr *= 0.9
LogReg(w, b).save("guardkit/data/injection_lr.json")
print("trained; nonzero weights:", len(w))
