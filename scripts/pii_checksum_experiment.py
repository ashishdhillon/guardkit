"""How much do checksums cut false positives? (a) random digit strings, (b) real prompts.
Usage: python -I scripts/pii_checksum_experiment.py [CSV ...]"""
import csv, json, random, re, sys
from guardkit import pii

R = random.Random(0)
N = 200_000
out = {}
a = [str(R.randint(2, 9)) + "".join(R.choice("0123456789") for _ in range(11)) for _ in range(N)]
out["random 12-digit strings passing Verhoeff (Aadhaar)"] = round(sum(pii.verhoeff_valid(x) for x in a) / N, 4)
c = ["".join(R.choice("0123456789") for _ in range(16)) for _ in range(N)]
out["random 16-digit strings passing Luhn (card)"] = round(sum(pii.luhn_valid(x) for x in c) / N, 4)
# genuinely valid numbers are always kept
good = [x[:11] + pii.verhoeff_check_digit(x[:11]) for x in a[:5000]]
out["generated valid Aadhaar kept"] = sum(bool(pii.PIIGuard(["aadhaar"]).scan(x)) for x in good) / len(good)

csv.field_size_limit(10 ** 8)
texts = []
for p in sys.argv[1:]:
    texts += [r["prompt"] for r in csv.DictReader(open(p, encoding="utf-8"))]
g_all = pii.PIIGuard(["aadhaar", "card"])
raw_a = sum(len(pii._AADHAAR.findall(t)) for t in texts)
raw_c = sum(len([m for m in pii._CARD.finditer(t) if 13 <= len(re.sub(r"\D", "", m.group())) <= 19]) for t in texts)
val = {"aadhaar": 0, "card": 0}
for t in texts:
    for f in g_all.scan(t):
        val[f.rule] += 1
out["real prompts (n=%d): 12-digit regex matches / after Verhoeff" % len(texts)] = [raw_a, val["aadhaar"]]
out["real prompts: 13-19-digit regex matches / after Luhn"] = [raw_c, val["card"]]
print(json.dumps(out, indent=1))
json.dump(out, open("results_pii_checksum.json", "w"), indent=1)
