# Author-Written Test Sets Overstate Lightweight Prompt-Injection Detectors: A Case Study with an Offline Guardrail Toolkit

Ashish Dhillon, [Affiliation], dhillon.ashish15@gmail.com
Draft, 1 November 2026. Code: github.com/ashishdhillon/guardkit (MIT). Package: `pip install guardkit`.

## Abstract

Lightweight, dependency-free guardrails for LLM applications are attractive because they run offline and add under two milliseconds per request. We study how reliably such a detector's headline numbers transfer. We built guardkit, an open-source toolkit with rule-based and logistic-regression prompt-injection detectors plus checksum-validated PII detection. On two hand-written evaluation sets, the detector reaches precision 0.94 and recall 0.67 on unseen phrasings (recall 0.85 on a development set). On a public in-the-wild jailbreak dataset (15,140 prompts, 1,405 jailbreaks) the same family of detectors is much weaker: trained on the earlier 65% of the data and tested on the later part, a bag-of-words classifier reaches AUC 0.74, recall 0.42 at a 12.6% false-positive rate, or recall 0.20 at 3.3%. Regular expressions reach recall 0.05. We also find that 5.2% of the dataset's benign prompts contain the literal phrase "ignore all previous instructions", which makes that phrase an unreliable signal in user prompts even though it is a strong signal in third-party documents. Separately, checksum validation (Luhn for cards, Verhoeff for India's Aadhaar numbers) removes about 90% of false positives on random digit strings, and reduced 166 card-shaped strings found in real prompts to 9. We argue that evaluations of lightweight detectors should use external, time-split data and report operating points at fixed false-positive rates.

## 1. Introduction

Guardrails for LLM applications sit before and after the model to block prompt injection, redact personal data and keep secrets out of responses. Many deployments want a first layer that is fast, deterministic and runs without a model download or API call. Rule sets and small linear classifiers meet that need, but they are usually validated on examples written by their authors. Such examples share vocabulary with the rules and with the training data, so they can overstate how the detector behaves on real traffic.

This report documents one such tool, guardkit, and measures the gap directly. Our contributions are modest and empirical:

1. An open-source, zero-ML-dependency toolkit with a trained classifier shipped as a 60 KB JSON file.
2. A measurement of the gap between author-written and external, time-split evaluation for the same detector family.
3. An observation about label semantics: a phrase that signals an attack inside a retrieved document is common in benign user-prompt templates.
4. A small measurement of how much checksum validation reduces false positives in PII detection.

## 2. The toolkit

guardkit applies configurable guards to input and output text and takes one of three actions per guard: block, redact or warn. Policies are written in YAML. The guards are:

- **PII:** email, phone numbers (India and international), payment cards validated with the Luhn algorithm, Aadhaar numbers validated with the Verhoeff algorithm, PAN, IPv4, US SSN and PIN codes. Cue-based name and address heuristics are opt-in.
- **Secrets:** well-known credential formats and high-entropy `key=value` assignments.
- **Injection:** (a) ten regular-expression rules applied after Unicode normalisation (NFKC, zero-width removal, case folding); (b) a logistic-regression classifier over hashed word unigrams and bigrams (65,536 buckets) implemented in pure Python. Two classifiers ship: `injection`, trained on 2,800 synthetic template examples, and `jailbreak`, trained on public data (Section 3).
- **Topics and JSON:** banned keywords and output schema checks.

## 3. Evaluation setup

**Author-written sets.** We wrote two labelled sets of short texts. The development set (149 examples, 75 attacks) was used while building the system and is therefore optimistic. The held-out set (102 examples, 51 attacks, 51 benign) was written after training data generation and evaluated once before a single data-bug fix (a padding phrase that appeared only in attack training examples made "thanks!" look malicious). After that fix both sets were re-scored. Both sets, and the training-data generator, were written by the same author.

**External data.** We use the public in-the-wild jailbreak dataset of Shen et al. (ACM CCS 2024; MIT licence), which contains 1,405 jailbreak prompts and 13,735 regular prompts collected from Reddit, Discord and websites during 2022-2023. We first scored the detectors zero-shot on all 15,140 prompts. We then trained a second classifier with a temporal split: prompts created before 4 July 2023 form the training set (8,038 prompts, 758 jailbreaks after removing near-duplicates by a normalised 300-character prefix) and later prompts form the test set (5,497 prompts, 398 jailbreaks, 7.2% prevalence), with any test prompt whose prefix occurs in training removed. Training uses all jailbreaks and four randomly chosen benign prompts per jailbreak. We fixed hyperparameters in advance (12 epochs of stochastic gradient descent, learning rate 0.5 with decay 0.85, L2 1e-5) and evaluated the test set once. We report an operating point at the 0.5 threshold and a second point whose threshold is set on training negatives so that 1% of them are flagged.

**Metrics.** Recall, false-positive rate (FPR), precision at the dataset's prevalence, and AUC for the classifier. Throughput was measured as wall-clock time per prompt on one CPU core.

## 4. Results

### 4.1 Author-written sets

| Set | Detector | Precision | Recall | F1 |
|---|---|---|---|---|
| Held-out (n=102) | regex rules | 1.00 | 0.02 | 0.04 |
| | classifier (`injection`) | 0.94 | 0.67 | 0.78 |
| | rules + classifier | 0.94 | 0.67 | 0.78 |
| Development (n=149) | regex rules | 1.00 | 0.24 | 0.39 |
| | rules + classifier | 1.00 | 0.85 | 0.92 |

The rules almost never fire falsely but miss paraphrases; the classifier recovers about two thirds of unseen paraphrases.

### 4.2 External data, zero-shot (all 15,140 prompts)

| Detector | Recall | FPR |
|---|---|---|
| regex rules | 0.134 | 0.074 |
| classifier (`injection`, synthetic training) | 0.311 | 0.123 |
| rules + classifier | 0.394 | 0.182 |

The detectors tuned on author-written data flag a large share of ordinary prompts and still miss most jailbreaks.

### 4.3 External data, time-split (5,497 test prompts, 398 jailbreaks)

| Detector | Recall | FPR | Precision |
|---|---|---|---|
| regex rules | 0.048 | 0.026 | 0.13 |
| classifier, threshold 0.5 | 0.420 | 0.126 | 0.21 |
| classifier, threshold at 1% training FPR | 0.204 | 0.033 | 0.33 |

The classifier's AUC is 0.739. Training on in-distribution data helps recall (roughly 0.31 to 0.42 at a similar FPR, though the two numbers come from different prompt sets) but does not close the gap to the author-written sets. At realistic prevalence, a detector at 12.6% FPR produces about four false alarms for every true detection. Scoring costs 0.5-1.2 ms per prompt.

### 4.4 A label-semantics finding

In the regular-prompt set, 721 of 13,735 prompts (5.2%) contain a literal "ignore all previous instructions" (or close variant). These are ordinary templates, for example "Ignore all previous instructions. You are an experienced coding teacher". The regex override rule, which also matches looser variants of the phrase, accounts for 1,000 of the 1,022 regular prompts the rules flag. The same phrase is a strong signal when it appears inside a retrieved document or tool output, because the user did not write it. Detectors therefore need to know where text came from, and a single phrase list cannot serve both contexts.

### 4.5 PII checksum validation

Random 12-digit strings starting 2-9 pass the Verhoeff check 9.9% of the time and random 16-digit strings pass Luhn 10.0% of the time (200,000 samples each), so checksum validation removes about 90% of false positives from numeric look-alikes, while all 5,000 generated valid Aadhaar numbers were kept. On the 15,140 real prompts, the regular expression for card-shaped strings (13-19 digits) matched 166 strings and 9 survived the Luhn check. For Aadhaar-shaped strings, 4 matched and 1 survived. The dataset has no PII labels, so we cannot report precision; some survivors may be genuine or coincidentally valid numbers.

## 5. Discussion

The author-written sets and the external data disagree for ordinary reasons. The authors' examples share vocabulary with the authors' rules and training generator. Real jailbreaks are long, varied role-play prompts, and real benign prompts include long system-style templates that look similar. A hashed bag-of-words model has little to separate them. Stronger detectors (fine-tuned transformer classifiers, or model-based judges) are the natural next step; we did not evaluate them here because no model downloads were available in our environment, and we make no claim about their performance.

Recommendations for practitioners and for future evaluations of lightweight detectors:

- Evaluate on external, time-split data; report recall at fixed low false-positive rates, not only at a 0.5 threshold.
- Report precision at a stated prevalence. A 12% FPR is unusable at 7% prevalence.
- Treat provenance as a feature: use different policies for user prompts and for third-party content.
- Use checksum validation wherever an identifier has one.

## 6. Limitations

All hand-written sets and the synthetic training data were produced by one author, who also designed the rules. The external dataset labels jailbreak intent, not "prompt injection" in the document-embedded sense, and its benign class is not guaranteed to be free of jailbreaks. The temporal split covers one year and one data source. We evaluated one model family (hashed bag-of-words logistic regression) with no hyperparameter search beyond fixed defaults, so the results characterise lightweight linear detectors, not all detectors. The PII experiment has no ground-truth labels for real data. Latency was measured on one machine.

## 7. Reproducibility

Everything is in the repository. `python scripts/evaluate.py` reproduces Section 4.1. After downloading the two CSVs from github.com/verazuo/jailbreak_llms, `python -I scripts/eval_external.py` reproduces Section 4.2, `python -I scripts/train_jailbreak.py` reproduces Section 4.3, and `python -I scripts/pii_checksum_experiment.py` reproduces Section 4.5. Seeds are fixed. The package is on PyPI as `guardkit`.

## Acknowledgements and AI-use statement

Code, experiments and a first draft of this report were prepared with assistance from Claude (Anthropic). The author reviewed the results and is responsible for the content. Verify the venue's AI-disclosure policy before submission.

## References

- Shen, X., Chen, Z., Backes, M., Shen, Y., Zhang, Y. "Do Anything Now": Characterizing and Evaluating In-The-Wild Jailbreak Prompts on Large Language Models. ACM CCS 2024. arXiv:2308.03825. Data: github.com/verazuo/jailbreak_llms.
- Verhoeff, J. Error Detecting Decimal Codes. Mathematical Centre Tracts 29, 1969.
- Luhn, H. P. Computer for Verifying Numbers. US Patent 2,950,048, 1960.
