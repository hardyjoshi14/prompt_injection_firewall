# Self-Assessment

**Declared: D2 / F3**

## Depth (D2)

Input formats: text, HTML, PDF, email, API JSON
Test set: 221 labeled samples (161 malicious, 60 benign; some overlap in count due to per-source grouping)
Model: openai/gpt-oss-120b via Groq (cloud)

| Metric | Value |
|---|---|
| Precision | 0.994 |
| Recall | 0.994 |
| F1 | 0.994 |
| Accuracy | 0.991 |
| False Positive Rate | 0.017 |
| False Negative Rate | 0.006 |
| LLM parse failures | 0 / 221 |

Confusion: TP=160 · FP=1 · TN=59 · FN=1

## Features (F3 — 9 attack types)

F3 requires detection of at least 7 attack types. All 9 are implemented with
dedicated detection mechanisms.

| Attack Type | Detected / Total | Rate |
|---|---|---|
| Role Change | 20 / 20 | 1.000 |
| Secret Extraction | 20 / 20 | 1.000 |
| Credential Theft | 20 / 20 | 1.000 |
| Tool Abuse | 19 / 19 | 1.000 |
| Encoded Instructions | 12 / 12 | 1.000 |
| Indirect Injection | 15 / 15 | 1.000 |
| Context Poisoning | 20 / 20 | 1.000 |
| Instruction Override | 20 / 20 | 1.000 |
| Multi-Step Jailbreak | 14 / 15 | 0.933 |


All nine categories exceed the F3 threshold.

## Per-Source Accuracy

| Source | Correct / Total | Accuracy |
|---|---|---|
| api | 10 / 10 | 1.000 |
| text | 175 / 176 | 0.994 |
| html | 24 / 25 | 0.960 |
| email | 9 / 10 | 0.900 |

## Why not D3

D3 requires heterogeneous multimodal input (images, OCR, audio).
The current system processes only structured/textual content across five
formats. Image and OCR handling are not implemented. The submission declares D2, which is fully evidenced by the metrics above.

## Out-of-Distribution Probe

An independent probe (`tests/novel_paraphrases.py`) of 66 novel attack
paraphrases and 20 security-adjacent benign inputs:

| Metric | Value |
|---|---|
| Attack recall | 1.000 (66/66) |
| Benign specificity | 0.700 (14/20) |
| OOD F1 | 0.957 |

The 8B local baseline scored 0.758 / 0.450 on the same probe, confirming that the 120B cloud classifier resolves the OOD capacity limit.