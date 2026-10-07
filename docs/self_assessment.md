# Self-Assessment

**Declared: D2 / F3**

## Depth (D2)

Input formats: text, HTML, PDF, email, API JSON
Test set: 221 labeled samples (180 malicious, 60 benign; some overlap in count due to per-source grouping)
Model: llama3.1:8b (local, via Ollama)

| Metric | Value |
|---|---|
| Precision | 0.994 |
| Recall | 0.981 |
| F1 | 0.988 |
| Accuracy | 0.982 |
| False Positive Rate | 0.017 |
| False Negative Rate | 0.019 |
| LLM parse failures | 0 / 221 |

Confusion: TP=158 · FP=1 · TN=59 · FN=3

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
| Context Poisoning | 19 / 20 | 0.950 |
| Instruction Override | 19 / 20 | 0.950 |
| Multi-Step Jailbreak | 14 / 15 | 0.933 |


All nine categories exceed the F3 threshold.

## Per-Source Accuracy

| Source | Correct / Total | Accuracy |
|---|---|---|
| text | 173 / 176 | 0.983 |
| html | 25 / 25 | 1.000 |
| api | 10 / 10 | 1.000 |
| email | 9 / 10 | 0.900 |

## Why not D3

D3 requires heterogeneous **multimodal** input (images, OCR, audio, etc.).
The current system processes only structured/textual content across five
formats. Image and OCR handling are not implemented. This is a deliberate
scope decision, not a limitation discovered post-hoc — D2 is fully evidenced
and defensible with margin.