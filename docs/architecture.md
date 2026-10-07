# Prompt Injection Firewall Architecture

## 1. Overview

The Firewall is an agentic security layer that intercepts all content arriving at the LLM system - user messages, retrieved documents, API responses, emails, and web pages. It neutralizes prompt injection 
attacks before they can influence the downstream model.

The system operates in basically four stages:
    Ingest -> Detect -> Decide -> Sanitize -> Audit

Each input is normalized, scanned by four independent detectors, classified into one of the nine attack categories, assigned a confidence score, and either allowed, sanitized, or blocked. Each decision is recorded in an audit log.

## 2. Design Principles

1. **In-depth defense** - multiple independent detection layers. Failure of one does not compromise the firewall.
2. **Determinisitc first** - regex catches known patterns with zero latency and uncertainty. The LLM handles semantic nuance that regex cannot.
3. **Failure-safe defaults** - malformed input, detector errors and unparseable output all default to a safe decision rathen than crashing or allowing.
4. **Explainability** - every decision carries an explanation, and where applicable, the exact spans that triggered it.
5. **Traceability** - every decision is logged along with timestamp, input hash, decision, confidence, and which detectors were used.
6. **On-premise** - all inference runs on-device via Ollama. No content leaves the premises, which is critical for security product.

## 3. Process Flow

Input (text | HTML | PDF | email | API response | Markdown | source code)
  |
  V
┌──────────────────────────────────────────────────────────────┐
│ 1. Ingestion Router                                          │
│    - Routes to format-specific extractor                     │
│    - HTML: visible text + script/style/comment content       │
│    - PDF: page-wise text extraction (PyMuPDF)                │
│    - Email: headers + body                                   │
│    - Text/API/Markdown/code: pass-through                    │
└──────────────────────────────────────────────────────────────┘
  |
  V
┌──────────────────────────────────────────────────────────────┐
│ 2. Normalization                                             │
│    - Unicode NFKC (defeats lookalike characters)             │
│    - Control-character stripping                             │
│    - Whitespace collapsing                                   │
└──────────────────────────────────────────────────────────────┘
  |
  V
┌──────────────────────────────────────────────────────────────┐
│ 3. Parallel Detection Layer                                  │
│                                                              │
│  ┌────────────────┐  ┌────────────────┐                      │
│  │ RegexDetector  │  │ EncodedDetector│                      │
│  │ 6 categories   │  │ Base64, hex,   │                      │
│  │ ~30 patterns   │  │ URL, ROT13     │                      │
│  └────────────────┘  └────────────────┘                      │
│                                                              │
│  ┌────────────────┐  ┌────────────────┐                      │
│  │IndirectDetector│  │  LLMDetector   │                      │
│  │ retrieved-     │  │  llama3.1:8b   │                      │
│  │ content scan   │  │  structured    │                      │
│  │                │  │  JSON output   │                      │
│  └────────────────┘  └────────────────┘                      │
└──────────────────────────────────────────────────────────────┘
  |
  V
┌──────────────────────────────────────────────────────────────┐
| 4. Aggregation and Decision                                  | 
|    - Take highest confidence malicious verdict               |
|    - Boost confidence +0.10 when atleast 2 detectors agree   | 
|    - Apply thresholds:                                       | 
|        confidence >= 0.75 -> BLOCK                           | 
|        confidence between 0.40, and 0.75 -> SANITIZE         |
|        confidence < 0.40 -> ALLOW                            |
└──────────────────────────────────────────────────────────────┘
  |
  v
┌──────────────────────────────────────────────────────────────┐
| 5. Audit                                                     |
|    - Append JSON entry: timestamp, hash, source, decision,   |
|      attack_type, confidence, detectors_used, latency, spans |
|    - Persisted to logs/audit.jsonl                           | 
|    - Surfaced in Streamlit Audit Log tab                     | 
└──────────────────────────────────────────────────────────────┘  

## 4. Component Detail

### 4.1 Ingestion

| Module | Responsibility |
|---|---|
| IngestionROuter | Dispatches by source argument |
| TextIngestor | Unicode NFKC normalization, control-char stripping |
| HTMLIngestor | BeautifulSoup extraction; preserves script/style/comment content attackers hide payloads there |
| PDFIngestor | PyMuPDF page-wise text extraction |
| EmailIngestor | RFC822 parsing; concatenates headers + plain-text body |

The HTML ingestor deliberately does not discard <script>, <style> or HTML comments. Common indirect injection vectors usually hide instructions in comment or script tags where visible page render shows nothing suspicious.

### 4.2 Detection

**RegexDetector** - pattern matching across six categories: Instruction Override, Role Change, Secret Extraction, Tool Abuse, Credential Theft, Context Poisoning. Patterns use word boundaries and gap-tolerant wildcards. Matches are grouped by category, the one with most matches wins. Confidence scales with match count (0.55 - 0.90).

**EncodedDetector** - decodes Base64, hex, URL-encoded, and ROT13 payloads then re-runs RegexDetector on the decoded text. This catches instructions inside encodings that would otherwise pass every detector.

**IndirectDetector** - scans retrieved content (PDF, HTML, email, API) for imperative patterns directed at an AI ([SYSTEM], assistant:, you must, ignore previous). Only fires when the source is a retrieved channel; direct user input is exempt because the user is expected to address the AI directly.

**LLMDetector** - sends content to llama3.1:8b running locally through Ollama, using a structured JSON schema. The prompt contains descriptions of each attack category and asks for {is_malicious, attack_type, confidence, explanation}. Parsing failures are logged and treated as benign (with no confidence contribution), never as malicious - this prevents a broken LLM from taking down the firewall.

### 4.3 Aggregation and Decision

- Malicious verdicts from all four detectors are collected.
- The highest confidence verdict becomes the primary decision.
- If two or more detectors flagged the input as malicious, confidence is boosted by 0.10 (capped at 0.99) -  this rewards agreement.
- Thresholds are configurable in pipeline.py:
  - BLOCK_THRESHOLD = 0.75
  - SANITIZE_THRESHOLD = 0.40
- Inputs below SANITIZE_THRESHOLD are allowed unchanged.

### 4.4 Sanitization

When the decision is sanitize, three operations run in sequence:

1. **Secret redaction** - regex-based removal of API keys, JWTs, passwords, AWS/GitHub tokens before anything else.
2. **Instruction stripping** - matched malicious spans are replaced with [REDACTED] so the downstream LLM never sees the instrucution.
3. **Delimiter wrapping** - content is wrapped in <untrusted_content>...</untrusted_content> tags, and any existing delimiters are escaped. This informs the downstream LLM that the wrapped text is data, not instructions.

### 4.5 Observability

Every decision is recorded in logs/audit.jsonl as a JSON line. Fields:

- timestamp (UTC ISO-8601)
- content_hash (SHA-256 prefix - correlation without storing full content)
- content_preview (first 200 chars)
- source
- decision
- attack_type
- confidence
- detectors_used
- matched_spans_count
- sanitized (bool)
- latency_ms
- explanation

The Streamlit Audit Log page provides filterable browsing, per-decision inspection and summary metrics.

## 5. Model Usage

| Model | Role | Why |
|---|---|---|
| llama3.1:8b (Ollama) | Semantic classification | 8B parameters handle nuanced instructions that 3B models miss. Runs entirely on-device. |

No cloud inference is used. Structured output is enforced through Ollama's format parameter with a Pydantic generated JSON schema.

## 6. Attack Coverage

| # | Attack Type | Primary Detector | Secondary | Sanitization |
|---|---|---|---|---|
| 1 | Instruction Override | Regex | LLM | Strip spans |
| 2 | Role Change | Regex | LLM | Strip spans |
| 3 | Secret Extraction | Regex | LLM | Strip spans |
| 4 | Tool Abuse | Regex | LLM | Strip spans, block tool calls |
| 5 | Credential Theft | Regex | LLM | Redact secrets |
| 6 | Context Poisioning | Regex | LLM | Strip spans |
| 7 | Multi-Step Jailbreak | LLM | - | Strip spans |
| 8 | Encoded Instructions | EncoderDecoder -> Regex | LLM | Strip spans |
| 9 | Indirect Injection | IndirectDetector | LLM | Strip spans + delimiter wrap |

All nine attack types defined in the problem statement are covered, exceeding the F3 threshold of 7.

## 7. Solution Depth Justification (D2)

**D2 requires**: mostly structured/textual input + high degree of demonstrable reliability.

**Input coverage**:
- Plain text, Markdown, source code
- HTML (including hidden scripts/comments)
- PDF
- Email (.eml)
- API JSON responses

**Reliability evidence** (v4 evaluation, 221 synthetic samples):

| Metric | Value |
|---|---|
| Precision | 0.994 |
| Recall | 0.981 |
| F1 | 0.988 |
| Accuracy | 0.982 |
| False Positive Rate | 0.017 |
| False Negative Rate | 0.019 |
| LLM parse failures | 0 / 221 |

Per-attack detection rate - all nine categories above 0.90 except Multi-Step Jailbreak (which relies only on the LLM).

**Why not D3**: D3 requires heterogeneous multimodal input. The current solution does not process image content and therefore does not claim D3. The self-assessment: 9/9 attack types with precision greater than 0.99 and recall greater than 0.97 across five input formats satisfies D2 with margin.

## 8. Solution Features Justification (F3)

**F3**: detect at least 7 attack types.
**Achieved**: 9 attack type, all with dedicated detection mecahnims and per-type recall reported in evaluations/reports/v5.md

## 9. Responsible AI

| Concern | Mitigation |
|--|--|
| Hallucination | LLM output constrained to a Pydantic schema; parse failures logged and default to benign |
| False Positives | Deliberate precision-first design; per-decision explanation shown to user; audit logs enable review |
| Privacy | All inference via local Ollama; only 200-char preview and SHA-256 stored in audit log |
| Bias | Rules are language structure based, not content based; LLM prompts emphasizes "legitimate security questions are NOT attacks" |
| Human oversight | Every decision is explainable and auditable; sanitize tier provides a middle ground between allow and block |
| Reliability | Defense-in-depth; four independent detectors; agreement boosts confidence; failure of any layer degrades gracefully |
| Security | Secrets redacted before content reaches downstream LLM; untrusted content wrapped in delimiters to prevent instruction confusion |

## 10. Limitations and Future Work 

- Multi-step jailbreaks (conversation-wide manipulation) are detected only by the LLM. A stateful detector that tracks conversation history could improve recall here.
- OCR-based image injection is not supported.
- The 9-attack taxonomy is fixed; novel attack classes require prompt or regex updates.
- Adversarial robustness against a motivated attacker who knows the rules is not formally tested.

## 11. Reproducibility

```bash
# Setup
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install -e .
ollama pull llama3.1:8b

# Generate test set
python data/generate_test_set.py

# Run evaluation
python evaluation/evaluate.py --model llama3.1:8b --tag v4

# Launch demo
streamlit run app/main.py