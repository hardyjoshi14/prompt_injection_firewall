# Prompt Injection Firewall

An agentic security layer that intercepts content before it reaches an LLM,
detects prompt injection attacks, and neutralizes them while preserving
legitimate traffic.

## Highlights

- Detects 9 attack types: Instruction Override, Role Change, Secret Extraction,
  Tool Abuse, Credential Theft, Context Poisoning, Multi-Step Jailbreak,
  Encoded Instructions, Indirect Injection
- Layered defense: regex, encoding decoder, indirect-content scanner, and a
  local LLM classifier
- Five input formats: text, HTML, PDF, email, API JSON
- Three-tier response: allow / sanitize / block
- Full audit trail with timestamp, hash, confidence, and detectors fired
- Runs entirely on-device via Ollama; no content leaves the perimeter

## Evaluation (v5, n=221)

| Metric | Value |
|---|---|
| Precision | 0.994 |
| Recall | 0.981 |
| F1 | 0.988 |
| Accuracy | 0.982 |
| False Positive Rate | 0.017 |
| False Negative Rate | 0.019 |

Full report: `evaluation/reports/v5.md`

Declared position: **D2 / F3** (see `docs/self_assessment.md`)

## Architecture

See `docs/architecture.md` for the full breakdown and
`docs/architecture_diagram.png` for the system diagram.

## Setup

```bash
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
pip install -e .
ollama pull llama3.1:8b
```

## Run the Demo

```bash
streamlit run app/main.py
```

Four tabs:

1. Live Demo — paste content, see decision and sanitized output
2. Attack Gallery — one-click demo of each attack type
3. Audit Log — filterable history of every decision
4. Metrics — evaluation dashboard

## Reproduce the Evaluation

```bash
python data/generate_test_set.py
python evaluation/evaluate.py --model llama3.1:8b --tag v5
```

Results written to `evaluation/reports/v5.md`.

## Project Structure

```
firewall/          Core pipeline and detectors
  ingestion/       Format-specific input extraction
  detectors/       Regex, encoded, indirect, LLM
  sanitizers/      Redaction, stripping, delimiter wrapping
  observability/   Audit logging
app/               Streamlit UI
evaluation/        Test harness and reports
data/              Test set generator
docs/              Architecture, self-assessment, diagram
```

## Requirements

- Python 3.10+
- Ollama running locally with llama3.1:8b pulled