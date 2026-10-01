"""Detects prompt injection hidden in retrieved/indirect content."""
import re
from firewall.detectors.base_detector import BaseDetector, DetectionResult

# Phrases that direct AI, not user
IMPERATIVE_PATTERNS = [
    r"^\s*(assistant|ai|system|model)\s*[:>-]",
    r"\b(please\s+)?(ignore|disregard|forget)\b.{0,40}\b(previous|above|prior)\b",
    r"\b(you\s+must|you\s+should|you\s+will|you\s+are\s+required)\b",
    r"\b(new\s+instructions?|updated?\s+instructions?|system\s+prompt)\b",
    r"\b(execute|run|invoke|call)\s+the\s+following\b",
    r"\bdo\s+not\s+(tell|inform|mention|reveal)\b",
    r"<\s*(system|instruction|admin)\s*>",
    r"\[\s*(system|instruction|admin)\s*\]"
]

COMPILED_IMPERATIVES = [re.compile(p, re.IGNORECASE | re.MULTILINE) for p in IMPERATIVE_PATTERNS]

# sources considered retrieved
RETRIEVED_SOURCES = {"pdf", "html", "web", "email", "api", "ocr", "markdown"}

class IndirectDetector(BaseDetector):
    name = "indirect"

    def detect(self, text: str, source: str, str = "text") -> DetectionResult:
        if source.lower() not in RETRIEVED_SOURCES:
            return DetectionResult(
                is_malicious=False,
                confidence=0.0,
                explanation="Source is direct input - indirect injection N/A",
                detector_name=self.name
            )

        matches = []
        for pattern in COMPILED_IMPERATIVES:
            for m in pattern.finditer(text):
                matches.append({
                    "attack_type": "Indirect Injection",
                    "matched": m.group(0).strip(),
                    "start": m.start(),
                    "end": m.end()
                })

        if not matches:
            return DetectionResult(
                is_malicious=False,
                confidence=0.0,
                explanation=f"No instruction patterns in {source} content.",
                detector_name=self.name
            )

        confidence = min(0.55 + 0.10 * len(matches), 0.95)

        return DetectionResult(
            is_malicious=True,
            attack_type="Indirect Injection",
            confidence=confidence,
            explanation=f"Found {len(matches)} instruction-like pattern(s) in retrieved {source} content.",
            matched_spans=matches,
            detector_name=self.name
        )