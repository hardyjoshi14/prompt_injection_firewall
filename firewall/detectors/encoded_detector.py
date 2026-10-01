"""Detects instructions hidden inside encodings by decoding and re-scanning."""
from firewall.detectors.base_detector import BaseDetector, DetectionResult
from firewall.detectors.regex_detector import RegexDeteector
from firewall.preprocessing.decoder import decode_all

class EncodedDetector(BaseDetector):
    name = "encoded"

    def __init__(self):
        self.inner = RegexDeteector()

    def detect(self, text: str, source: str = "text") -> DetectionResult:
        decoded_variants = decode_all(text)

        if not decoded_variants:
            return DetectionResult(
                is_malicious=False,
                confidence=0.0,
                explanation="No encoded payloads detected",
                detector_name=self.name
            )

        for scheme, decoded in decoded_variants:
            inner = self.inner.detect(decoded)
            if inner.is_malicious:
                return DetectionResult(
                    is_malicious=True,
                    attack_type="Encoded Instructions",
                    confidence=min(inner.confidence + 0.10, 0.98),
                    explanation=f"Detected {scheme}-encoded payload. Decoded content matched: {inner.explanation}",
                    matched_spans=inner.matched_spans,
                    detector_name=self.name
                )

        return DetectionResult(
            is_malicious=False,
            confidence=0.0,
            explanation=f"Found {len(decoded_variants)} encoded payload(0), none malicious.",
            detector_name=self.name
        )