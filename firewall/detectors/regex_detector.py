"""Rule-based detector using regex patterns for common injection attacks."""
import re
from firewall.detectors.base_detector import BaseDetector, DetectionResult

PATTERNS = {
    "Instruction Override": [
        r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions",
        r"disregard\s+(all\s+)?(previous|prior|above)",
        r"forget\s+(everything|all|your)\s+(instructions?|rules?|prompts?)",
        r"override\s+(your\s+)?(instructions?|rules?|guidelines?)",
    ],
    "Role Change": [
        r"you\s+are\s+now\s+[a-z\s]+",
        r"act\s+as\s+(a|an)\s+[a-z\s]+",
        r"pretend\s+(to\s+be|you\s+are)",
        r"from\s+now\s+on[,\s]+you\s+(are|will)",
        r"your\s+new\s+role\s+is",
    ],
    "Secret Extraction": [
        r"(reveal|show|tell|give)\s+(me\s+)?(your\s+)?(system\s+)?prompt",
        r"what\s+(are|is)\s+your\s+(instructions?|prompt|rules?)",
        r"repeat\s+(your\s+)?(system\s+)?(prompt|instructions?)",
        r"print\s+(your\s+)?(system\s+)?prompt",
    ],
    "Tool Abuse": [
        r"(call|invoke|execute|run)\s+(the\s+)?[a-z_]+\s*(tool|function|api)",
        r"use\s+(the\s+)?(delete|drop|remove|admin)\w*\s+(tool|function|api)",
    ],
    "Credential Theft": [
        r"(api[_\s-]?key|password|secret|token|credential)s?\s*[:=]",
        r"(send|share|expose)\s+(the\s+)?(api[_\s-])?key|password|token",
    ],
}

COMPILED = {
    attack: [re.compile(p, re.IGNORECASE) for p in patterns]
    for attack, patterns in PATTERNS.items()
}

class RegexDeteector(BaseDetector):
    name = "regex"

    def detect(self, text: str) -> DetectionResult:
        matches = []

        for attack_type, patterns in COMPILED.items():
            for pattern in patterns:
                for m in pattern.finditer(text):
                    matches.append({
                        "attack_type": attack_type,
                        "matched": m.group(0),
                        "start": m.start(),
                        "end": m.end()
                    })

        if not matches:
            return DetectionResult(
                is_malicious=False,
                confidence=0.0,
                explanation="No known injection patterns found",
                detector_name=self.name
            )

        primary = matches[0] # highest priority match
        confidence = min(0.5 + 0.15 * len(matches), 0.95) # more matches, higher confidence

        return DetectionResult(
            is_malicious=True,
            attack_type=primary["attack_type"],
            confidence=confidence,
            explanation=f"Matched pattern: '{primary['matched']}' ({primary['attack_type']})",
            matched_spans=matches,
            detector_name=self.name
        )