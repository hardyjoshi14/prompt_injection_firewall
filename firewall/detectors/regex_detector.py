"""Rule-based detector using regex patterns for common injection attacks."""
import re
from firewall.detectors.base_detector import BaseDetector, DetectionResult

PATTERNS = {
    "Instruction Override": [
        r"ignore\s+(all\s+)?(previous|prior|above|earlier|the\s+above)",
        r"disregard\s+(all\s+)?(previous|prior|above|earlier|the\s+above)",
        r"forget\s+(everything|all|anything|what\s+you\s+were|your)",
        r"override\s+(your|the|all)?\s*(safety|instructions?|rules?|guidelines?|filter?)",
        r"cancel\s+(all\s+)?(previous|prior|above)",
        r"follow\s+my\s+instructions\s+instead",
        r"\bignore\s+(everything|all|anything)\s+(above|before)\b"
    ],
    "Role Change": [
        r"you\s+are\s+now\s+",
        r"act\s+as\s+(a|an|if|though)",
        r"pretend\s+(to\s+be|you\s+are|you're)",
        r"from\s+now\s+on[,\s]+you",
        r"your\s+new\s+role\s+is",
        r"developer\s+mode",
        r"jailbreak",
        r"unrestricted\s+(ai|assistant|model)"
    ],
    "Secret Extraction": [
        r"(reveal|show|tell|give|print|display|repeat)\s+(me\s+)?(your|the)?\s*(system\s+)?(prompt|instructions?|rules?|message)",
        r"what\s+(are|is|were)\s+your\s+(instructions?|rules?|prompt|system)",
        r"what\s+you\s+were\s+told",
        r"text\s+(above|before)",
        r"hidden\s+instructions?",
        r"initial\sinstructions?",
        r"repeat\s+(everything|all|the\s+text)",
        r"\b(developer|original|initial|full)\s+(prompt|context|configuration)\b",
        r"\btext\s+between\s+(the\s+)?system\s+tags\b",
        r"\bdisplay\s+the\s+full\s+context\b"
    ],
    "Tool Abuse": [
        r"(call|invoke|execute|run|use)\s+(the\s+)?[a-z_]+\s*(tool|function|api)?",
        r"(delete|drop|remove|disable|bypass)\w*\s+(the\s+)?(tool|function|api|auth|security|databse)",
        r"(admin|root|sudo)\s+(access|privileges|mode)"
    ],
    "Credential Theft": [
        r"(api[_\s-]?key|password|secret|token|credential)s?",
        r"(send|share|expose|give|tell)\s+(me\s+)?(the\s+)?(api|password|token|secret|credential)",
        r"(aws|gcp|azure)\s+credentials?",
        r"(jwt|oauth|session)\s+(token|key|cookie)",
        r"private\s+key",
        r"environment\s+variables?"
    ],
}

COMPILED = {
    attack: [re.compile(p, re.IGNORECASE) for p in patterns]
    for attack, patterns in PATTERNS.items()
}

class RegexDeteector(BaseDetector):
    name = "regex"

    def detect(self, text: str, source: str = "text") -> DetectionResult:
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