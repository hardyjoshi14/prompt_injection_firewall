"""Removes spans flagged as malicious by detectors."""
import re
from firewall.detectors.base_detector import DetectionResult

class InstructionStripper:
    def strip(self, text: str, detection: DetectionResult) -> str:
        if not detection.matched_spans:
            return text

        # Sort spans by start index, remove from end to preserve offsets
        spans = sorted(detection.matched_spans, key=lambda m: m["start"], reverse=True)
        chars = list(text)
        for span in spans:
            start, end = span["start"], span["end"]
            # Replace malicious with a neutral placeholder
            chars[start:end] = list("[REDACTED]")

        return "".join(chars)