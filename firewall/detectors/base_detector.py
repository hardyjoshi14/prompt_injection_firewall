"""Abstract base for all detectors"""
from dataclasses import dataclass, field
from typing import Optional

@dataclass
class DetectionResult:
    is_malicious: bool
    attack_type: Optional[str] = None
    confidence: float = 0.0
    explanation: str = ""
    matched_spans: list = field(default_factory=list)
    detector_name: str = ""

class BaseDetector:
    """All detectors implement direct(text) -> DetectionResult."""
    
    name: str = "base"

    def detect(self, text: str) -> DetectionResult:
        raise NotImplementedError
