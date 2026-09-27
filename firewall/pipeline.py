"""Ingest -> Detect -> Decide"""
from dataclasses import dataclass, field
from typing import Optional
import time

from firewall.ingestion.text_ingestor import TextIngestor
from firewall.detectors.regex_detector import RegexDeteector
from firewall.detectors.base_detector import DetectionResult

@dataclass
class FirewallDecision:
    decision: str # 'allow', 'block', 'sanitize'
    attacK_type: Optional[str]
    confidence: float
    explanation: str
    sanitized_text: Optional[str] = None
    latency_ms: float = 0.0
    detector_name: str = ""
    matches: list = field(default_factory=list)

class FirewallPipeline:
    def __init__(self):
        self.ingestor = TextIngestor()
        self.detectors = [RegexDeteector()]
        self.block_threshold = 0.5

    def process(self, content: str, source: str = "text") -> FirewallDecision:
        start = time.perf_counter()

        normalized = self.ingestor.ingest(content)

        # run detectors, take highest confidence malicious result
        results = [d.detect(normalized) for d in self.detectors]
        malicious = [r for r in results if r.is_malicious]

        if not malicious:
            elapsed = (time.perf_counter() - start) * 1000
            return FirewallDecision(
                decision="allow",
                attacK_type=None,
                confidence=0.0,
                explanation="No threats detected",
                latency_ms=elapsed
            )

        best = max(malicious, key=lambda r: r.confidence)

        decision = "block" if best.confidence >= self.block_threshold else "allow"

        elapsed = (time.perf_counter() - start) * 1000
        return FirewallDecision(
            decision=decision,
            attacK_type=best.attack_type,
            confidence=best.confidence,
            explanation=best.explanation,
            latency_ms=elapsed,
            detector_name=best.detector_name,
            matches=best.matched_spans
        )