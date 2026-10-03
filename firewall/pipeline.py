"""Ingest -> Detect -> Decide -> Sanitize."""
from dataclasses import dataclass, field
from typing import Optional
import time

from firewall.ingestion.router import IngestorRouter
from firewall.detectors.regex_detector import RegexDeteector
from firewall.detectors.llm_detector import LLMDetector
from firewall.detectors.encoded_detector import EncodedDetector
from firewall.detectors.indirect_detector import IndirectDetector
from firewall.sanitizers.instruction_stripper import InstructionStripper
from firewall.sanitizers.delimiter_wrapper import DelimiterWrapper
from firewall.sanitizers.secret_redactor import SecretRedactor

BLOCK_THRESHOLD = 0.75
SANITIZE_THRESHOLD = 0.40

@dataclass
class FirewallDecision:
    decision: str # 'allow', 'block', 'sanitize'
    attack_type: Optional[str]
    confidence: float
    explanation: str
    sanitized_text: Optional[str] = None
    latency_ms: float = 0.0
    detectors_used: list = field(default_factory=list)
    matches: list = field(default_factory=list)

class FirewallPipeline:
    def __init__(self, llm_model: str = "llama3.1:8b", use_llm: bool = True):
        self.router = IngestorRouter()
        self.detectors = [
            RegexDeteector(),
            EncodedDetector(),
            IndirectDetector(),
            ]
        if use_llm:
            self.detectors.append(LLMDetector(model=llm_model))

        self.stripper = InstructionStripper()
        self.wrapper = DelimiterWrapper()
        self.redactor = SecretRedactor()

    def process(self, content: str, source: str = "text") -> FirewallDecision:
        start = time.perf_counter()

        try:
            normalized = self.router.ingest(content, source=source)
        except Exception as e:
            return FirewallDecision(
                decision="block",
                attack_type=None,
                confidence=1.0,
                explanation=f"Ingestion failed: {e}",
                latency_ms=(time.perf_counter() - start) * 1000,
            )

        # run all detectors
        results = [d.detect(normalized, source=source) for d in self.detectors]
        malicious = [r for r in results if r.is_malicious]
        detectors_used = [r.detector_name for r in results]

        # no threats -> allow
        if not malicious:
            return FirewallDecision(
                decision="allow",
                attack_type=None,
                confidence=0.0,
                explanation="No threats detected",
                latency_ms=(time.perf_counter() - start) * 1000,
                detectors_used=detectors_used
            )

        # aggregate: take highest confidence, combine signals
        best = max(malicious, key=lambda r: r.confidence)

        # if multiple detectors agree, boost confidence
        if len(malicious) > 1:
            best_confidence = min(best.confidence + 0.10, 0.99)
        else:
            best_confidence = best.confidence

        # decide
        if best_confidence >= BLOCK_THRESHOLD:
            decision = "block"
            sanitized = None
        elif best_confidence >= SANITIZE_THRESHOLD:
            decision = "sanitize"
            sanitized = self._sanitize(normalized, best)
        else:
            decision = "allow"
            sanitized = None

        return FirewallDecision(
            decision=decision,
            attack_type=best.attack_type,
            confidence=best.confidence,
            explanation=best.explanation,
            sanitized_text=sanitized,
            latency_ms=(time.perf_counter() - start) * 1000,
            detectors_used=detectors_used,
            matches=best.matched_spans
        )

    def _sanitize(self, text: str, detection) -> str:
        # redact secrets
        text, _ = self.redactor.redact(text)
        # strip malicious instruction spans
        text = self.stripper.strip(text, detection)
        # wrap in delimiters so downstream llm treats it as data
        text = self.wrapper.wrap(text)
        return text