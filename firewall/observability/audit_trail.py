"""Builds audit entries from pipeline decisions."""
import hashlib
from firewall.observability.logger import log_event


def content_hash(text: str) -> str:
    """Short stable hash for dedup/correlation without storing full content."""
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()[:16]


def record_decision(
    content,
    source: str,
    decision,
    content_preview_len: int = 200,
) -> dict:
    """Create and persist an audit entry. Returns the entry for optional display."""
    preview = content if isinstance(content, str) else str(content)
    preview = preview[:content_preview_len]

    entry = {
        "source": source,
        "content_hash": content_hash(preview),
        "content_preview": preview,
        "decision": decision.decision,
        "attack_type": decision.attack_type,
        "confidence": round(decision.confidence, 4),
        "detectors_used": decision.detectors_used,
        "matched_spans_count": len(decision.matches) if decision.matches else 0,
        "sanitized": decision.sanitized_text is not None,
        "latency_ms": round(decision.latency_ms, 2),
        "explanation": decision.explanation,
    }

    log_event(entry)
    return entry