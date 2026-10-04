"""Structured JSON logger for firewall decisions."""
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

LOG_DIR = Path(__file__).resolve().parent.parent.parent / "logs"
LOG_DIR.mkdir(exist_ok=True)

AUDIT_FILE = LOG_DIR / "audit.jsonl"

# Standard Python logger for console
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("firewall")


def log_event(event: dict) -> None:
    """Append a JSON line to the audit file."""
    event.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
    with open(AUDIT_FILE, "a") as f:
        f.write(json.dumps(event) + "\n")


def read_audit_log(limit: int | None = None) -> list[dict]:
    """Read audit entries, most recent first."""
    if not AUDIT_FILE.exists():
        return []
    entries = []
    with open(AUDIT_FILE) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    entries.reverse()
    return entries[:limit] if limit else entries


def clear_audit_log() -> None:
    if AUDIT_FILE.exists():
        AUDIT_FILE.unlink()