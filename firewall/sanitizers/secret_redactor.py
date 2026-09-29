"""Redacts common secret patterns."""
import re

PATTERNS = [
    (re.compile(r"sk-[A-Za-z0-9]{20,}"), "[OPENAI_KEY_REDACTED]"),
    (re.compile(r"sk-ant-[A-Za-z0-9\-_]{20,}"), "[ANTHROPIC_KEY_REDACTED]"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "[AWS_KEY_REDACTED]"),
    (re.compile(r"ghp_[A-Za-z0-9]{36}"), "GITHUB_TTOKEN_REDACTED"),
    (re.compile(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"), "JWT_REDACTED"),
    (re.compile(r"(?i)password\s:[:=]\s*\S+"), "password=[REDACTED]")
]

class SecretRedactor:
    def redact(self, text:str) -> tuple[str, int]:
        count = 0
        for pattern, replacement in PATTERNS:
            text, n = pattern.subn(replacement, text)
            count += n
        return text, count