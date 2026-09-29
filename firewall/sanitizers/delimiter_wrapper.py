"""Wraps untrusted content in delimiters so the downstream LLM treats it as data, not instructions."""

class DelimiterWrapper:
    OPEN = "<untrusted_content>"
    CLOSE = "</untrusted_content>"

    def wrap(self, text: str) -> str:
        # Escape any existing delimiters to prevent breakout
        safe = text.replace(self.OPEN, "[escaped]").replace(self.CLOSE, "[/escaped]")
        return f"{self.OPEN}\n{safe}\n{self.CLOSE}"