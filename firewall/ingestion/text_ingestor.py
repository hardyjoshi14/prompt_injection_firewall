"""Normalizes plain text input before detection."""
import re
import unicodedata

class TextIngestor:
    """Basic text normalizer: unicode, whitespace, control chars."""

    def ingest(self, content: str) -> str:
        if not isinstance(content, str):
            content = str(content)

        # Unicode normalization (handles lookalike characters)
        content = unicodedata.normalize("NFKC", content)

        # Strip null bytes and control chars (except newline/tab)
        content = "".join(
            ch for ch in content
            if ch in "\n\t" or unicodedata.category(ch)[0] != "C"
        )

        # Collapse excessive whitespace
        content = re.sub(r"[ \t]+", " ", content)
        content = re.sub(r"\n{3,}", "\n\n", content)

        return content.strip()
