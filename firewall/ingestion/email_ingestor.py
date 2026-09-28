"""Extract text from .eml files"""
import email
from email import policy
from firewall.ingestion.text_ingestor import TextIngestor

class EmailIngestor:
    def __init__(self):
        self.text_ingestor = TextIngestor()

    def ingest(self, raw: str) -> str:
        msg = email.message_from_string(raw, policy=policy.default)

        parts = []
        if msg["subject"]:
            parts.append(f"Subject: {msg['subject']}")
        if msg["from"]:
            parts.append(f"From: {msg['from']}")

        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    parts.append(part.get_content())
        else:
            parts.append(msg.get_content())

        return self.text_ingestor.ingest("\n\n".join(parts))