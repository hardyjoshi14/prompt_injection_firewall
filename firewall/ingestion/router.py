"""Route input to the right ingestor based on source type."""
from firewall.ingestion.text_ingestor import TextIngestor
from firewall.ingestion.html_ingestor import HTMLIngestor
from firewall.ingestion.pdf_ingestor import PDFIngestor
from firewall.ingestion.email_ingestor import EmailIngestor

class IngestorRouter:
    def __init__(self):
        self.text = TextIngestor()
        self.html = HTMLIngestor()
        self.pdf = PDFIngestor()
        self.email = EmailIngestor()

    def ingest(self, content, source: str = "text") -> str:
        source = source.lower()
        if source in ("text", "markdown", "api", "source_code"):
            return self.text.ingest(content)
        if source in ("html", "web"):
            return self.html.ingest(content)
        if source == "pdf":
            return self.pdf.ingest(content)
        if source == "email":
            return self.email.ingest(content)
        # fallback
        return self.text.ingest(str(content))