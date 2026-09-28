"""Extract text from PDF. Accepts a file path or bytes."""
import pymupdf
from firewall.ingestion.text_ingestor import TextIngestor

class PDFIngestor:
    def __init__(self):
        self.text_ingestor = TextIngestor()

    def ingest(self, source) -> str:
        """source can be a file path or raw bytes."""
        if isinstance(source, bytes):
            doc = pymupdf.open(stream=source, filetype="pdf")
        else:
            doc = pymupdf.open(source)

        pages = [page.get_text() for page in doc]
        doc.close()

        return self.text_ingestor.ingest("\n\n".join(pages))
    