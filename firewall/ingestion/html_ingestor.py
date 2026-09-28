"""Extract clean text from HTML, stripping scripts and styles."""
from bs4 import BeautifulSoup
from firewall.ingestion.text_ingestor import TextIngestor

class HTMLIngestor:
    def __init__(self):
        self.text_ingestor = TextIngestor()

    def ingest(self, html: str) -> str:
        soup = BeautifulSoup(html, "lxml")

        for tag in soup(["script", "style", "noscript"]):
            tag.decompose()

        text = soup.get_text(separator="\n")
        return self.text_ingestor.ingest(text)

