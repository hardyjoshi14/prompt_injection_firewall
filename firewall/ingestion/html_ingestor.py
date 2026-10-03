"""Extract clean text from HTML, stripping scripts and styles."""
from bs4 import BeautifulSoup, Comment
from firewall.ingestion.text_ingestor import TextIngestor

class HTMLIngestor:
    def __init__(self):
        self.text_ingestor = TextIngestor()

    def ingest(self, html: str) -> str:
        soup = BeautifulSoup(html, "lxml")

        hidden_parts = []

        for tag in soup(["script", "style", "noscript"]):
            if tag.string:
                hidden_parts.append(tag.string)
            tag.decompose()

        for comment in soup.find_all(string=lambda t: isinstance(t, Comment)):
            hidden_parts.append(str(comment))

        visible = soup.get_text(separator="\n")
        combined = "\n".join(hidden_parts + [visible])
        return self.text_ingestor.ingest(combined)

