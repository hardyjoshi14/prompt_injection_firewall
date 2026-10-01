"""Attempts to decode common obfuscation schemes."""
import base64
import binascii
import codecs
import re
from urllib.parse import unquote

BASE64_PATTERN = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
HEX_PATTERN = re.compile(r"(?:[0-9a-fA-F]{2}\s*){10,}")

def try_base64(text: str) -> list[str]:
    """Find and decode base64-looking substrings."""
    decoded = []
    for match in BASE64_PATTERN.finditer(text):
        chunk = match.group(0)
        # padded to multiple of 4
        padded = chunk + "=" * (-len(chunk) % 4)
        try:
            raw = base64.b64decode(padded, validate=True)
            candidate = raw.decode("utf-8", errors="ignore")
            # keep only printable-ish results
            if sum(c.isprintable() for c in candidate) / max(len(candidate), 1) > 0.8:
                decoded.append(candidate)
        except (binascii.Error, ValueError):
            continue
    return decoded

def try_hex(text: str) -> list[str]:
    decoded = []
    for match in HEX_PATTERN.finditer(text):
        cleaned = re.sub(r"\s+", "", match.group(0))
        try:
            raw = bytes.fromhex(cleaned)
            candidate = raw.decode("utf-8", errors="ignore")
            if sum(c.isprintable() for c in candidate) / max(len(candidate), 1) > 0.8:
                decoded.append(candidate)
        except ValueError:
            continue
    return decoded

def try_url(text: str) -> list[str]:
    decoded = unquote(text)
    return [decoded] if decoded != text else []

def try_rot13(text: str) -> list[str]:
    decoded = codecs.decode(text, "rot_13")
    return [decoded] if decoded != text else []

def decode_all(text: str) -> list[tuple[str, str]]:
    """Returns list of (scheme, decoded_text) tuples."""
    results = []
    for name, fn in [
        ("base64", try_base64),
        ("hex", try_hex),
        ("url", try_url),
        ("rot13", try_rot13)
    ]:
        for decoded in fn(text):
            results.append((name, decoded))
    return results