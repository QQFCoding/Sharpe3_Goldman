"""Reusable bounded, intent-preserving synthetic transformations (never executed)."""
import base64
import html
from urllib.parse import quote


def transform(text, name):
    if len(text) > 12000:
        raise ValueError("Synthetic transformation input too large")
    def enc(value):
        return base64.b64encode(value.encode()).decode()
    operations = {
        "plain": lambda: text,
        "base64": lambda: "Encoded passage: " + enc(text),
        "base64url": lambda: "Encoded passage: " + base64.urlsafe_b64encode(text.encode()).decode().rstrip("="),
        "url": lambda: quote(text, safe=""),
        "url_twice": lambda: quote(quote(text, safe=""), safe=""),
        "html_entities": lambda: "".join(f"&#{ord(c)};" if c.isalpha() else html.escape(c) for c in text),
        "unicode_escape": lambda: "".join(f"\\u{ord(c):04x}" if ord(c) < 65536 else c for c in text),
        "hex_escape": lambda: "".join(f"\\x{ord(c):02x}" if ord(c) < 128 else c for c in text),
        "octal_escape": lambda: "$'" + "".join(f"\\{ord(c):03o}" if ord(c) < 128 else c for c in text) + "'",
        "mixed_encoding": lambda: quote(enc(text), safe=""),
        "zero_width": lambda: "\u200b".join(text),
        "bidi": lambda: "\u202e" + "\u2066".join(text) + "\u202c",
        "fullwidth": lambda: "".join(chr(ord(c) + 0xfee0) if 33 <= ord(c) <= 126 else c for c in text),
        "homoglyph": lambda: text.translate(str.maketrans("aceopx", "асеорх")),
        "whitespace": lambda: text.replace(" ", "\n\t "),
        "letter_spacing": lambda: " ".join(text),
        "punctuation": lambda: " ".join("·".join(word) for word in text.split()),
        "leet": lambda: text.translate(str.maketrans("aeiost", "431057")),
        "nested_quotes": lambda: 'Document fragment: "' + text + '"',
        "html_base64": lambda: "<section data-note='" + enc(text) + "'></section>",
        "long_middle": lambda: ("Public catalog entry. " * 110) + text + (" Public exhibit summary." * 110),
        "long_end": lambda: ("Public catalog entry. " * 230) + text,
    }
    return operations[name]()


ATTACK_TRANSFORMS = ("plain", "base64", "url_twice", "html_entities", "unicode_escape",
    "zero_width", "fullwidth", "homoglyph", "punctuation", "leet", "mixed_encoding", "long_end")
BENIGN_TRANSFORMS = ("plain", "base64", "url", "html_entities", "unicode_escape", "whitespace", "fullwidth", "long_middle")
