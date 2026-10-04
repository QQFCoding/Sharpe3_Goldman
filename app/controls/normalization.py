"""Bounded inspection views. Never rewrite executable arguments or authorization digests."""
import base64
import binascii
import html
import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import unquote

VERSION = "inspection-views-v3"
MAX_CHARS = 65536
MAX_VIEWS = 8
MAX_DEPTH = 3
CONFUSABLES = str.maketrans({"а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x",
    "і": "i", "ј": "j", "у": "y", "Α": "A", "Β": "B", "Ε": "E", "Ι": "I", "Ο": "O",
    "Ρ": "P", "Τ": "T", "ο": "o", "ρ": "p", "ι": "i"})
LEET = str.maketrans("013457", "oieast")
BASE64 = re.compile(r"(?<![\w+/=-])[A-Za-z0-9+/_-]{16,}(?:={0,2})(?![\w+/=-])")
SHORT_BASE64 = re.compile(r"(?:\b(?:base64|b64)\s*[:(]\s*)([A-Za-z0-9+/_-]{4,}={0,2})", re.I)
FRAGMENTED = re.compile(r"\b(?:[A-Za-z][ \t]){3,}[A-Za-z]\b")
PUNCTUATED = re.compile(r"\b(?:[A-Za-z][·._-]){2,}[A-Za-z]\b")


class InspectionLimit(ValueError):
    pass


@dataclass(frozen=True)
class TextView:
    text: str
    transformations: tuple[str, ...] = ()


def decoded_token(token, minimum=3):
    try:
        raw = base64.b64decode(token + "=" * (-len(token) % 4), altchars=b"-_", validate=True)
        decoded = raw.decode("utf-8")
        canonical = base64.urlsafe_b64encode(raw).decode().rstrip("=")
        if canonical != token.replace("+", "-").replace("/", "_").rstrip("="):
            return None
        if len(decoded) >= minimum and all(c.isprintable() or c in "\n\r\t" for c in decoded):
            return decoded
    except (ValueError, UnicodeError, binascii.Error):
        pass
    return None


def normalize(text):
    # Reject surrogate code points instead of crashing later while hashing/encoding.
    if re.search(r"[\ud800-\udfff]",text):
        raise InspectionLimit("Malformed Unicode scalar")
    value = text if text.isascii() else "".join(c for c in unicodedata.normalize("NFKC", text) if unicodedata.category(c) != "Cf")
    # Do not transliterate natural Cyrillic/Greek text. Map confusables only in
    # mixed-script tokens, where the ASCII context provides inspection evidence.
    if not value.isascii():
        value = re.sub(r"\w+", lambda m: m[0].translate(CONFUSABLES)
            if re.search(r"[A-Za-z]",m[0]) else m[0],value)
    value = re.sub(r"\s+", " ", value).strip()
    value = PUNCTUATED.sub(lambda m: re.sub(r"[·._-]", "", m[0]), value)
    value = FRAGMENTED.sub(lambda m: re.sub(r"\s", "", m[0]), value)
    # A standalone encoded leaf can be a short fragment. Preserve its alphabet
    # before leetspeak normalization; decoding is inspection-only.
    if re.fullmatch(r"[A-Za-z0-9+/_-]{4,}={0,2}", value) and decoded_token(value):
        return value
    if re.search(r"\\(?:u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2}|[0-7]{3})",value):
        return value
    # Keep percent escapes and long encoding tokens intact until decoding.
    return re.sub(r"(?<!%)\b[A-Za-z013457]*[013457][A-Za-z013457]*\b",
        lambda m: m[0].translate(LEET) if len(m[0]) <= 15 and any(c.isalpha() for c in m[0])
            and not SHORT_BASE64.search(value[max(0,m.start()-12):m.end()]) else m[0], value)


def decoded_candidates(text):
    candidates = []
    if re.search(r"%[0-9a-fA-F]{2}", text):
        try:
            candidates.append((unquote(text, errors="strict"), "url_decode"))
        except UnicodeError as exc:
            raise InspectionLimit("Malformed URL encoding") from exc
    if re.search(r"&(?:#[xX]?[0-9a-fA-F]+|[a-zA-Z]{2,12});", text):
        candidates.append((html.unescape(text), "html_decode"))
    if re.search(r"\\(?:u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2})", text):
        candidates.append((re.sub(r"\\(?:u([0-9a-fA-F]{4})|x([0-9a-fA-F]{2}))",
            lambda m: chr(int(m[1] or m[2], 16)), text), "escape_decode"))
    # Octal is interpreted only in an explicit shell-quoted inspection passage.
    if "$'" in text and re.search(r"\\[0-7]{3}", text):
        candidates.append((re.sub(r"\\([0-7]{3})", lambda m: chr(int(m[1],8)),text),"octal_decode"))
    replacements = []
    matches = [(m.start(),m.end(),m[0],8) for m in BASE64.finditer(text)]
    matches += [(m.start(),m.end(),m[1],3) for m in SHORT_BASE64.finditer(text)]
    if re.fullmatch(r"[A-Za-z0-9+/_-]{4,}={0,2}",text):
        matches.append((0,len(text),text,3))
    for start,end,token,minimum in sorted(matches):
        if any(start < b and end > a for a,b,_ in replacements):
            continue
        decoded=decoded_token(token,minimum)
        if decoded:
            replacements.append((start,end,decoded))
            if len(replacements) > 8:
                raise InspectionLimit("Too many encoded fragments")
    if replacements:
        value = text
        for start, end, decoded in reversed(replacements):
            value = value[:start] + decoded + value[end:]
        candidates.append((value, "base64_decode"))
    return candidates


def inspection_views(text):
    if not isinstance(text, str):
        raise TypeError("Inspection requires text")
    if len(text) > MAX_CHARS:
        raise InspectionLimit("Inspection input exceeds limit")
    canonical = normalize(text)
    views = [TextView(canonical, ("unicode/spacing",) if canonical != text else ())]
    seen = {canonical}
    total = len(canonical)
    frontier = list(views)
    for _ in range(MAX_DEPTH):
        next_frontier = []
        for view in frontier:
            for value, method in decoded_candidates(view.text):
                value = normalize(value)
                if value not in seen:
                    if len(views) >= MAX_VIEWS or total + len(value) > MAX_CHARS * 4:
                        raise InspectionLimit("Inspection expansion exceeds limit")
                    total += len(value)
                    seen.add(value)
                    new = TextView(value, (*view.transformations, method))
                    views.append(new)
                    next_frontier.append(new)
        frontier = next_frontier
        if not frontier:
            break
    if frontier and any(normalize(value) != view.text for view in frontier for value, _ in decoded_candidates(view.text)):
        raise InspectionLimit("Encoded nesting exceeds inspection depth")
    return views
