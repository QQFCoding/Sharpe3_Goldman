import ipaddress
import re

from app.core.transaction import Finding, SecurityTransaction, text_leaves


def luhn(value: str) -> bool:
    digits = [int(c) for c in value if c.isdigit() and c.isascii()]
    if not 13 <= len(digits) <= 19 or len(set(digits)) < 2:
        return False
    return (
        sum((d * 2 - 9 if d > 4 else d * 2) if i % 2 else d for i, d in enumerate(reversed(digits))) % 10 == 0
    )


def pesel(value: str) -> bool:
    return (
        len(value) == 11
        and value.isascii()
        and value.isdigit()
        and len(set(value)) > 1
        and (sum(int(d) * w for d, w in zip(value[:10], [1, 3, 7, 9, 1, 3, 7, 9, 1, 3])) + int(value[-1]))
        % 10
        == 0
    )


def iban(value: str) -> bool:
    value = re.sub(r"\s", "", value).upper()
    lengths = {"PL": 28, "GB": 22, "DE": 22, "FR": 27, "ES": 24, "IT": 27, "NL": 18}
    if len(value) != lengths.get(value[:2], -1):
        return False
    numeric = "".join(str(ord(c) - 55) if c.isalpha() else c for c in value[4:] + value[:4])
    return numeric.isdigit() and int(numeric) % 97 == 1


def valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


PATTERNS = [
    ("EMAIL", re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b"), lambda _: True),
    ("IBAN", re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]){11,30}\b"), iban),
    ("PESEL", re.compile(r"(?<!\d)\d{11}(?!\d)"), pesel),
    ("CREDIT_CARD", re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)"), luhn),
    ("PHONE", re.compile(r"(?<![\w])\+\d{1,3}[ -]?(?:\d[ -]?){7,11}\d(?!\d)"), lambda _: True),
    ("IP", re.compile(r"(?<![\w])(?:\d{1,3}\.){3}\d{1,3}(?![\w])"), valid_ip),
    ("IP", re.compile(r"(?<![\w])(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(?![\w])"), valid_ip),
]


def inspect(tx: SecurityTransaction, action: str) -> list[Finding]:
    findings = []
    for path, text in text_leaves(tx.payload):
        for kind, pattern, validator in PATTERNS:
            for match in pattern.finditer(text):
                if validator(match[0]):
                    findings.append(
                        Finding(
                            code="PII_DETECTED",
                            control="pii-scanner",
                            action=action,
                            path=list(path),
                            start=match.start(),
                            end=match.end(),
                            replacement=f"<{kind}_REDACTED>",
                        )
                    )
    return findings
