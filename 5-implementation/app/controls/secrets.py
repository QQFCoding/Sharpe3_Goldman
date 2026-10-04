import math
import re
from collections import Counter

from app.core.transaction import Finding, SecurityTransaction, text_leaves

PATTERNS = [
    ("PRIVATE_KEY", r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?(?:-----END [^\n]+-----|$)"),
    ("GITHUB_TOKEN", r"\b(?:gh[pousr]_[A-Za-z0-9_]{20,255}|github_pat_[A-Za-z0-9_]{20,255})\b"),
    ("AWS_ACCESS_KEY", r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    ("BEARER_TOKEN", r"(?i)\bbearer\s+[A-Za-z0-9_.~+/=-]{12,}"),
    (
        "SECRET_ASSIGNMENT",
        r"(?i)\b(?:password|passwd|pwd|api[_-]?key|secret(?:[_-]?key)?|"
        r"aws_secret_access_key|access[_-]?token)\b[\"']?\s*[:=]\s*[\"']?[^\s\"',;}]{6,}",
    ),
    (
        "CONNECTION_STRING",
        r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s/@:]+:[^\s/@]+@[^\s]+",
    ),
    ("API_KEY", r"\bsk-[A-Za-z0-9_-]{20,}\b"),
]
COMPILED = [(kind, re.compile(pattern)) for kind, pattern in PATTERNS]


def entropy(value: str) -> float:
    return -sum((n / len(value)) * math.log2(n / len(value)) for n in Counter(value).values())


def inspect(tx: SecurityTransaction, action: str) -> list[Finding]:
    findings = []
    for path, text in text_leaves(tx.payload):
        if (
            path
            and re.fullmatch(
                r"(?i)(password|passwd|pwd|api[_-]?key|secret(?:[_-]?key)?|"
                r"aws_secret_access_key|access[_-]?token)",
                str(path[-1]),
            )
            and len(text) >= 6
        ):
            findings.append(
                Finding(
                    code="SECRET_DETECTED",
                    control="secret-scanner",
                    action=action,
                    path=list(path),
                    start=0,
                    end=len(text),
                    replacement="<SECRET_REDACTED>",
                )
            )
        for kind, pattern in COMPILED:
            for match in pattern.finditer(text):
                findings.append(
                    Finding(
                        code="SECRET_DETECTED",
                        control="secret-scanner",
                        action=action,
                        path=list(path),
                        start=match.start(),
                        end=match.end(),
                        replacement=f"<{kind}_REDACTED>",
                    )
                )
        for match in re.finditer(r"(?i)\b(?:token|key|secret)\s*[:=]\s*([A-Za-z0-9+/=_-]{24,})", text):
            if entropy(match[1]) >= 3.5:
                findings.append(
                    Finding(
                        code="SECRET_DETECTED",
                        control="secret-scanner",
                        action=action,
                        path=list(path),
                        start=match.start(),
                        end=match.end(),
                        replacement="<SECRET_REDACTED>",
                    )
                )
    return findings
