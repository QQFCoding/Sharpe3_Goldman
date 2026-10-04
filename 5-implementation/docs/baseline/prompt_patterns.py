import re

from app.controls.discussion import security_discussion
from app.core.transaction import Finding, SecurityTransaction, text_leaves

PATTERNS = [
    r"(?i)\bignore\s+(?:all\s+)?(?:previous|prior|above|system)\s+(?:instructions|rules|prompts)",
    r"(?i)\b(?:override|disregard|forget)\s+(?:all\s+)?(?:system|previous|safety)\s+(?:instructions|rules|policy)",
    r"(?i)\b(?:reveal|print|expose)\s+(?:the\s+)?(?:system\s+prompt|hidden\s+instructions)",
    r"(?i)<\|(?:im_start|system|start_header_id)\|>",
    r"(?i)\b(?:send|upload|exfiltrate).{0,80}(?:credentials|secrets|api.?keys)\b",
]


def inspect(tx: SecurityTransaction) -> list[Finding]:
    if security_discussion(tx):
        return []
    for _, text in text_leaves(tx.payload):
        if any(re.search(pattern, text) for pattern in PATTERNS):
            tx.risk.prompt_injection = 0.95
            return [Finding(code="PROMPT_INJECTION_PATTERN", control="prompt-patterns")]
    return []
