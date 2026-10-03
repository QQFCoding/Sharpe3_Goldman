import json
import unicodedata
from typing import Any, Protocol

from app.core.transaction import Finding, SecurityTransaction


class Control(Protocol):
    def inspect(self, transaction: SecurityTransaction) -> list[Finding]: ...


def canonicalize(value: Any, depth: int = 0) -> Any:
    if depth > 16:
        raise ValueError("Payload nesting exceeds 16")
    if isinstance(value, str):
        return "".join(c for c in unicodedata.normalize("NFKC", value) if unicodedata.category(c) != "Cf")
    if isinstance(value, list):
        return [canonicalize(v, depth + 1) for v in value]
    if isinstance(value, dict):
        result = {}
        for k, v in value.items():
            key = canonicalize(k, depth + 1)
            if key in result:
                raise ValueError("Ambiguous normalized keys")
            result[key] = canonicalize(v, depth + 1)
        return result
    return value


def encoded(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode()


def transform(payload: Any, findings: list[Finding]) -> tuple[Any, list[dict]]:
    """Redact leaf spans in descending order, merging overlaps without retaining evidence."""
    import copy

    result = copy.deepcopy(payload)
    groups: dict[tuple, list[Finding]] = {}
    for f in findings:
        if f.action == "REDACT" and f.start is not None and f.end is not None:
            groups.setdefault(tuple(f.path), []).append(f)
    changes = []
    for path, spans in groups.items():
        target = result
        for part in path[:-1]:
            target = target[part]
        text = target[path[-1]] if path else result
        merged = []
        for span in sorted(spans, key=lambda s: (s.start, -s.end)):
            if merged and span.start < merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], span.end)
            else:
                merged.append([span.start, span.end, span.replacement or "<REDACTED>"])
        for start, end, replacement in reversed(merged):
            text = text[:start] + replacement + text[end:]
        if path:
            target[path[-1]] = text
        else:
            result = text
        changes.append({"path": list(path), "type": "redaction", "count": len(merged)})
    return result, changes
