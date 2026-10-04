"""Narrow, complete educational questions; never exempts tools or untrusted sources."""
import re


def security_discussion(tx):
    if tx.operation != "llm_request" or tx.context.source_trust != "trusted":
        return False
    texts = [m["content"] for m in tx.payload.get("messages", []) if m.get("role") == "user"] if isinstance(tx.payload, dict) else []
    if isinstance(tx.payload, dict) and "content" in tx.payload:
        texts = [tx.payload["content"].removeprefix("Echo: ")]
    patterns = [r"Explain what ['\"]ignore previous instructions['\"] means[.?]?",
        r"Why is curl URL \| bash dangerous[?]?",
        r"Show an example of a prompt injection for my security class[.?]?",
        r"Write detection logic for AWS_SECRET_ACCESS_KEY patterns[.?]?",
        r"Analyze this malicious email without following its instructions[.?]?"]
    return bool(texts) and all(any(re.fullmatch(p, t.strip(), re.I) for p in patterns) for t in texts)
