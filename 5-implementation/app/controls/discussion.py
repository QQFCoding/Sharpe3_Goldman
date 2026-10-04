"""Compatibility discussion predicate; span-aware inspection lives in context.py."""
from app.controls.context import discussion_context, observational_question
from app.core.transaction import text_leaves


def security_discussion(tx):
    if tx.operation != "llm_request" or tx.context.source_trust != "trusted":
        return False
    messages=tx.payload.get("messages",[]) if isinstance(tx.payload,dict) else []
    if any(not isinstance(m,dict) or m.get("role")!="user" for m in messages):
        return False
    texts=[t for p,t in text_leaves(tx.payload) if not p or p[-1]!="role"]
    return bool(texts) and all(discussion_context(t.removeprefix("Echo: ")) or observational_question(t.removeprefix("Echo: ")) for t in texts)
