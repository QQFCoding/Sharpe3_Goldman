"""Opt-in, bounded ephemeral trace. Content excerpts never enter durable audit."""
import contextvars
import hashlib
import math
import time

from app.controls.normalization import inspection_views
from app.core.transaction import Principal, SecurityTransaction

active_trace = contextvars.ContextVar("detection_trace",default=None)
STAGES = {"received","validation","canonicalization","unicode_normalization","encoding_discovery",
    "decoded_views","deterministic","privacy","ai_input","ai_window","ai_score","aggregation",
    "opa","guardrail","final","error"}


def safe_excerpt(text, limit=1000):
    from app.controls import pii, secrets
    trace=active_trace.get()
    if trace is not None and any(value and value in text for value in trace.withheld_text):
        return "[WITHHELD: reconstructed sensitive content]"
    try:
        for view in inspection_views(text):
            tx=SecurityTransaction(principal=Principal(subject="trace",tenant_id="trace"),
                operation="llm_request",payload=view.text)
            if secrets.inspect(tx,"BLOCK") or pii.inspect(tx,"BLOCK"):
                return "[WITHHELD: sensitive content detected]"
    except (ValueError,UnicodeError):
        return "[WITHHELD: inspection limit or malformed encoding]"
    # Excerpts are only returned to the authenticated live requester, not persisted.
    return text[:limit] + (" … [truncated]" if len(text)>limit else "")


def scrub(data, depth=0):
    if depth>9:
        return "[bounded]"
    if isinstance(data,dict):
        return {safe_excerpt(str(k),64):scrub(v,depth+1) for k,v in list(data.items())[:40]}
    if isinstance(data,(list,tuple)):
        return [scrub(v,depth+1) for v in data[:40]]
    if isinstance(data,str):
        return safe_excerpt(data,1500)
    if isinstance(data,float) and not math.isfinite(data):
        return "[invalid numeric trace data]"
    if data is None or isinstance(data,(bool,int,float)):
        return data
    return "[unsupported trace data]"


class Trace:
    def __init__(self, callback=None):
        self.started=time.perf_counter()
        self.events=[]
        self.withheld_text=set()
        self.callback=callback

    def emit(self, stage, data=None, duration_ms=None):
        if stage not in STAGES or len(self.events)>=240:
            return
        if duration_ms is not None and (not isinstance(duration_ms,(int,float)) or not math.isfinite(duration_ms) or duration_ms<0):
            duration_ms=None
        event={"sequence":len(self.events),"stage":stage,
            "elapsed_ms":max(0,(time.perf_counter()-self.started)*1000),
            "duration_ms":duration_ms,"data":scrub(data or {})}
        self.events.append(event)
        if self.callback:
            self.callback(event)


def emit(stage,data=None,duration_ms=None):
    trace=active_trace.get()
    if trace is not None:
        trace.emit(stage,data,duration_ms)


def text_hash(text):
    return hashlib.sha256(text.encode("utf-8",errors="replace")).hexdigest()
