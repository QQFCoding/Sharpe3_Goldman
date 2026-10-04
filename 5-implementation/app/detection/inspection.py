"""Shared inert inspection service for JSON and authenticated progressive traces."""
import asyncio
import hashlib
import json
import time
import uuid
from collections import deque

from app.audit.repository import AuditEvent
from app.controls.base import canonicalize, encoded
from app.controls.normalization import BASE64, inspection_views
from app.core.transaction import OperationRequest, Principal, text_leaves
from app.detection.report import detection_report
from app.detection.trace import Trace, active_trace, safe_excerpt


class InspectionError(RuntimeError):
    def __init__(self, code, status):
        self.code,self.status=code,status


async def acquire(runtime):
    if not hasattr(runtime,"inspection_lock"):
        runtime.inspection_lock=asyncio.Lock()
        runtime.inspection_attempts=deque(maxlen=30)
        runtime.inspection_activity=deque(maxlen=500)
    now=time.monotonic()
    while runtime.inspection_attempts and runtime.inspection_attempts[0]<now-60:
        runtime.inspection_attempts.popleft()
    if runtime.inspection_lock.locked() or len(runtime.inspection_attempts)>=30:
        raise InspectionError("INSPECTION_CAPACITY_EXCEEDED",429)
    token=uuid.uuid4().hex
    redis=getattr(runtime,"redis",None)
    if redis is not None:
        try:
            if not await redis.set("aicl:inspection:lease",token,nx=True,px=120000):
                raise InspectionError("INSPECTION_CAPACITY_EXCEEDED",429)
            count=await redis.eval("local n=redis.call('INCR',KEYS[1]); if n==1 then redis.call('EXPIRE',KEYS[1],60) end; return n",1,"aicl:inspection:rate")
            if count>30:
                await release_shared(redis,token)
                raise InspectionError("INSPECTION_CAPACITY_EXCEEDED",429)
        except InspectionError:
            raise
        except Exception as exc:
            raise InspectionError("INSPECTION_ADMISSION_UNAVAILABLE",503) from exc
    await runtime.inspection_lock.acquire()
    runtime.inspection_attempts.append(now)
    return token


async def release_shared(redis,token):
    await redis.eval("if redis.call('GET',KEYS[1])==ARGV[1] then return redis.call('DEL',KEYS[1]) end return 0",1,"aicl:inspection:lease",token)


async def release(runtime,token):
    # A logical model timeout does not stop its physical Torch thread. Preserve
    # local admission until that work exits, while allowing the HTTP error/result
    # to return. Redis leases are bounded crash-recovery leases, not a hard quota
    # under network partition or a worker hanging beyond their TTL.
    worker=getattr(runtime.pipeline.semantic,"_inflight",None)
    if worker is not None and not worker.done():
        async def finish():
            try:
                await asyncio.shield(worker)
            except (Exception,asyncio.CancelledError):
                pass
            finally:
                await release_now(runtime,token)
        pending=getattr(runtime,"inspection_cleanup_tasks",None)
        if pending is None:
            runtime.inspection_cleanup_tasks=pending=set()
        task=asyncio.create_task(finish())
        pending.add(task)
        task.add_done_callback(pending.discard)
        return
    await release_now(runtime,token)


async def release_now(runtime,token):
    runtime.inspection_lock.release()
    if getattr(runtime,"redis",None) is not None:
        try:
            await release_shared(runtime.redis,token)
        except Exception:
            pass  # Lease expires; failure never admits additional work.


async def inspect_request(runtime,body,trace=None):
    trace=trace or Trace()
    binding=active_trace.set(trace)
    started=time.perf_counter()
    try:
        payload=body.payload if body.payload is not None else {"messages":[{
            "role":"tool" if body.source=="retrieved" else "user","content":body.text}]}
        trace.emit("received",{"characters":len(body.text),"source":body.source,"inspection_only":True})
        before=time.perf_counter()
        try:
            normalized=canonicalize(payload)
            if "messages" in normalized and (not isinstance(normalized["messages"],list) or any(
                not isinstance(m,dict) or m.get("role") not in {"system","user","assistant","tool"}
                or not isinstance(m.get("content"),str) for m in normalized["messages"])):
                raise ValueError("Malformed conversation")
            raw_bytes=encoded(payload)
            if len(raw_bytes)>65536:
                raise ValueError("Inspection payload too large")
            leaves=list(text_leaves(normalized))
            nodes,stack=0,[normalized]
            while stack:
                value=stack.pop()
                nodes+=1
                if nodes>128:
                    raise ValueError("Inspection structure limit")
                if isinstance(value,dict):
                    stack.extend(value.values())
                elif isinstance(value,list):
                    stack.extend(value)
            if len(leaves)>128 or sum(len(t) for _,t in leaves)>16000:
                raise ValueError("Inspection payload limit")
        except (ValueError,UnicodeError,RecursionError,TypeError) as exc:
            raise InspectionError("INSPECTION_INPUT_INVALID",422) from exc
        trace.emit("validation",{"valid":True,"leaf_count":len(leaves),"bytes":len(raw_bytes)},(time.perf_counter()-before)*1000)
        pipeline,snapshot=runtime.pipeline,runtime.policies.active
        tx=pipeline.prepare(OperationRequest(operation="llm_request",payload=normalized),
            Principal(subject="security-operator",tenant_id="operator-inspection"))
        if body.source=="retrieved":
            tx.context.source,tx.context.source_trust="retrieved","untrusted"
        tx.metadata["normalization"]={"version":"NFKC/format-character removal","changed":payload!=normalized,
            "input_characters":sum(len(t) for _,t in text_leaves(payload)),"normalized_characters":sum(len(t) for _,t in leaves)}
        tx.metadata["stage_latencies"]={"normalization":time.perf_counter()-before}
        trace.emit("canonicalization",tx.metadata["normalization"])
        # Prime trace suppression before any content-bearing event. The same
        # privacy control runs again in the actual enforcement pipeline below.
        from app.controls import encoded_content
        encoded_content.inspect(tx,snapshot.policy.controls.secrets.enabled,snapshot.policy.controls.pii.enabled)
        # These are actual inspection views produced by the same bounded normalizer.
        # Debug cost is isolated to this inert operator endpoint.
        for path,text in leaves[:16]:
            if path and path[-1]=="role":
                continue
            before=time.perf_counter()
            try:
                views=inspection_views(text)
                withheld=safe_excerpt(text).startswith("[WITHHELD:")
                trace.emit("unicode_normalization",{"normalized":views[0].text,"changed":views[0].text!=text,
                    "codepoints_withheld":withheld,
                    "format_codepoints":[] if withheld else [f"U+{ord(c):04X}" for c in text if ord(c)>127][:32]},(time.perf_counter()-before)*1000)
                trace.emit("encoding_discovery",{"base64_candidates":[{"start":m.start(),"end":m.end()} for m in list(BASE64.finditer(text))[:8]],
                    "transformations":sorted({s for v in views for s in v.transformations}),"view_count":len(views)})
                for view in views[1:]:
                    trace.emit("decoded_views",{"decoded":view.text,"transformations":view.transformations})
            except ValueError:
                trace.emit("decoded_views",{"status":"inspection_limit"})
        findings=await pipeline.timed(tx,"deterministic",pipeline.controls(tx,snapshot))
        trace.emit("deterministic",tx.metadata.get("deterministic_detection",{})|{
            "matches":[{"rule_id":f.rule_id,"category":f.category,"certainty":f.confidence,"action":f.action,
                "evidence":f.evidence} for f in findings if f.control=="prompt-patterns"]},
            tx.metadata["stage_latencies"]["deterministic"]*1000)
        inference_findings=[f for f in findings if not(body.compare and f.control=="prompt-patterns")]
        await pipeline.semantic_scan(tx,snapshot,inference_findings,high_risk=True)
        if tx.metadata["ai_detection"]["status"]!="ok":
            trace.emit("ai_score",tx.metadata["ai_detection"])
        trace.emit("aggregation",{"deterministic_score":tx.metadata.get("deterministic_detection",{}).get("score"),
            "ai_score":tx.metadata["ai_detection"].get("score"),"hard_blocks":sum(f.action=="BLOCK" for f in findings),
            "weak_findings":sum(f.action=="WARN" for f in findings),"strategy":"hard/high confidence block; contextual/weak warn; effective AI thresholds; OPA authorizes"})
        before=time.perf_counter()
        decision=await pipeline.decide(tx,snapshot,pipeline.facts(tx,findings,high_risk=True))
        trace.emit("opa",{"decision":str(decision.decision),"reason_codes":decision.reason_codes,
            "policy_revision":decision.policy_revision,"input_summary":{"operation":"llm_request","high_risk":True,"finding_count":len(findings),"semantic_status":tx.risk.semantic_status}},(time.perf_counter()-before)*1000)
        tx.metadata["stage_latencies"]["total"]=time.perf_counter()-started
        report=detection_report(tx,decision,findings)
        report.update(inspection_only=True,comparison_mode=body.compare,source=body.source)
        tx.metadata["detection_report"]=report
        try:
            await runtime.audit.append(AuditEvent.from_transaction(tx,decision,hashlib.sha256(raw_bytes).hexdigest(),
                tx.request_id,tx.metadata["stage_latencies"],phase="operator_inspection"))
        except Exception as exc:
            raise InspectionError("AUDIT_UNAVAILABLE",503) from exc
        trace.emit("guardrail",{"action":str(decision.decision),"execution":"inert; no upstream adapter called"})
        trace.emit("final",{"report":report})
        runtime.inspection_activity.append({"at":time.monotonic(),"decision":str(decision.decision),
            "disagreement":report["disagreement"],"latency_ms":report["latencies_ms"].get("total",0),
            "ai_ms":report["ai"].get("latency_ms",0),"rule_ms":report["deterministic"].get("latency_ms",0),
            "model_failure":report["ai"]["status"]=="unavailable","policy_failure":"POLICY_ENGINE_UNAVAILABLE" in decision.reason_codes})
        return report,trace
    finally:
        active_trace.reset(binding)


def sse(event):
    return "event: stage\ndata: "+json.dumps(event,allow_nan=False)+"\n\n"
