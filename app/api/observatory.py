"""Authenticated, read-only operational views. Never return private audit payloads."""
import json
import time
from collections import Counter
from datetime import datetime

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse

from app.api.dependencies import admin
from app.detection.trace import safe_excerpt
from app.evaluation.evidence import source_fingerprint
from app.settings import ROOT

router=APIRouter(prefix="/admin/detection",dependencies=[Depends(admin)])


def request_alerts(rows):
    """One investigation per request; retain every matched finding as evidence."""
    grouped={}
    severity_rank={"critical":4,"high":3,"medium":2,"low":1}
    for row in rows:
        key=row["request_id"]
        if key not in grouped:
            grouped[key]={k:v for k,v in row.items() if k!="flag"}
            grouped[key].update(findings=[],severity="low",detectors=[],categories=[])
        alert=grouped[key]
        finding=row["flag"]
        alert["findings"].append(finding)
        if severity_rank.get(finding.get("severity"),0)>severity_rank.get(alert["severity"],0):
            alert["severity"]=finding["severity"]
        for name,field in (("detectors","detection_type"),("categories","category")):
            value=finding.get(field)
            if value and value not in alert[name]:
                alert[name].append(value)
    for alert in grouped.values():
        alert["finding_count"]=len(alert["findings"])
        alert["disposition"]="blocked" if alert["decision"]=="BLOCK" else "review required" if alert["decision"] in {"WARN","REQUIRE_APPROVAL"} else "redacted" if alert["decision"]=="REDACT" else "signal on allowed request"
        alert["investigation_reason"]="Detectors disagree; inspect source and authorized intent" if alert["disagreement"] else "Review policy disposition and matched evidence"
    return list(grouped.values())


@router.get("/status")
async def status(request: Request):
    runtime=request.app.state.runtime
    semantic=runtime.pipeline.semantic
    items=list(getattr(runtime,"inspection_activity",[]))
    recent=[r for r in items if r["at"]>=time.monotonic()-60]
    decisions=dict(Counter(r["decision"] for r in items))
    windows=getattr(semantic,"last_details",{})
    try:
        validation=json.loads((ROOT/"artifacts/self-test.json").read_text())
        validation={"status":validation.get("status"),"current":validation.get("source_fingerprint")==source_fingerprint()}
    except (OSError,ValueError):
        validation={"status":"missing","current":False}
    return JSONResponse({"model":{"provider":getattr(semantic,"provider_id","none"),
        "state":"disabled" if getattr(semantic,"provider_id","none")=="none" else
            "ready" if getattr(semantic,"model",None) is not None else "provider_managed" if getattr(semantic,"provider_id",None)=="ollama" else "not_loaded_or_unavailable",
        "revision":getattr(semantic,"model_revision",None),"window_limit":getattr(semantic,"max_windows",None),
        "last_window_count":windows.get("window_count")},
        "policy":{"revision":runtime.policies.active.policy.metadata.revision,"feed_revision":runtime.policies.active.feed.revision},
        "admission":{"scope":"shared Redis lease/rate limit" if getattr(runtime,"redis",None) is not None else "single worker demo",
            "active_inspections":int(getattr(runtime,"inspection_lock",None) is not None and runtime.inspection_lock.locked()),
            "model_worker_active":bool(getattr(semantic,"_inflight",None) is not None and not semantic._inflight.done()),
            "queue_depth":0,"queue_policy":"reject excess; no waiting queue"},
        "activity":{"scope":"this process, inert operator inspections; last 500 completions","samples":len(items),
            "requests_per_second_60s":len(recent)/60,"decisions":decisions,
            "disagreements":sum(r["disagreement"] is True for r in items),
            "model_failures":sum(r["model_failure"] for r in items),"policy_failures":sum(r["policy_failure"] for r in items),
            "mean_latencies_ms":{key:sum(r[key] for r in items)/len(items) if items else None for key in ("latency_ms","ai_ms","rule_ms")}},
        "validation":validation,"guardrails":{"execution":"inspect → OPA authorize → execute; lab never executes",
            "output_boundary":"Buffered output inspection cannot undo upstream side effects",
            "torch_timeout":"Admission stays occupied until the thread exits; no physical cancellation",
            "egress":"Deployment must restrict service egress; application URL checks are not an OS firewall"}},headers={"Cache-Control":"no-store"})


@router.get("/flags")
async def flags(request: Request, severity: str | None=Query(None,max_length=16),
    detector: str | None=Query(None,max_length=32),category: str | None=Query(None,max_length=80),
    decision: str | None=Query(None,max_length=32),disagreement: bool | None=None,
    request_id: str | None=Query(None,max_length=128),since: datetime | None=None,until: datetime | None=None,
    limit: int=Query(100,ge=1,le=500)):
    events=await request.app.state.runtime.audit.recent(500)
    rows=[]
    for event in events:
        report=event.get("detection_report",{})
        if not report or request_id and report.get("request_id")!=request_id:
            continue
        stamp=report.get("timestamp","")
        try:
            instant=datetime.fromisoformat(stamp)
            if since and instant.timestamp()<since.timestamp() or until and instant.timestamp()>until.timestamp():
                continue
        except (ValueError,TypeError):
            continue
        if decision and report.get("final",{}).get("decision")!=decision or disagreement is not None and report.get("disagreement")!=disagreement:
            continue
        findings=report.get("findings",[])
        if report.get("ai",{}).get("verdict")=="malicious":
            findings=[*findings,{"rule_id":"AI_INJECTION","detection_type":"ai","category":"semantic_injection",
                "severity":"high","title":"Effective model score exceeds deployed threshold","confidence":None,
                "description":"Model evidence is a risk signal, not a calibrated probability.",
                "remediation":"Review provenance, quoted context and authorized intent.","evidence":{"model_revision":report["ai"].get("model_revision")}}]
        for f in findings:
            if severity and f.get("severity")!=severity or detector and f.get("detection_type")!=detector or category and f.get("category")!=category:
                continue
            rows.append({"timestamp":stamp,"request_id":report["request_id"],
                "risk":report.get("aggregation",{}).get("risk_score"),"decision":report.get("final",{}).get("decision"),
                "source":report.get("source",event.get("source_category","unknown")),
                "ai_score":report.get("ai",{}).get("score"),"rule_ids":report.get("deterministic",{}).get("rule_ids",[]),
                "disagreement":report.get("disagreement"),"action":f.get("action",report.get("final",{}).get("decision")),
                "latency_ms":report.get("latencies_ms",{}).get("total"),
                "flag":{k:f.get(k) for k in ("rule_id","category","severity","detection_type","title","description","remediation","confidence","path","evidence")},
                "actor":{"subject":event.get("subject"),"agent_id":event.get("agent_id")}})
    alerts=request_alerts(rows)
    return JSONResponse({"flags":rows[:limit],"alerts":alerts[:limit],"matched":len(rows),"scanned_events":len(events),
        "summary":{"requests":len(alerts),"findings":len(rows),"severities":dict(Counter(a["severity"] for a in alerts)),
            "dispositions":dict(Counter(a["disposition"] for a in alerts)),"disagreements":sum(a["disagreement"] is True for a in alerts)},
        "window":"latest 500 durable audit events; filters apply within this bounded window"},headers={"Cache-Control":"no-store"})


@router.get("/diagnostics")
async def diagnostics(kind: str=Query("summary",pattern="^(summary|false_positive|false_negative|disagreement)$"),
    language: str | None=Query(None,max_length=8),category: str | None=Query(None,max_length=80),limit: int=Query(100,ge=1,le=200),
    cohort: str=Query("all",pattern="^(all|known_v2|fresh_v3)$")):
    path=ROOT/"artifacts/iteration3/current-v3.json"
    if not path.is_file():
        path=ROOT/"artifacts/iteration3/current-v2.json"
    if not path.is_file():
        path=ROOT/"artifacts/iteration2/current-v2.json"
    try:
        report=json.loads(path.read_text(encoding="utf-8"))
    except (OSError,ValueError):
        return JSONResponse({"status":"missing","cases":[],"current":False})
    threshold=report["ai_threshold"]
    rows=report.get("results",[])
    if kind=="false_negative":
        try:
            rows=json.loads(path.with_name(path.stem+"-false-negatives.json").read_text(encoding="utf-8"))
        except (OSError,ValueError):
            rows=[]
    elif kind=="false_positive":
        try:
            rows=json.loads(path.with_name(path.stem+"-false-positives.json").read_text(encoding="utf-8"))
        except (OSError,ValueError):
            rows=[r for r in rows if not r["malicious"] and (r["ai_score"]>=threshold or r["deterministic_score"]>=.9)]
    elif kind=="disagreement":
        rows=[r for r in rows if r["agreement"] in {"ai_only","rule_only"}]
    else:
        rows=[]
    rows=[r for r in rows if (not language or r["language"]==language) and (not category or r["category"]==category)
        and (cohort=="all" or r.get("cohort","known_v2")==cohort)]
    safe=[]
    for row in rows[:limit]:
        item={k:v for k,v in row.items() if k not in {"normalized_representation","relevant_model_windows","ai_details","synthetic_input"}}
        if "normalized_representation" in row:
            item["normalized_representation"]=[safe_excerpt(t) for t in row["normalized_representation"][:8]]
        if "synthetic_input" in row:
            item["synthetic_input"]=[safe_excerpt(t) for t in row["synthetic_input"][:8]]
        safe.append(item)
    return JSONResponse({"status":"measured","current":report.get("source_fingerprint")==source_fingerprint(),
        "protocol":report.get("protocol"),"quality":report.get("quality"),
        "splits":report.get("splits") if cohort=="all" else report.get("cohort_summaries",{}).get(cohort),"cohort":cohort,
        "performance":report.get("performance"),"threshold":threshold,"cases":safe,"matched":len(rows),
        "scope":"authored inert synthetic diagnostics, not production labels"},headers={"Cache-Control":"no-store"})
