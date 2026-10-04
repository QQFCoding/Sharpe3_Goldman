"""Authenticated governance views: explicit policy fields and real scoped accounting."""
import json
from datetime import UTC, datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse, Response

from app.api.dependencies import admin
from app.budget.manager import InMemoryBudgetManager, RedisBudgetManager, agent_key, keys
from app.core.transaction import Operation, SecurityTransaction, StrictModel, WorkflowContext

router = APIRouter(prefix="/admin/governance", dependencies=[Depends(admin)])
NO_STORE = {"Cache-Control": "no-store"}

# Reading uses one Redis evaluation and filters expired reservations without changing admission state.
SNAPSHOT_LUA = r"""
local state, active, rate, agent = KEYS[1], KEYS[2], KEYS[3], KEYS[4]
local now = tonumber(ARGV[1])
local function num(name) return tonumber(redis.call('HGET', state, name) or '0') end
local reserved_c, reserved_t, active_count = 0, 0, 0
for _, id in ipairs(redis.call('ZRANGEBYSCORE', active, '(' .. now, '+inf')) do
  local raw = redis.call('HGET', state, 'r:' .. id)
  if raw then
    local held = cjson.decode(raw)
    active_count = active_count + 1
    if not held.charged then
      reserved_c = reserved_c + held.credits
      reserved_t = reserved_t + held.tokens
    end
  end
end
return cjson.encode({present=redis.call('EXISTS', state) == 1,
  start=tonumber(redis.call('HGET', state, 'start') or now),
  steps=num('steps'), llm_calls=num('llm'), tool_calls=num('tool'),
  credits_used=num('credits'), tokens_used=num('tokens'),
  credits_reserved=reserved_c, tokens_reserved=reserved_t, active=active_count,
  concurrent=redis.call('ZCOUNT', agent, '(' .. now, '+inf'),
  requests=redis.call('ZCOUNT', rate, '(' .. (now - 60), '+inf')})
"""


def identities(runtime):
    return sorted({(p.tenant_id, p.subject, p.agent_id or "") for p in runtime.auth.records.values()})


@router.get("")
async def governance(request: Request):
    runtime = request.app.state.runtime
    snapshot = runtime.policies.active
    p = snapshot.policy
    semantic = p.controls.prompt_injection.semantic
    provider = getattr(runtime.pipeline.semantic, "provider_id", "none")
    thresholds = semantic.provider_thresholds.get(provider, semantic)
    body = {
        "schema_version": "governance-v1",
        "policy": {"revision": p.metadata.revision, "feed_revision": snapshot.feed.revision,
            "previous_valid_revision": runtime.policies.last_known_good.policy.metadata.revision,
            "mode": p.mode, "defaults": p.defaults.model_dump()},
        "controls": {
            "pii": p.controls.pii.model_dump(), "secrets": p.controls.secrets.model_dump(),
            "prompt_injection": {"enabled": p.controls.prompt_injection.enabled,
                "deterministic_enabled": p.controls.prompt_injection.deterministic_enabled,
                "semantic_enabled": semantic.enabled, "always_scan": semantic.always_scan,
                "uncertain_read": semantic.uncertain_read,
                "provider": provider, "review_threshold": thresholds.review_threshold,
                "block_threshold": thresholds.block_threshold,
                "provider_state": "disabled" if provider == "none" else "ready" if getattr(runtime.pipeline.semantic, "model", None) is not None else "provider_managed" if provider == "ollama" else "unavailable",
                "threshold_source": "provider_override" if provider in semantic.provider_thresholds else "default"},
            "information_flow": p.information_flow.model_dump(),
            "task_alignment": p.task_alignment.model_dump(), "memory": p.memory.model_dump(),
            "network": p.network.model_dump(), "mcp": p.mcp.model_dump(),
            "threat_intelligence": {"enabled": p.threat_intelligence.enabled},
            "authentication": {"required": True}, "audit": p.audit.model_dump(),
        },
        "resources": {"models": p.models.model_dump()["allowed"], "tools": p.tools.model_dump(),
            "agents": p.agents.allowed, "apis": p.apis.allowed},
        "budgets": p.budgets.model_dump(), "request_limits": p.limits.model_dump(),
        "costs": {"unit": "configured credits", "provider_billing_verified": False,
            **p.resource_costs.model_dump()},
        "storage": {"budget": "redis" if isinstance(runtime.budgets, RedisBudgetManager) else "process_memory",
            "audit": "postgresql" if runtime.audit.pool else "process_memory",
            "audit_retention": "database retention policy" if runtime.audit.pool else "latest 10000 events; restart clears history"},
        "identities": [{"tenant_id": t, "subject": s, "agent_id": a or None} for t, s, a in identities(runtime)],
        "last_reload": getattr(runtime, "governance_last_reload", None),
        "reload_scope": "Policy and feed are validated together; this process publishes one atomic snapshot.",
        "inspection_scope": "The inert detection lab does not reserve execution budgets. Run gateway operations to measure usage.",
    }
    return JSONResponse(body, headers=NO_STORE)


async def budget_snapshot(manager, tx):
    key, rate = keys(tx)
    now = manager.clock()
    if isinstance(manager, RedisBudgetManager):
        return json.loads(await manager.redis.eval(SNAPSHOT_LUA, 4, key, key + ":active", rate, agent_key(key), now)), now
    if not isinstance(manager, InMemoryBudgetManager):
        raise RuntimeError("Unsupported budget accounting backend")
    async with manager._lock:
        state = manager.workflows.get(key)
        active = [r for r in (state or {}).get("active", {}).values() if r[2] > now]
        return {
            "present": state is not None, "start": (state or {}).get("start", now),
            "steps": (state or {}).get("steps", 0), "llm_calls": (state or {}).get("llm", 0),
            "tool_calls": (state or {}).get("tool", 0), "credits_used": (state or {}).get("credits", 0),
            "tokens_used": (state or {}).get("tokens", 0),
            "credits_reserved": sum(r[0] for r in active if not r[3]),
            "tokens_reserved": sum(r[1] for r in active if not r[3]), "active": len(active),
            "concurrent": sum(expiry > now for expiry in manager.agent_active.get(agent_key(key), {}).values()),
            "requests": sum(t > now - 60 for t in manager.rates.get(rate, [])),
        }, now


@router.get("/budget")
async def budget(request: Request,
    subject: Annotated[str, Query(min_length=1, max_length=128)],
    tenant_id: Annotated[str, Query(min_length=1, max_length=128)],
    workflow_id: Annotated[str, Query(min_length=1, max_length=128)],
    agent_id: Annotated[str | None, Query(max_length=128)] = None):
    runtime = request.app.state.runtime
    candidates = [p for p in runtime.auth.records.values() if p.subject == subject and p.tenant_id == tenant_id
        and p.agent_id == (agent_id or None)]
    if not candidates:
        raise HTTPException(status_code=404, detail={"error": "IDENTITY_NOT_FOUND"})
    # Multiple credentials for the same principal refer to the same accounting owner.
    tx = SecurityTransaction(principal=candidates[0], operation=Operation.LLM_REQUEST, payload={})
    tx.context.workflow = WorkflowContext(workflow_id=workflow_id)
    limits = runtime.policies.active.policy.budgets
    try:
        state, now = await budget_snapshot(runtime.budgets, tx)
    except Exception:
        return JSONResponse({"error": "BUDGET_ACCOUNTING_UNAVAILABLE"}, status_code=503, headers=NO_STORE)
    rows = {}
    for name, used, reserved, limit in (
        ("credits", state["credits_used"], state["credits_reserved"], limits.per_agent.credit_limit),
        ("tokens", state["tokens_used"], state["tokens_reserved"], limits.per_agent.token_limit),
        ("steps", state["steps"], 0, limits.per_agent.max_steps),
        ("llm_calls", state["llm_calls"], 0, limits.per_agent.max_llm_calls),
        ("tool_calls", state["tool_calls"], 0, limits.per_agent.max_tool_calls)):
        rows[name] = {"used": used, "reserved": reserved, "limit": limit,
            "remaining": max(0, limit - used - reserved), "over_limit": used + reserved > limit + 1e-9}
    elapsed = max(0, now - state["start"]) if state["present"] else 0
    body = {"schema_version": "budget-snapshot-v1", "timestamp": datetime.now(UTC).isoformat(),
        "scope": {"subject": subject, "tenant_id": tenant_id, "agent_id": agent_id or None,
            "workflow_id": workflow_id, "unit": "one principal and workflow; concurrency spans its workflows; rate spans subject and tenant"},
        "policy_revision": runtime.policies.active.policy.metadata.revision,
        "backend": "redis" if isinstance(runtime.budgets, RedisBudgetManager) else "process_memory",
        "workflow_present": state["present"], "usage": rows,
        "workflow_time": {"elapsed_seconds": elapsed, "limit_seconds": limits.per_agent.max_wall_time_seconds,
            "remaining_seconds": max(0, limits.per_agent.max_wall_time_seconds - elapsed)},
        "active_reservations": state["active"],
        "concurrency": {"active": state["concurrent"], "limit": limits.per_agent.concurrent_requests,
            "remaining": max(0, limits.per_agent.concurrent_requests - state["concurrent"])},
        "rate": {"requests_last_60s": state["requests"], "limit": limits.per_user.requests_per_minute,
            "remaining": max(0, limits.per_user.requests_per_minute - state["requests"]),
            "includes_rejected_reservation_attempts": True},
        "accounting_note": "Used includes conservative charges for started operations until reconciliation; expired unstarted holds are excluded. Credits are configured units, not a provider invoice."}
    return JSONResponse(body, headers=NO_STORE)


class ReloadRequest(StrictModel):
    kind: Literal["policy", "threat_feed"] = "policy"


@router.post("/reload")
async def reload(body: ReloadRequest, request: Request):
    runtime = request.app.state.runtime
    before = runtime.policies.active.policy.metadata.revision
    before_feed = runtime.policies.active.feed.revision
    ok = False
    try:
        snapshot = await runtime.policies.reload()
        runtime.metrics.revisions(snapshot)
        ok = True
    except Exception:
        # Parser diagnostics and configured values never leave the gateway.
        pass
    runtime.metrics.reloads.labels(body.kind, "success" if ok else "failure").inc()
    result = {"timestamp": datetime.now(UTC).isoformat(), "kind": body.kind,
        "status": "success" if ok else "rejected", "previous_revision": before,
        "previous_feed_revision": before_feed,
        "policy_revision": runtime.policies.active.policy.metadata.revision,
        "feed_revision": runtime.policies.active.feed.revision,
        "changed": before != runtime.policies.active.policy.metadata.revision or before_feed != runtime.policies.active.feed.revision,
        "error": None if ok else "POLICY_RELOAD_INVALID",
        "last_valid_policy_retained": not ok}
    runtime.governance_last_reload = result
    return JSONResponse(result, status_code=200 if ok else 422, headers=NO_STORE)


@router.get("/audit/export")
async def audit_export(request: Request, limit: Annotated[int, Query(ge=1, le=10000)] = 1000,
    tenant_id: Annotated[str | None, Query(max_length=128)] = None,
    subject: Annotated[str | None, Query(max_length=128)] = None):
    runtime = request.app.state.runtime
    try:
        events = await runtime.audit.recent(limit)
    except Exception:
        return JSONResponse({"error": "AUDIT_UNAVAILABLE"}, status_code=503, headers=NO_STORE)
    rows = []
    for event in events:
        if tenant_id and event.get("tenant_id") != tenant_id or subject and event.get("subject") != subject:
            continue
        # Explicit allowlist: no raw payload, content excerpt, transformation or arbitrary metadata.
        row = {k: event.get(k) for k in ("request_id", "trace_id", "timestamp", "subject", "tenant_id",
            "agent_id", "operation", "resource", "phase", "workflow_id", "effect", "source_category",
            "execution_id", "prompt_hash", "budget_reserved", "budget_consumed", "latencies")}
        security = event.get("security", {})
        row["security"] = {k: security.get(k) for k in ("decision", "reason_codes", "controls",
            "policy_revision", "threat_feed_revision")}
        row["findings"] = [{k: finding.get(k) for k in ("rule_id", "code", "control", "category",
            "severity", "action", "detection_type")} for finding in event.get("detection_report", {}).get("findings", [])[:64]]
        rows.append(row)
    headers = {**NO_STORE, "Content-Disposition": 'attachment; filename="aicl-audit.ndjson"',
        "X-Audit-Scanned": str(len(events)), "X-Audit-Exported": str(len(rows)),
        "X-Audit-Scope": "latest bounded window; newest first"}
    return Response("".join(json.dumps(row, ensure_ascii=True) + "\n" for row in rows),
        media_type="application/x-ndjson", headers=headers)
