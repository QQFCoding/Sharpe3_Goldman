from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse
from pydantic import Field

from app.api.dependencies import admin
from app.controls.base import canonicalize
from app.core.auth import approval_digest
from app.core.transaction import OperationRequest, StrictModel

router = APIRouter(prefix="/admin", dependencies=[Depends(admin)])


@router.get("/mcp/registry")
async def registry(request: Request):
    return {"findings": request.app.state.runtime.pipeline.manifests.analyze()}


class ExecutionResolution(StrictModel):
    subject: str
    tenant_id: str
    execution_id: str = Field(min_length=1, max_length=128)
    disposition: Literal["COMPLETED", "FAILED"]
    evidence: str = Field(min_length=10, max_length=8192)


@router.post("/executions/resolve")
async def resolve_execution(body: ExecutionResolution, request: Request):
    import hashlib

    from app.audit.repository import AuditEvent
    from app.core.decision import Decision, DecisionResult
    from app.core.transaction import Operation, Principal, SecurityTransaction
    runtime = request.app.state.runtime
    identity = Principal(subject=body.subject, tenant_id=body.tenant_id)
    tx = SecurityTransaction(principal=identity, operation=Operation.API_CALL, payload={})
    tx.metadata["execution_id"] = body.execution_id
    snapshot = runtime.policies.active
    decision = DecisionResult(decision=Decision.ALLOW, reason_codes=["OPERATOR_EXECUTION_RESOLUTION"],
        controls=["execution-operator"], policy_revision=snapshot.policy.metadata.revision,
        threat_feed_revision=snapshot.feed.revision, request_id=tx.request_id)
    await runtime.audit.append(AuditEvent.from_transaction(tx, decision,
        hashlib.sha256(body.evidence.encode()).hexdigest(), "0" * 32, {}, phase="operator_resolution_authorized"))
    try:
        return await runtime.executions.resolve(identity, body.execution_id, body.disposition)
    except (ValueError, RuntimeError):
        return JSONResponse({"error": "EXECUTION_RESOLUTION_REFUSED"}, status_code=409)


@router.get("/policy")
async def policy(request: Request):
    store = request.app.state.runtime.policies
    return {
        "active": store.active.model_dump(),
        "last_known_good_revision": store.last_known_good.policy.metadata.revision,
    }


@router.post("/policy/reload")
@router.post("/threat-feed/reload")
async def reload_policy(request: Request):
    runtime = request.app.state.runtime
    store = runtime.policies
    kind = "threat_feed" if "threat-feed" in request.url.path else "policy"
    try:
        snapshot = await store.reload()
        runtime.metrics.reloads.labels(kind, "success").inc()
        runtime.metrics.revisions(snapshot)
        return {
            "policy_revision": snapshot.policy.metadata.revision,
            "threat_feed_revision": snapshot.feed.revision,
        }
    except Exception:
        runtime.metrics.reloads.labels(kind, "failure").inc()
        # Validation messages can contain values from the configuration. Return safe diagnostics.
        return JSONResponse(
            {"error": "POLICY_RELOAD_INVALID", "active_revision": store.active.policy.metadata.revision},
            status_code=422,
        )


class ApprovalRequest(StrictModel):
    subject: str
    tenant_id: str
    agent_id: str | None = None
    request: OperationRequest


@router.post("/approvals")
async def approve(body: ApprovalRequest, request: Request):
    runtime = request.app.state.runtime
    candidates = [
        p
        for p in runtime.auth.records.values()
        if p.subject == body.subject
        and p.tenant_id == body.tenant_id
        and (body.agent_id is None or p.agent_id == body.agent_id)
    ]
    if not candidates:
        return JSONResponse({"error": "IDENTITY_NOT_FOUND"}, status_code=404)
    if len(candidates) != 1:
        return JSONResponse({"error": "IDENTITY_AMBIGUOUS", "hint": "Specify agent_id"}, status_code=409)
    identity = candidates[0]
    tx = runtime.pipeline.prepare(body.request, identity)
    tx.payload = canonicalize(tx.payload)
    if tx.operation in {"mcp_tool_call", "tool_call"}:
        await runtime.pipeline.manifests.inspect(tx, runtime.pipeline.tool_adapter(tx),
            runtime.policies.active.policy.mcp)
    token = await runtime.approvals.issue(
        approval_digest(tx, runtime.policies.active.policy.metadata.revision)
    )
    return {
        "approval_token": token,
        "expires_in_seconds": 300,
        "policy_revision": runtime.policies.active.policy.metadata.revision,
    }


@router.get("/audit")
async def audit(request: Request, limit: Annotated[int, Query(ge=1, le=1000)] = 100):
    return {"events": await request.app.state.runtime.audit.recent(limit)}
