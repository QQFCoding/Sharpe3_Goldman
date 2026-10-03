from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from app.core.transaction import Operation, Principal, SecurityTransaction

router = APIRouter()


@router.get("/health")
async def health():
    return {"status": "ok"}


@router.get("/ready")
async def ready(request: Request):
    runtime = request.app.state.runtime
    tx = SecurityTransaction(
        principal=Principal(subject="health", tenant_id="health"),
        operation=Operation.AGENT_MESSAGE,
        payload={},
    )
    verdict = await runtime.engine.evaluate(tx, runtime.policies.active, runtime.pipeline.facts(tx, []))
    ok = "POLICY_ENGINE_UNAVAILABLE" not in verdict.reason_codes
    try:
        if runtime.redis:
            await runtime.redis.ping()
        if runtime.pool:
            async with runtime.pool.connection() as conn:
                await conn.execute("SELECT 1")
    except Exception:
        ok = False
    return JSONResponse(
        {
            "status": "ready" if ok else "degraded",
            "policy_revision": runtime.policies.active.policy.metadata.revision,
            "semantic_provider": runtime.settings.semantic_provider,
            "demo_mode": runtime.settings.demo_mode,
        },
        status_code=200 if ok else 503,
    )
