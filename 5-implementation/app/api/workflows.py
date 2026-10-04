from typing import Annotated

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import Field

from app.api.dependencies import principal
from app.core.delegation import DelegationRequest
from app.core.transaction import Effect, Principal, StrictModel

router = APIRouter(prefix="/v1")
Identity = Annotated[Principal, Depends(principal)]


class IntentRequest(StrictModel):
    workflow_id: str = Field(min_length=1, max_length=128)
    goal: str = Field(min_length=1, max_length=2048)
    allowed_effects: list[Effect] = Field(default_factory=lambda: [Effect.READ])
    allowed_resources: list[str] = Field(default_factory=list, max_length=64)


@router.post("/workflows")
async def register(body: IntentRequest, request: Request, identity: Identity):
    try:
        intent = await request.app.state.runtime.workflows.register(identity, body.workflow_id, body.goal,
            body.allowed_effects, body.allowed_resources)
        return {"intent": intent.model_dump(mode="json")}
    except PermissionError:
        return JSONResponse({"error": "INTENT_SCOPE_MISSING"}, status_code=403)
    except ValueError:
        return JSONResponse({"error": "TRUSTED_INTENT_IMMUTABLE"}, status_code=409)


@router.post("/delegations")
async def delegate(body: DelegationRequest, request: Request, identity: Identity):
    runtime = request.app.state.runtime
    try:
        token, child = await runtime.delegations.issue(identity, body, runtime.policies.active.policy.delegation)
        return {"token": token, "principal": child.model_dump(mode="json"), "expires_in_seconds": runtime.delegations.ttl}
    except PermissionError as error:
        result = await runtime.reject(str(error), "delegation", identity)
        return JSONResponse(result.model_dump(mode="json"), status_code=403)
