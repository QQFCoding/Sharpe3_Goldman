from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import Field

from app.adapters.mcp_protocol import validate
from app.api.dependencies import principal, status_for
from app.core.transaction import (
    Operation,
    OperationRequest,
    Principal,
    Resource,
    StrictModel,
    WorkflowContext,
)

router = APIRouter()
Identity = Annotated[Principal, Depends(principal)]


class Message(StrictModel):
    role: Literal["system", "user", "assistant", "tool"]
    content: str = Field(max_length=65536)


class ChatRequest(StrictModel):
    model: str = "demo"
    provider: Literal["mock", "ollama"] = "mock"
    messages: list[Message] = Field(min_length=1, max_length=64)
    max_tokens: int = Field(default=256, ge=1, le=2048)
    stream: Literal[False] = False  # Buffering is necessary to inspect the complete output.
    workflow: WorkflowContext = Field(default_factory=WorkflowContext)
    approval_token: str | None = None


@router.post("/v1/transactions")
async def transaction(body: OperationRequest, request: Request, identity: Identity):
    result = await request.app.state.runtime.pipeline.execute(body, identity)
    return JSONResponse(result.model_dump(mode="json"), status_code=status_for(result.security.decision))


@router.post("/v1/chat/completions")
async def chat(body: ChatRequest, request: Request, identity: Identity):
    tx = OperationRequest(
        operation=Operation.LLM_REQUEST,
        resource=Resource(name=body.model, provider=body.provider, model=body.model),
        payload={"messages": [m.model_dump() for m in body.messages], "max_tokens": body.max_tokens},
        workflow=body.workflow,
        approval_token=body.approval_token,
    )
    result = await request.app.state.runtime.pipeline.execute(tx, identity)
    data = result.model_dump(mode="json")
    if result.output is not None and status_for(result.security.decision) == 200:
        data.update(
            id=result.security.request_id,
            object="chat.completion",
            model=body.model,
            choices=[
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": result.output["content"]},
                    "finish_reason": "stop",
                }
            ],
        )
    return JSONResponse(data, status_code=status_for(result.security.decision))


class MCPParams(StrictModel):
    name: str | None = None
    arguments: dict = Field(default_factory=dict)
    meta: dict = Field(default_factory=dict, alias="_meta")
    execution_id: str | None = Field(default=None, min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$")
    workflow: WorkflowContext = Field(default_factory=WorkflowContext)
    approval_token: str | None = None


class MCPRequest(StrictModel):
    jsonrpc: Literal["2.0"] = "2.0"
    id: str | int
    method: Literal["tools/list", "tools/call"]
    params: MCPParams | None = None


@router.post("/v1/mcp")
async def mcp(body: MCPRequest, request: Request, identity: Identity):
    runtime = request.app.state.runtime
    try:
        validate(body.model_dump(mode="json", by_alias=True, exclude_none=True), request.headers, legacy=True)
    except ValueError:
        result = await runtime.reject("MCP_HEADER_MISMATCH", "mcp-protocol", identity)
        return JSONResponse({"jsonrpc": "2.0", "id": body.id, "error": {"code": -32020,
            "message": "MCP_HEADER_MISMATCH"}, "security": result.security.model_dump(mode="json")}, status_code=400)
    if body.method == "tools/list":
        policy = runtime.policies.active.policy
        visible = set(policy.tools.allow + policy.tools.require_approval)
        return {
            "jsonrpc": "2.0",
            "id": body.id,
            "result": {
                "tools": [
                    {
                        "name": t.name,
                        "description": t.description or "Registered " + t.name,
                        "inputSchema": t.schema,
                        "outputSchema": t.output_schema,
                        "effect": t.effect,
                        "required_scopes": list(t.required_scopes),
                    }
                    for t in runtime.pipeline.tools.values()
                    if t.name in visible and set(t.required_scopes) <= set(identity.scopes)
                ]
            },
        }
    if body.params is None or body.params.name is None:
        result = await runtime.reject("SCHEMA_INVALID", "schema", identity)
    else:
        result = await runtime.pipeline.execute(
            OperationRequest(
                operation=Operation.MCP_TOOL_CALL,
                resource=Resource(name=body.params.name),
                payload=body.params.arguments,
                workflow=body.params.workflow,
                approval_token=body.params.approval_token,
                execution_id=body.params.execution_id,
            ),
            identity,
        )
    data = {"jsonrpc": "2.0", "id": body.id, "security": result.security.model_dump(mode="json"),
        "execution": result.execution, "value_handles": result.value_handles,
        "detection_report": result.detection_report}
    if status_for(result.security.decision) == 200:
        data["result"] = {"structuredContent": result.output,
            "isError": "MCP_TOOL_REPORTED_ERROR" in result.security.reason_codes}
    else:
        data["error"] = {
            "code": -32001,
            "message": result.security.decision.value,
            "data": result.security.model_dump(mode="json"),
        }
    return JSONResponse(data, status_code=status_for(result.security.decision))


@router.get("/v1/executions/{execution_id}")
async def execution_status(execution_id: str, request: Request, identity: Identity):
    state = await request.app.state.runtime.executions.get(identity, execution_id)
    return state or JSONResponse({"error": "EXECUTION_NOT_FOUND"}, status_code=404)
