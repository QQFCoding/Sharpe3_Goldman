from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Operation(StrEnum):
    LLM_REQUEST = "llm_request"
    LLM_RESPONSE = "llm_response"
    MCP_TOOL_CALL = "mcp_tool_call"
    TOOL_CALL = "tool_call"
    MEMORY_READ = "memory_read"
    MEMORY_WRITE = "memory_write"
    AGENT_MESSAGE = "agent_message"
    API_CALL = "api_call"


class Effect(StrEnum):
    READ = "read"
    WRITE = "write"
    EXTERNAL_SIDE_EFFECT = "external_side_effect"
    DESTRUCTIVE = "destructive"
    CODE_EXECUTION = "code_execution"


class Principal(StrictModel):
    subject: str = Field(min_length=1, max_length=128)
    tenant_id: str = Field(min_length=1, max_length=128)
    agent_id: str | None = Field(default=None, max_length=128)
    roles: list[str] = Field(default_factory=list)
    scopes: list[str] = Field(default_factory=list)
    on_behalf_of: str | None = None
    authentication_method: str = "api_key"
    authenticated: bool = True
    delegator: str | None = None
    parent_agent: str | None = None
    delegation_depth: int = Field(default=0, ge=0)
    delegated_workflow: str | None = None
    capabilities: list[str] = Field(default_factory=list)


class Resource(StrictModel):
    name: str = Field(max_length=256)
    tenant_id: str | None = None
    owner: str | None = None
    provider: str | None = None
    model: str | None = None
    mcp_server: str | None = None
    classification: str = "public"


class WorkflowContext(StrictModel):
    workflow_id: str = Field(default_factory=lambda: str(uuid4()), min_length=1, max_length=128)
    parent_request_id: str | None = Field(default=None, max_length=128)
    depth: int = Field(default=0, ge=0, le=10000)


class SecurityContext(StrictModel):
    workflow: WorkflowContext = Field(default_factory=WorkflowContext)
    source: str = "application"
    source_trust: str = "trusted"
    phase: str = "input"
    approval_verified: bool = False
    semantic_required: bool = False


class RiskSignals(StrictModel):
    prompt_injection: float = Field(default=0, ge=0, le=1)
    data_exfiltration: float = Field(default=0, ge=0, le=1)
    tool_misuse: float = Field(default=0, ge=0, le=1)
    semantic_status: str = "not_required"
    risk_band: str = "LOW_RISK"
    task_alignment: float = Field(default=1, ge=0, le=1, allow_inf_nan=False)
    goal_deviation: float = Field(default=0, ge=0, le=1, allow_inf_nan=False)
    data_exfiltration_intent: float = Field(default=0, ge=0, le=1, allow_inf_nan=False)
    unexpected_side_effect: float = Field(default=0, ge=0, le=1, allow_inf_nan=False)
    alignment_confidence: float = Field(default=0, ge=0, le=1, allow_inf_nan=False)
    alignment_status: str = "not_required"


class BudgetContext(StrictModel):
    available: bool = True
    reservation_id: str | None = None
    reserved_credits: float = 0
    consumed_credits: float = 0
    estimated_input_tokens: int = 0
    max_output_tokens: int = 256
    steps: int = 0
    llm_calls: int = 0
    tool_calls: int = 0
    violations: list[str] = Field(default_factory=list)


class Finding(StrictModel):
    code: str
    control: str
    action: str = "BLOCK"
    path: list[str | int] = Field(default_factory=list)
    start: int | None = None
    end: int | None = None
    replacement: str | None = None
    rule_id: str | None = None
    category: str = "security"
    severity: str = "high"
    confidence: float = Field(default=.95, ge=0, le=1, allow_inf_nan=False)
    detection_type: str = "deterministic"
    title: str = "Security control triggered"
    description: str = ""
    remediation: str = "Review the request and follow the configured security policy."
    evidence: dict[str, Any] = Field(default_factory=dict)
    version: str = "1"


class SecurityTransaction(StrictModel):
    request_id: str = Field(default_factory=lambda: str(uuid4()))
    principal: Principal
    operation: Operation
    effect: Effect = Effect.READ
    resource: Resource | None = None
    context: SecurityContext = Field(default_factory=SecurityContext)
    payload: Any
    risk: RiskSignals = Field(default_factory=RiskSignals)
    budget: BudgetContext = Field(default_factory=BudgetContext)
    metadata: dict[str, Any] = Field(default_factory=dict)


class OperationRequest(StrictModel):
    """Wire input deliberately excludes identity, effect, risk, and budget facts."""

    operation: Operation
    resource: Resource | None = None
    payload: dict[str, Any]
    workflow: WorkflowContext = Field(default_factory=WorkflowContext)
    approval_token: str | None = Field(default=None, max_length=256)
    execution_id: str | None = Field(default=None, min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$")
    result_fields: list[str] | None = Field(default=None, max_length=32)
    value_references: dict[str, str] = Field(default_factory=dict, max_length=32)
    public_action: str | None = Field(default=None, max_length=128)


def text_leaves(value: Any, path: tuple = ()):
    # Iterative and bounded: hostile object depth must not consume Python recursion.
    stack, visited = [(path, value)], 0
    while stack:
        current, item = stack.pop()
        visited += 1
        if len(current)>16 or visited>4096 or len(stack)>4096:
            from app.controls.normalization import InspectionLimit
            raise InspectionLimit("Inspection structure budget exceeded")
        if isinstance(item,str):
            yield current,item
        elif isinstance(item,dict):
            stack.extend(reversed([(current+(key,),v) for key,v in item.items()]))
        elif isinstance(item,list):
            stack.extend(reversed([(current+(i,),v) for i,v in enumerate(item)]))
