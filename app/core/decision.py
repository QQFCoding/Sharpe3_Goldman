from enum import StrEnum
from typing import Any

from pydantic import Field

from app.core.transaction import RiskSignals, StrictModel


class Decision(StrEnum):
    ALLOW = "ALLOW"
    REDACT = "REDACT"
    WARN = "WARN"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    BLOCK = "BLOCK"
    TERMINATE = "TERMINATE"
    QUARANTINE = "QUARANTINE"


PERMITTED = {Decision.ALLOW, Decision.REDACT, Decision.WARN}


class DecisionResult(StrictModel):
    decision: Decision
    reason_codes: list[str] = Field(default_factory=list)
    controls: list[str] = Field(default_factory=list)
    policy_revision: str
    threat_feed_revision: str
    risk: RiskSignals = Field(default_factory=RiskSignals)
    transformations: list[dict[str, Any]] = Field(default_factory=list)
    request_id: str


class GatewayResult(StrictModel):
    security: DecisionResult
    output: Any = None
    input_security: DecisionResult | None = None
    budget: dict[str, Any] = Field(default_factory=dict)
