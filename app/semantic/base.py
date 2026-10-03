from typing import Protocol

from pydantic import ConfigDict, Field

from app.core.transaction import SecurityTransaction, StrictModel


class SemanticRisk(StrictModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    prompt_injection: float = Field(ge=0, le=1, allow_inf_nan=False)
    data_exfiltration: float = Field(default=0, ge=0, le=1, allow_inf_nan=False)
    tool_misuse: float = Field(default=0, ge=0, le=1, allow_inf_nan=False)
    reason_codes: list[str] = Field(default_factory=list, max_length=32)


class SemanticUnavailable(RuntimeError):
    pass


class SemanticSecurityProvider(Protocol):
    async def analyze(self, transaction: SecurityTransaction) -> SemanticRisk: ...


class UnavailableProvider:
    async def analyze(self, transaction):
        raise SemanticUnavailable("No semantic provider configured")
