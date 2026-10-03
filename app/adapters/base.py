from typing import Any, Protocol

from pydantic import Field

from app.core.transaction import SecurityTransaction, StrictModel


class UpstreamResult(StrictModel):
    output: Any
    tool_error: bool = False
    input_tokens: int = Field(default=0, ge=0, le=10000000)
    output_tokens: int = Field(default=0, ge=0, le=10000000)


class UpstreamAdapter(Protocol):
    async def execute(self, transaction: SecurityTransaction) -> UpstreamResult: ...
