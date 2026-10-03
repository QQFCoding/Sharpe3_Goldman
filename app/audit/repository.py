import asyncio
import hashlib
from datetime import UTC, datetime
from typing import Any

from pydantic import Field

from app.core.decision import DecisionResult
from app.core.transaction import SecurityTransaction, StrictModel


class AuditEvent(StrictModel):
    request_id: str
    trace_id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    subject: str
    tenant_id: str
    agent_id: str | None
    operation: str
    resource: str | None
    phase: str = "final"
    security: DecisionResult
    budget_reserved: float
    budget_consumed: float
    latencies: dict[str, float]
    prompt_hash: str
    workflow_id: str = ""
    effect: str = "read"
    resource_category: str = "other"
    data_security: dict[str, Any] = Field(default_factory=dict)
    delegation_depth: int = 0
    source_category: str = "direct_user_injection"

    @classmethod
    def from_transaction(
        cls, tx: SecurityTransaction, decision, prompt_hash, trace_id, latencies, phase="final"
    ):
        from app.adapters.tools import TOOLS

        name = tx.resource.name if tx.resource else None
        resource = (
            name
            if name in TOOLS
            else ("sha256:" + hashlib.sha256(name.encode()).hexdigest() if name else None)
        )
        return cls(
            request_id=tx.request_id,
            trace_id=trace_id,
            subject=tx.principal.subject,
            tenant_id=tx.principal.tenant_id,
            agent_id=tx.principal.agent_id,
            operation=tx.operation.value,
            resource=resource,
            security=decision,
            budget_reserved=tx.budget.reserved_credits,
            budget_consumed=tx.budget.consumed_credits,
            latencies=latencies,
            prompt_hash=prompt_hash,
            phase=phase,
            workflow_id="sha256:" + hashlib.sha256(tx.context.workflow.workflow_id.encode()).hexdigest(),
            effect=tx.effect,
            resource_category=tx.operation.value,
            data_security=tx.metadata.get("data_label", {}),
            delegation_depth=tx.principal.delegation_depth,
            source_category=tx.metadata.get("source_category", "direct_user_injection"),
        )


class AuditRepository:
    def __init__(self, pool=None):
        self.pool = pool
        self.events: list[dict[str, Any]] = []
        self._lock = asyncio.Lock()

    async def initialize(self):
        if self.pool:
            async with self.pool.connection() as conn:
                await conn.execute("""CREATE TABLE IF NOT EXISTS aicl_audit (
                    event_id BIGSERIAL PRIMARY KEY, request_id TEXT NOT NULL,
                    timestamp TIMESTAMPTZ NOT NULL, event JSONB NOT NULL)""")
                await conn.execute("CREATE INDEX IF NOT EXISTS aicl_audit_request ON aicl_audit(request_id)")
                from app.settings import ROOT
                await conn.execute((ROOT / "observability/postgres/events.sql").read_text(encoding="utf-8"))

    async def append(self, event: AuditEvent):
        body = event.model_dump(mode="json")
        if self.pool:
            from psycopg.types.json import Jsonb

            async with self.pool.connection() as conn:
                await conn.execute(
                    "INSERT INTO aicl_audit(request_id,timestamp,event) VALUES (%s,%s,%s)",
                    (event.request_id, event.timestamp, Jsonb(body)),
                )
        else:
            async with self._lock:
                self.events.append(body)
                if len(self.events) > 10000:
                    del self.events[:-10000]

    async def recent(self, limit: int = 100):
        if self.pool:
            async with self.pool.connection() as conn:
                cursor = await conn.execute(
                    "SELECT event FROM aicl_audit ORDER BY event_id DESC LIMIT %s", (limit,)
                )
                return [row[0] for row in await cursor.fetchall()]
        async with self._lock:
            return list(reversed(self.events[-limit:]))
