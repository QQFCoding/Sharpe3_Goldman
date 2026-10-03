import asyncio
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from pydantic import Field

from app.core.labels import DataSecurityLabel
from app.core.transaction import StrictModel


class MemoryRecord(StrictModel):
    memory_id: str = Field(default_factory=lambda: str(uuid4()))
    tenant_id: str
    owner: str
    created_by: str
    source: str
    source_trust: str
    classification: str = "internal"
    security_labels: list[str] = Field(default_factory=list)
    content: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime
    quarantined: bool = False
    data_security: DataSecurityLabel | None = None


class MemoryService:
    """Metadata reads are local and scoped. Content is released only after the pipeline authorizes it."""

    def __init__(self, pool=None):
        self.pool = pool
        self._lock = asyncio.Lock()
        self.records: dict[str, MemoryRecord] = {}

    async def initialize(self):
        if self.pool:
            async with self.pool.connection() as conn:
                await conn.execute("""CREATE TABLE IF NOT EXISTS aicl_memory (
                    memory_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, owner_id TEXT NOT NULL,
                    record JSONB NOT NULL, expires_at TIMESTAMPTZ NOT NULL)""")

    async def lookup(self, memory_id: str, tenant_id: str) -> MemoryRecord | None:
        """Fetch metadata, without content, for the pre-authorization policy decision."""
        if self.pool:
            async with self.pool.connection() as conn:
                cursor = await conn.execute(
                    "SELECT record - 'content' FROM aicl_memory WHERE memory_id=%s AND tenant_id=%s AND expires_at > now()",
                    (memory_id, tenant_id),
                )
                row = await cursor.fetchone()
                return MemoryRecord.model_validate({**row[0], "content": ""}) if row else None
        async with self._lock:
            record = self.records.get(memory_id)
            if not record or record.tenant_id != tenant_id or record.expires_at <= datetime.now(UTC):
                return None
            return record.model_copy(update={"content": ""}, deep=True)

    async def get(
        self, memory_id: str, tenant_id: str, subject: str | None = None, administrator: bool = False
    ) -> MemoryRecord | None:
        if self.pool:
            async with self.pool.connection() as conn:
                cursor = await conn.execute(
                    "SELECT record FROM aicl_memory WHERE memory_id=%s AND tenant_id=%s AND expires_at > now() "
                    "AND (%s::text IS NULL OR owner_id=%s OR %s)",
                    (memory_id, tenant_id, subject, subject, administrator),
                )
                row = await cursor.fetchone()
                return MemoryRecord.model_validate(row[0]) if row else None
        async with self._lock:
            record = self.records.get(memory_id)
            if not record or record.tenant_id != tenant_id or record.expires_at <= datetime.now(UTC):
                return None
            if subject is not None and record.owner != subject and not administrator:
                return None
            return record.model_copy(deep=True)

    async def write(self, tx, max_ttl: int, quarantined: bool = False) -> MemoryRecord:
        record = MemoryRecord(
            tenant_id=tx.principal.tenant_id,
            owner=tx.principal.subject,
            created_by=tx.principal.agent_id or tx.principal.subject,
            source=tx.payload["source"],
            source_trust=tx.context.source_trust,
            classification=tx.payload.get("classification", "internal"),
            content=tx.payload["content"],
            expires_at=datetime.now(UTC)
            + timedelta(seconds=min(tx.payload.get("ttl_seconds", max_ttl), max_ttl)),
            quarantined=quarantined,
            security_labels=["prompt_injection"] if quarantined else [],
            data_security=DataSecurityLabel.model_validate(tx.metadata["data_label"])
                if "data_label" in tx.metadata else None,
        )
        await self.save(record)
        return record

    async def save(self, record: MemoryRecord):
        if self.pool:
            from psycopg.types.json import Jsonb

            async with self.pool.connection() as conn:
                await conn.execute(
                    """INSERT INTO aicl_memory VALUES (%s,%s,%s,%s,%s)
                    ON CONFLICT(memory_id) DO UPDATE SET record=EXCLUDED.record""",
                    (
                        record.memory_id,
                        record.tenant_id,
                        record.owner,
                        Jsonb(record.model_dump(mode="json")),
                        record.expires_at,
                    ),
                )
        else:
            async with self._lock:
                self.records[record.memory_id] = record.model_copy(deep=True)

    async def quarantine(self, record: MemoryRecord):
        record.quarantined = True
        record.security_labels = sorted(set(record.security_labels + ["prompt_injection"]))
        if self.pool:
            async with self.pool.connection() as conn:
                await conn.execute(
                    """UPDATE aicl_memory SET record = record ||
                    jsonb_build_object('quarantined', true, 'security_labels',
                    (record->'security_labels') || '["prompt_injection"]'::jsonb)
                    WHERE memory_id=%s AND tenant_id=%s""",
                    (record.memory_id, record.tenant_id),
                )
        else:
            async with self._lock:
                actual = self.records.get(record.memory_id)
                if actual and actual.tenant_id == record.tenant_id:
                    actual.quarantined = True
                    actual.security_labels = sorted(set(actual.security_labels + ["prompt_injection"]))
