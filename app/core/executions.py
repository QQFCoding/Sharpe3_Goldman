"""Durable, non-expiring execution tombstones; uncertainty never permits retry."""
import asyncio
import hashlib
import json
import secrets
import time

from app.controls.base import encoded

CREATE = """
local old=redis.call('GET',KEYS[1])
if old then return {0,old} end
redis.call('SET',KEYS[1],ARGV[1])
return {1,ARGV[1]}
"""
TRANSITION = """
local raw=redis.call('GET',KEYS[1])
if not raw then return 0 end
local record=cjson.decode(raw)
if record.owner~=ARGV[1] then return 0 end
local expected=cjson.decode(ARGV[2])
local found=false
for _,state in ipairs(expected) do if record.state==state then found=true end end
if not found then return 0 end
record.state=ARGV[3]
record.updated_at=tonumber(ARGV[4])
redis.call('SET',KEYS[1],cjson.encode(record))
return 1
"""


class ReplayRejected(RuntimeError):
    def __init__(self, record, binding):
        self.record = record
        self.code = ("EXECUTION_BINDING_MISMATCH" if record["binding"] != binding else
            "EXECUTION_OUTCOME_UNCERTAIN" if record["state"] in {"EXECUTING", "UNCERTAIN"} else
            "EXECUTION_ALREADY_COMPLETED" if record["state"] == "COMPLETED" else
            "EXECUTION_ALREADY_FAILED" if record["state"] == "FAILED" else "EXECUTION_IN_PROGRESS")


class ExecutionStore:
    def __init__(self, redis=None):
        self.redis = redis
        self.records = {}
        self.lock = asyncio.Lock()

    @staticmethod
    def key(principal, execution_id):
        # Agent/workflow are in the binding, not the key: changing them cannot reuse an ID.
        return "aicl:execution:" + hashlib.sha256(encoded([
            principal.tenant_id, principal.subject, execution_id])).hexdigest()

    @staticmethod
    def logical_id(tx):
        return hashlib.sha256(encoded([tx.principal.tenant_id, tx.principal.subject, tx.principal.agent_id,
            tx.operation, tx.resource.name if tx.resource else None,
            tx.payload])).hexdigest()

    @staticmethod
    def binding(tx, revision):
        return hashlib.sha256(encoded({"principal": tx.principal.subject, "tenant": tx.principal.tenant_id,
            "agent": tx.principal.agent_id, "workflow": tx.context.workflow.model_dump(),
            "operation": tx.operation, "resource": tx.resource.model_dump() if tx.resource else None,
            "effect": tx.effect, "arguments": tx.metadata.get("execution_arguments", tx.payload),
            "execution_id": tx.metadata["execution_id"], "policy_revision": revision,
            "manifest_hash": tx.metadata.get("manifest_hash")})).hexdigest()

    async def reserve(self, tx, revision):
        binding = self.binding(tx, revision)
        key = self.key(tx.principal, tx.metadata["execution_id"])
        record = {"execution_id": tx.metadata["execution_id"], "binding": binding,
            "state": "AUTHORIZED", "owner": secrets.token_hex(16), "updated_at": time.time()}
        if self.redis:
            created, old = await self.redis.eval(CREATE, 1, key, json.dumps(record))
            old = json.loads(old)
        else:
            async with self.lock:
                created = key not in self.records
                old = self.records.setdefault(key, record.copy())
        if not created:
            raise ReplayRejected(old, binding)
        ticket = {"key": key, **record}
        await self.transition(ticket, ["AUTHORIZED"], "EXECUTION_RESERVED")
        return ticket

    async def transition(self, ticket, expected, state):
        updated_at = time.time()
        if self.redis:
            changed = await self.redis.eval(TRANSITION, 1, ticket["key"], ticket["owner"],
                json.dumps(expected), state, updated_at)
        else:
            async with self.lock:
                record = self.records[ticket["key"]]
                changed = record["owner"] == ticket["owner"] and record["state"] in expected
                if changed:
                    record.update(state=state, updated_at=updated_at)
        if not changed:
            raise RuntimeError("Execution state transition refused")
        ticket["state"] = state
        ticket["updated_at"] = updated_at

    async def resolve(self, principal, execution_id, disposition):
        if disposition not in {"COMPLETED", "FAILED"}:
            raise ValueError("EXECUTION_DISPOSITION_INVALID")
        key = self.key(principal, execution_id)
        if self.redis:
            raw = await self.redis.get(key)
            record = json.loads(raw) if raw else None
        else:
            async with self.lock:
                record = self.records.get(key)
                record = record.copy() if record else None
        unresolved = ["AUTHORIZED", "EXECUTION_RESERVED", "EXECUTING", "UNCERTAIN"]
        if not record or record["state"] not in unresolved:
            raise ValueError("EXECUTION_NOT_UNCERTAIN")
        ticket = {"key": key, **record}
        await self.transition(ticket, unresolved, disposition)
        return self.public(ticket)

    async def start(self, ticket):
        await self.transition(ticket, ["EXECUTION_RESERVED"], "EXECUTING")

    async def complete(self, ticket):
        await self.transition(ticket, ["EXECUTING"], "COMPLETED")

    async def fail(self, ticket, uncertain=False):
        if ticket and ticket["state"] not in {"COMPLETED", "FAILED", "UNCERTAIN"}:
            await self.transition(ticket, ["AUTHORIZED", "EXECUTION_RESERVED", "EXECUTING"],
                "UNCERTAIN" if uncertain else "FAILED")

    async def get(self, principal, execution_id):
        key = self.key(principal, execution_id)
        if self.redis:
            raw = await self.redis.get(key)
            record = json.loads(raw) if raw else None
        else:
            async with self.lock:
                record = self.records.get(key)
        return self.public(record)

    @staticmethod
    def public(record):
        return {k: record[k] for k in ("execution_id", "state", "updated_at")} if record else None
