"""Shared immutable intent and monotonic provenance; Redis is the deployment authority."""
import asyncio
import hashlib
import json
from datetime import UTC, datetime
from typing import Literal

from pydantic import ConfigDict, Field

from app.controls.base import canonicalize
from app.core.labels import DataSecurityLabel
from app.core.transaction import StrictModel


class TrustedIntent(StrictModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    workflow_id: str
    user_instruction_hash: str
    normalized_goal: str = Field(max_length=2048)
    allowed_effects: frozenset[Literal["read", "write", "external_side_effect", "destructive", "code_execution"]]
    allowed_resources: frozenset[str]
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


JOIN_LUA = r"""
local incoming = cjson.decode(ARGV[1])
local raw = redis.call('GET', KEYS[1])
if raw then
 local old = cjson.decode(raw)
 local rank = {trusted=0, derived=1, untrusted=2}
 if rank[old.integrity] > rank[incoming.integrity] then incoming.integrity=old.integrity end
 for _,field in ipairs({'confidentiality','taints','provenance'}) do
  local seen, values = {}, {}
  for _,item in ipairs(old[field]) do seen[item]=true end
  for _,item in ipairs(incoming[field]) do seen[item]=true end
  for item,_ in pairs(seen) do table.insert(values,item) end
  table.sort(values)
  if field == 'provenance' then while #values > 64 do table.remove(values) end end
  incoming[field]=values
 end
end
local body=cjson.encode(incoming)
-- Redis Lua cjson encodes an empty Lua table as an object; these fields are arrays.
for _,field in ipairs({'confidentiality','taints','provenance'}) do
 body=string.gsub(body, '"' .. field .. '":{}', '"' .. field .. '":[]')
end
redis.call('SET', KEYS[1], body, 'EX', ARGV[2])
return body
"""


class WorkflowStore:
    def __init__(self, redis=None, ttl=86400):
        self.redis, self.ttl = redis, ttl
        self._lock = asyncio.Lock()
        self._values = {}

    def key(self, principal, workflow, kind="flow"):
        value = json.dumps([principal.tenant_id, principal.subject, workflow], separators=(",", ":"))
        return "aicl:" + kind + ":" + hashlib.sha256(value.encode()).hexdigest()

    async def get(self, key):
        if self.redis:
            value = await self.redis.get(key)
            return json.loads(value) if value else None
        async with self._lock:
            import time
            item = self._values.get(key)
            return json.loads(item[0]) if item and item[1] > time.time() else None

    async def put_once(self, key, value, ttl=None):
        body = json.dumps(value)
        ttl = ttl or self.ttl
        if self.redis:
            return bool(await self.redis.set(key, body, nx=True, ex=ttl))
        async with self._lock:
            import time
            if key in self._values and self._values[key][1] > time.time():
                return False
            self._values[key] = (body, time.time() + ttl)
            return True

    async def intent(self, principal, workflow):
        value = await self.get(self.key(principal, workflow, "intent"))
        return TrustedIntent.model_validate(value) if value else None

    async def register(self, principal, workflow, goal, effects, resources):
        if "workflow:intent" not in principal.scopes or principal.delegated_workflow:
            raise PermissionError("INTENT_SCOPE_MISSING")
        goal = canonicalize(goal)
        intent = TrustedIntent(workflow_id=workflow, normalized_goal=goal,
            user_instruction_hash=hashlib.sha256(goal.encode()).hexdigest(),
            allowed_effects=frozenset(effects), allowed_resources=frozenset(resources))
        if not await self.put_once(self.key(principal, workflow, "intent"), intent.model_dump(mode="json")):
            raise ValueError("TRUSTED_INTENT_IMMUTABLE")
        return intent

    async def label(self, principal, workflow):
        labels = []
        # Protected exposure persists across workflow IDs, closing the simplest laundering bypass.
        for scope in (workflow, "__protected_exposure__"):
            value = await self.get(self.key(principal, scope))
            if value:
                labels.append(DataSecurityLabel.model_validate(value))
        return DataSecurityLabel.join(*labels)

    async def absorb(self, principal, workflow, label):
        scopes = [workflow]
        if label.confidentiality & {"private", "secret"}:
            scopes.append("__protected_exposure__")
        for scope in scopes:
            key = self.key(principal, scope)
            if self.redis:
                await self.redis.eval(JOIN_LUA, 1, key, label.model_dump_json(), self.ttl)
            else:
                async with self._lock:
                    import time
                    now = time.time()
                    old = self._values.get(key)
                    old_label = DataSecurityLabel.model_validate_json(old[0]) if old and old[1] > now else None
                    joined = DataSecurityLabel.join(old_label, label) if old_label else label
                    self._values[key] = (joined.model_dump_json(), now + self.ttl)
                    self._values = {k: v for k, v in self._values.items() if v[1] > now}

    async def handoff(self, sender, recipient, workflow, label):
        if sender.tenant_id != recipient.tenant_id:
            raise PermissionError("CROSS_TENANT_DELEGATION")
        await self.absorb(recipient, workflow, label)
