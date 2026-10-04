import asyncio
import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Protocol
from uuid import uuid4

from app.core.transaction import Operation, SecurityTransaction
from app.policy.loader import Policy


@dataclass
class Reservation:
    id: str | None = None
    key: str = ""
    credits: float = 0
    tokens: int = 0
    violations: list[str] = field(default_factory=list)
    steps: int = 0
    llm_calls: int = 0
    tool_calls: int = 0


class BudgetManager(Protocol):
    async def reserve(
        self, tx: SecurityTransaction, policy: Policy, tokens: int, credits: float
    ) -> Reservation: ...
    async def begin(self, reservation: Reservation) -> bool: ...
    async def reconcile(self, reservation: Reservation, tokens: int, credits: float) -> bool: ...


def keys(tx: SecurityTransaction) -> tuple[str, str]:
    p = tx.principal
    owner = hashlib.sha256(json.dumps([p.tenant_id, p.subject, p.agent_id]).encode()).hexdigest()
    workflow = hashlib.sha256(tx.context.workflow.workflow_id.encode()).hexdigest()
    user = hashlib.sha256(json.dumps([p.tenant_id, p.subject]).encode()).hexdigest()
    return f"aicl:budget:{owner}:{workflow}", f"aicl:rate:{user}"


def agent_key(workflow_key: str) -> str:
    return workflow_key.rsplit(":", 1)[0] + ":concurrent"


class InMemoryBudgetManager:
    """Single-process demo/test backend; identical admission semantics to the Lua backend."""

    def __init__(self, clock=time.time):
        self.clock = clock
        self._lock = asyncio.Lock()
        self.workflows: dict[str, dict] = {}
        self.rates: dict[str, list[float]] = {}
        self.agent_active: dict[str, dict[str, float]] = {}

    async def reserve(self, tx, policy, tokens, credits):
        key, user = keys(tx)
        limit = policy.budgets.per_agent
        async with self._lock:
            now = self.clock()
            agent = self.agent_active.setdefault(agent_key(key), {})
            for rid in list(agent):
                if agent[rid] <= now:
                    del agent[rid]
            state = self.workflows.setdefault(
                key,
                {
                    "start": now,
                    "steps": 0,
                    "llm": 0,
                    "tool": 0,
                    "credits": 0,
                    "tokens": 0,
                    "active": {},
                    "depths": {},
                },
            )
            state["active"] = {rid: r for rid, r in state["active"].items() if r[2] > now}
            times = [t for t in self.rates.get(user, []) if t > now - 60]
            times.append(now)
            self.rates[user] = times
            violations = []
            parent = tx.context.workflow.parent_request_id
            if parent:
                if parent not in state["depths"]:
                    violations.append("WORKFLOW_PARENT_INVALID")
                else:
                    tx.context.workflow.depth = max(tx.context.workflow.depth, state["depths"][parent] + 1)
            is_llm = tx.operation == Operation.LLM_REQUEST
            is_tool = tx.operation in {Operation.TOOL_CALL, Operation.MCP_TOOL_CALL, Operation.API_CALL}
            checks = [
                (state["steps"] + 1 > limit.max_steps, "MAX_AGENT_STEPS_EXCEEDED"),
                (state["llm"] + int(is_llm) > limit.max_llm_calls, "MAX_LLM_CALLS_EXCEEDED"),
                (state["tool"] + int(is_tool) > limit.max_tool_calls, "MAX_TOOL_CALLS_EXCEEDED"),
                (tx.context.workflow.depth > limit.max_depth, "MAX_WORKFLOW_DEPTH_EXCEEDED"),
                (now - state["start"] > limit.max_wall_time_seconds, "MAX_WALL_TIME_EXCEEDED"),
                (len(agent) >= limit.concurrent_requests, "CONCURRENCY_LIMIT_EXCEEDED"),
                (len(times) > policy.budgets.per_user.requests_per_minute, "REQUEST_RATE_EXCEEDED"),
                (
                    state["credits"] + sum(r[0] for r in state["active"].values() if not r[3]) + credits
                    > limit.credit_limit + 1e-9,
                    "CREDIT_LIMIT_EXCEEDED",
                ),
                (
                    state["tokens"] + sum(r[1] for r in state["active"].values() if not r[3]) + tokens
                    > limit.token_limit,
                    "TOKEN_LIMIT_EXCEEDED",
                ),
            ]
            violations += [reason for failed, reason in checks if failed]
            if violations:
                return Reservation(
                    key=key,
                    violations=violations,
                    steps=state["steps"],
                    llm_calls=state["llm"],
                    tool_calls=state["tool"],
                )
            state["steps"] += 1
            state["llm"] += int(is_llm)
            state["tool"] += int(is_tool)
            state["depths"][tx.request_id] = tx.context.workflow.depth
            rid = str(uuid4())
            state["active"][rid] = (credits, tokens, now + limit.reservation_ttl_seconds, False)
            agent[rid] = now + limit.reservation_ttl_seconds
            return Reservation(rid, key, credits, tokens, [], state["steps"], state["llm"], state["tool"])

    async def begin(self, reservation):
        async with self._lock:
            state = self.workflows.get(reservation.key)
            held = state["active"].get(reservation.id) if state else None
            if not held or held[2] <= self.clock() or held[3]:
                return False
            # A worker crash after starting an action retains the maximum charge.
            state["credits"] += held[0]
            state["tokens"] += held[1]
            state["active"][reservation.id] = (*held[:3], True)
            return True

    async def reconcile(self, reservation, tokens, credits):
        if not reservation.id:
            return True
        async with self._lock:
            state = self.workflows[reservation.key]
            held = state["active"].pop(reservation.id, None)
            self.agent_active.get(agent_key(reservation.key), {}).pop(reservation.id, None)
            if not held:
                return False
            # Charge even an expired reservation if reconciliation still finds it.
            # Overruns are charged, and the response is rejected by the pipeline.
            state["credits"] += max(0, credits) - (held[0] if held[3] else 0)
            state["tokens"] += max(0, tokens) - (held[1] if held[3] else 0)
            return tokens <= held[1] and credits <= held[0] + 1e-9 and held[2] > self.clock()


# All limits, counter updates, expiry cleanup, and reservations share one atomic Lua evaluation.
RESERVE_LUA = r"""
local state, active, rate, agent = KEYS[1], KEYS[2], KEYS[3], KEYS[4]
local args = cjson.decode(ARGV[1])
local now = args.now
local expired = redis.call('ZRANGEBYSCORE', active, '-inf', now)
for _, id in ipairs(expired) do
  redis.call('HDEL', state, 'r:' .. id)
  redis.call('ZREM', active, id)
end
redis.call('ZREMRANGEBYSCORE', rate, '-inf', now - 60)
redis.call('ZADD', rate, now, args.id)
redis.call('EXPIRE', rate, 120)
redis.call('ZREMRANGEBYSCORE', agent, '-inf', now)
local function num(name) return tonumber(redis.call('HGET', state, name) or '0') end
local start = tonumber(redis.call('HGET', state, 'start') or now)
local steps, llm, tool = num('steps'), num('llm'), num('tool')
local held_c, held_t = 0, 0
for _, id in ipairs(redis.call('ZRANGE', active, 0, -1)) do
  local r = cjson.decode(redis.call('HGET', state, 'r:' .. id))
  if not r.charged then
    held_c = held_c + r.credits
    held_t = held_t + r.tokens
  end
end
local v = {}
local function check(b, code) if b then table.insert(v, code) end end
local l = args.limits
if args.parent ~= '' then
  local parent_depth = redis.call('HGET', state, 'd:' .. args.parent)
  if not parent_depth then table.insert(v, 'WORKFLOW_PARENT_INVALID')
  else args.depth = math.max(args.depth, tonumber(parent_depth) + 1) end
end
check(steps + 1 > l.max_steps, 'MAX_AGENT_STEPS_EXCEEDED')
check(llm + args.llm > l.max_llm_calls, 'MAX_LLM_CALLS_EXCEEDED')
check(tool + args.tool > l.max_tool_calls, 'MAX_TOOL_CALLS_EXCEEDED')
check(args.depth > l.max_depth, 'MAX_WORKFLOW_DEPTH_EXCEEDED')
check(now - start > l.max_wall_time_seconds, 'MAX_WALL_TIME_EXCEEDED')
check(redis.call('ZCARD', agent) >= l.concurrent_requests, 'CONCURRENCY_LIMIT_EXCEEDED')
check(redis.call('ZCARD', rate) > args.rpm, 'REQUEST_RATE_EXCEEDED')
check(num('credits') + held_c + args.credits > l.credit_limit + 0.000000001, 'CREDIT_LIMIT_EXCEEDED')
check(num('tokens') + held_t + args.tokens > l.token_limit, 'TOKEN_LIMIT_EXCEEDED')
if #v > 0 then return cjson.encode({violations=v, steps=steps, llm_calls=llm, tool_calls=tool}) end
redis.call('HSET', state, 'start', start, 'steps', steps + 1, 'llm', llm + args.llm, 'tool', tool + args.tool)
redis.call('HSET', state, 'd:' .. args.request_id, args.depth)
redis.call('HSET', state, 'r:' .. args.id, cjson.encode({credits=args.credits, tokens=args.tokens}))
redis.call('ZADD', active, now + l.reservation_ttl_seconds, args.id)
redis.call('ZADD', agent, now + l.reservation_ttl_seconds, state .. '|' .. args.id)
redis.call('EXPIRE', agent, 86400)
redis.call('EXPIRE', state, 86400)
redis.call('EXPIRE', active, 86400)
return cjson.encode({id=args.id, steps=steps+1, llm_calls=llm+args.llm, tool_calls=tool+args.tool, depth=args.depth})
"""

BEGIN_LUA = r"""
local raw = redis.call('HGET', KEYS[1], 'r:' .. ARGV[1])
if not raw then return 0 end
local held = cjson.decode(raw)
local expires = tonumber(redis.call('ZSCORE', KEYS[2], ARGV[1]) or '0')
if held.charged or expires <= tonumber(ARGV[2]) then return 0 end
held.charged = true
redis.call('HSET', KEYS[1], 'r:' .. ARGV[1], cjson.encode(held))
redis.call('HINCRBYFLOAT', KEYS[1], 'credits', held.credits)
redis.call('HINCRBY', KEYS[1], 'tokens', held.tokens)
return 1
"""

RECONCILE_LUA = r"""
local state, active = KEYS[1], KEYS[2]
local id, tokens, credits, now = ARGV[1], tonumber(ARGV[2]), tonumber(ARGV[3]), tonumber(ARGV[4])
local raw = redis.call('HGET', state, 'r:' .. id)
if not raw then return 0 end
local held = cjson.decode(raw)
local expires = tonumber(redis.call('ZSCORE', active, id) or '0')
redis.call('ZREM', KEYS[3], state .. '|' .. id)
redis.call('HDEL', state, 'r:' .. id)
redis.call('ZREM', active, id)
local prior_c, prior_t = 0, 0
if held.charged then prior_c, prior_t = held.credits, held.tokens end
redis.call('HINCRBYFLOAT', state, 'credits', math.max(0, credits) - prior_c)
redis.call('HINCRBY', state, 'tokens', math.max(0, tokens) - prior_t)
if tokens > held.tokens or credits > held.credits + 0.000000001 or expires <= now then return 0 end
return 1
"""


class RedisBudgetManager:
    def __init__(self, redis, clock=time.time):
        self.redis, self.clock = redis, clock

    async def reserve(self, tx, policy, tokens, credits):
        key, user = keys(tx)
        args = {
            "now": self.clock(),
            "id": str(uuid4()),
            "limits": policy.budgets.per_agent.model_dump(),
            "rpm": policy.budgets.per_user.requests_per_minute,
            "tokens": tokens,
            "credits": credits,
            "depth": tx.context.workflow.depth,
            "llm": int(tx.operation == Operation.LLM_REQUEST),
            "parent": tx.context.workflow.parent_request_id or "",
            "request_id": tx.request_id,
            "tool": int(tx.operation in {Operation.TOOL_CALL, Operation.MCP_TOOL_CALL, Operation.API_CALL}),
        }
        result = json.loads(
            await self.redis.eval(
                RESERVE_LUA, 4, key, key + ":active", user, agent_key(key), json.dumps(args)
            )
        )
        result["violations"] = result.get("violations") or []
        tx.context.workflow.depth = result.pop("depth", tx.context.workflow.depth)
        return Reservation(
            key=key,
            credits=credits if result.get("id") else 0,
            tokens=tokens if result.get("id") else 0,
            **result,
        )

    async def reconcile(self, reservation, tokens, credits):
        if not reservation.id:
            return True
        return bool(
            await self.redis.eval(
                RECONCILE_LUA,
                3,
                reservation.key,
                reservation.key + ":active",
                agent_key(reservation.key),
                reservation.id,
                tokens,
                credits,
                self.clock(),
            )
        )

    async def begin(self, reservation):
        if not reservation.id:
            return False
        return bool(
            await self.redis.eval(
                BEGIN_LUA, 2, reservation.key, reservation.key + ":active", reservation.id, self.clock()
            )
        )
