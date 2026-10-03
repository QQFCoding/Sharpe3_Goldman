import asyncio

import fakeredis.aioredis
import pytest

from app.budget.manager import InMemoryBudgetManager, RedisBudgetManager
from app.core.transaction import Operation, Principal, SecurityTransaction, WorkflowContext
from app.policy.loader import PolicyStore
from app.settings import ROOT


def transaction(tenant="a"):
    tx = SecurityTransaction(
        principal=Principal(subject="alice", tenant_id=tenant, agent_id="agent"),
        operation=Operation.LLM_REQUEST,
        payload={},
    )
    tx.context.workflow = WorkflowContext(workflow_id="shared")
    return tx


@pytest.fixture(params=["memory", "redis"])
async def backend(request):
    now = [1000.0]
    if request.param == "redis":
        redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
        manager = RedisBudgetManager(redis, clock=lambda: now[0])
        yield manager, now
        await redis.aclose()
    else:
        yield InMemoryBudgetManager(clock=lambda: now[0]), now


def policy():
    p = PolicyStore(ROOT / "config/policy.yaml").active.policy
    p.budgets.per_agent.concurrent_requests = 100
    p.budgets.per_agent.credit_limit = 3
    p.budgets.per_user.requests_per_minute = 1000
    return p


async def test_atomic_reservations_prevent_overspend(backend):
    manager, _ = backend
    p = policy()
    results = await asyncio.gather(*(manager.reserve(transaction(), p, 1, 1) for _ in range(20)))
    admitted = [r for r in results if r.id]
    assert len(admitted) == 3
    assert all("CREDIT_LIMIT_EXCEEDED" in r.violations for r in results if not r.id)
    assert await manager.reconcile(admitted[0], 1, 0.4)
    assert not await manager.reconcile(admitted[0], 1, 0.4)  # No double charging/release.
    assert (await manager.reserve(transaction(), p, 1, 0.5)).id
    assert not (await manager.reserve(transaction(), p, 1, 0.2)).id


async def test_abandoned_expiration_and_tenant_separation(backend):
    manager, now = backend
    p = policy()
    p.budgets.per_agent.reservation_ttl_seconds = 1
    old = await manager.reserve(transaction(), p, 1, 3)
    assert old.id
    assert (await manager.reserve(transaction("b"), p, 1, 3)).id
    now[0] += 2
    assert (await manager.reserve(transaction(), p, 1, 3)).id
    assert not await manager.reconcile(old, 1, 1)


async def test_started_action_expiration_keeps_charge_and_single_begin(backend):
    manager, now = backend
    p = policy()
    p.budgets.per_agent.reservation_ttl_seconds = 1
    reservation = await manager.reserve(transaction(), p, 1, 3)
    assert await manager.begin(reservation)
    assert not await manager.begin(reservation)
    now[0] += 2
    assert not (await manager.reserve(transaction(), p, 1, 1)).id
    assert not await manager.reconcile(reservation, 1, 1)


async def test_concurrency_is_agent_wide_across_workflows(backend):
    manager, _ = backend
    p = policy()
    p.budgets.per_agent.concurrent_requests = 2
    requests = [transaction() for _ in range(8)]
    for i, tx in enumerate(requests):
        tx.context.workflow.workflow_id = f"different-workflow-{i}"
    results = await asyncio.gather(*(manager.reserve(tx, p, 1, 0.1) for tx in requests))
    assert sum(bool(r.id) for r in results) == 2
    assert all("CONCURRENCY_LIMIT_EXCEEDED" in r.violations for r in results if not r.id)


async def test_tokens_concurrency_rate_and_parent_depth(backend):
    manager, now = backend
    p = policy()
    p.budgets.per_agent.token_limit = 2
    p.budgets.per_agent.concurrent_requests = 1
    p.budgets.per_user.requests_per_minute = 3
    first_tx = transaction()
    first = await manager.reserve(first_tx, p, 2, 1)
    second = await manager.reserve(transaction(), p, 1, 1)
    assert "CONCURRENCY_LIMIT_EXCEEDED" in second.violations
    await manager.reconcile(first, 2, 1)
    third = await manager.reserve(transaction(), p, 1, 1)
    assert "TOKEN_LIMIT_EXCEEDED" in third.violations
    fourth = await manager.reserve(transaction(), p, 0, 0)
    assert "REQUEST_RATE_EXCEEDED" in fourth.violations
    now[0] += 61
    p.budgets.per_agent.max_depth = 0
    child = transaction()
    child.context.workflow.parent_request_id = first_tx.request_id
    parent = await manager.reserve(child, p, 0, 0)
    assert "MAX_WORKFLOW_DEPTH_EXCEEDED" in parent.violations
