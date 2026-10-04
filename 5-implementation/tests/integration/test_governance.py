import json

import fakeredis.aioredis
import pytest
import yaml

from app.budget.manager import InMemoryBudgetManager, RedisBudgetManager, keys
from app.core.transaction import Operation, SecurityTransaction, WorkflowContext
from tests.conftest import chat_body

ADMIN = {"Authorization": "Bearer demo-admin-token"}
SCOPE = {"subject": "alice", "tenant_id": "tenant-a", "agent_id": "demo-agent", "workflow_id": "governance-test"}


async def snapshot(client, **changes):
    return await client.get("/admin/governance/budget", params={**SCOPE, **changes}, headers=ADMIN)


def transaction(runtime, workflow="governance-test", token="demo-user-token"):
    tx = SecurityTransaction(principal=runtime.auth.authenticate(token), operation=Operation.LLM_REQUEST, payload={})
    tx.context.workflow = WorkflowContext(workflow_id=workflow)
    return tx


async def test_governance_requires_admin_and_exposes_only_safe_effective_config(running):
    client, runtime = running
    for path in ("/admin/governance", "/admin/governance/budget", "/admin/governance/audit/export"):
        assert (await client.get(path)).status_code == 403
    assert (await client.post("/admin/governance/reload", json={})).status_code == 403
    runtime.pipeline.semantic.provider_id = "deberta"
    response = await client.get("/admin/governance", headers=ADMIN)
    assert response.status_code == 200 and response.headers["cache-control"] == "no-store"
    body = response.json()
    expected = runtime.policies.active.policy.controls.prompt_injection.semantic.provider_thresholds["deberta"]
    assert body["controls"]["prompt_injection"]["block_threshold"] == expected.block_threshold
    assert body["controls"]["prompt_injection"]["threshold_source"] == "provider_override"
    assert body["storage"]["audit"] == "process_memory"
    assert body["costs"]["provider_billing_verified"] is False
    assert {k: SCOPE[k] for k in ("subject", "tenant_id", "agent_id")} in body["identities"]
    for private in ("demo-user-token", "demo-admin-token", str(runtime.settings.policy_path), "token_sha256"):
        assert private not in response.text


@pytest.mark.parametrize("backend", ["memory", "redis"])
async def test_scoped_accounting_reservations_charges_expiry_and_isolation(running, backend):
    client, runtime = running
    now = [1000.0]
    redis = fakeredis.aioredis.FakeRedis(decode_responses=True) if backend == "redis" else None
    manager = RedisBudgetManager(redis, clock=lambda: now[0]) if redis else InMemoryBudgetManager(clock=lambda: now[0])
    runtime.budgets = manager
    policy = runtime.policies.active.policy
    policy.budgets.per_agent.reservation_ttl_seconds = 10
    tx = transaction(runtime)
    try:
        absent = (await snapshot(client)).json()
        assert absent["workflow_present"] is False and absent["usage"]["tokens"]["used"] == 0
        first = await manager.reserve(tx, policy, 50, 2)
        held = (await snapshot(client)).json()
        assert held["usage"]["tokens"]["reserved"] == 50 and held["usage"]["credits"]["reserved"] == 2
        assert held["concurrency"]["active"] == 1 and held["rate"]["requests_last_60s"] == 1
        assert await manager.begin(first)
        await manager.reserve(transaction(runtime, workflow="another-workflow"), policy, 10, 1)
        await manager.reserve(transaction(runtime, token="demo-other-token"), policy, 90, 3)
        charged = (await snapshot(client)).json()
        assert charged["usage"]["tokens"]["used"] == 50 and charged["usage"]["tokens"]["reserved"] == 0
        assert charged["usage"]["tokens"]["remaining"] == policy.budgets.per_agent.token_limit - 50
        assert charged["usage"]["steps"]["used"] == 1 and charged["concurrency"]["active"] == 2
        assert charged["rate"]["requests_last_60s"] == 2
        other = (await snapshot(client, subject="bob", tenant_id="tenant-b")).json()
        assert other["usage"]["tokens"]["reserved"] == 90 and other["usage"]["tokens"]["used"] == 0
        now[0] += 11
        expired = (await snapshot(client)).json()
        assert expired["active_reservations"] == expired["concurrency"]["active"] == 0
        assert expired["usage"]["tokens"]["used"] == 50
        assert expired["usage"]["tokens"]["reserved"] == 0
        if backend == "redis":
            assert await redis.hexists(keys(tx)[0], "r:" + first.id)
        else:
            assert first.id in manager.workflows[keys(tx)[0]]["active"]
        # A read never deletes holds or changes the conservative charge; reconciliation owns that action.
        assert not await manager.reconcile(first, 20, .5)
        reconciled = (await snapshot(client)).json()
        assert reconciled["usage"]["tokens"]["used"] == 20 and reconciled["usage"]["credits"]["used"] == .5
    finally:
        if redis:
            await redis.aclose()


async def test_actual_gateway_execution_consumes_budget_but_inert_lab_does_not(running):
    client, runtime = running
    await client.post("/admin/detection/inspect", headers=ADMIN, json={"text": "Public museum hours"})
    assert not (await snapshot(client)).json()["workflow_present"]
    response = await client.post("/v1/chat/completions", json=chat_body(workflow={"workflow_id": SCOPE["workflow_id"]}))
    assert response.status_code == 200 and len(runtime.llm_spy.calls) == 1
    body = (await snapshot(client)).json()
    assert body["workflow_present"] and body["usage"]["tokens"]["used"] > 0
    assert body["usage"]["credits"]["used"] > 0 and body["usage"]["credits"]["reserved"] == 0
    assert body["usage"]["llm_calls"]["used"] == 1


async def test_identity_validation_and_backend_failure_never_fabricate_usage(running):
    client, runtime = running
    assert (await snapshot(client, agent_id="not-a-configured-agent")).status_code == 404
    assert (await snapshot(client, workflow_id="")).status_code == 422
    class FailedRedis:
        async def eval(self, *args):
            raise RuntimeError("private database credential")
    runtime.budgets = RedisBudgetManager(FailedRedis())
    response = await snapshot(client)
    assert response.status_code == 503 and response.json() == {"error": "BUDGET_ACCOUNTING_UNAVAILABLE"}


async def test_atomic_reload_visible_success_rejection_and_no_parser_value_leak(running):
    client, runtime = running
    path = runtime.settings.policy_path
    policy = yaml.safe_load(path.read_text(encoding="utf-8"))
    previous = policy["metadata"]["revision"]
    policy["metadata"]["revision"] = "governance-updated"
    policy["budgets"]["per_agent"]["token_limit"] = 12345
    path.write_text(yaml.safe_dump(policy), encoding="utf-8")
    success = await client.post("/admin/governance/reload", headers=ADMIN, json={"kind": "policy"})
    assert success.status_code == 200 and success.json()["previous_revision"] == previous
    assert (await client.get("/admin/governance", headers=ADMIN)).json()["budgets"]["per_agent"]["token_limit"] == 12345
    path.write_text("broken: [PRIVATE_PARSER_VALUE", encoding="utf-8")
    refused = await client.post("/admin/governance/reload", headers=ADMIN, json={"kind": "threat_feed"})
    assert refused.status_code == 422 and "PRIVATE_PARSER_VALUE" not in refused.text
    result = (await client.get("/admin/governance", headers=ADMIN)).json()["last_reload"]
    assert result["status"] == "rejected" and result["last_valid_policy_retained"]
    assert result["policy_revision"] == "governance-updated"


async def test_audit_export_is_bounded_filterable_and_excludes_arbitrary_evidence(running):
    client, runtime = running
    secret = "SYNTHETIC_PRIVATE_EXPORT_VALUE"
    await client.post("/admin/detection/inspect", headers=ADMIN, json={"text": "password=" + secret})
    event = runtime.audit.events[-1]
    event["raw_payload"] = secret
    event["security"]["transformations"] = [{"private": secret}]
    event["detection_report"]["findings"][0]["evidence"]["untrusted_raw_value"] = secret
    response = await client.get("/admin/governance/audit/export?limit=1", headers=ADMIN)
    assert response.status_code == 200 and secret not in response.text
    assert response.headers["content-type"].startswith("application/x-ndjson")
    assert response.headers["x-audit-scanned"] == response.headers["x-audit-exported"] == "1"
    rows = [json.loads(line) for line in response.text.splitlines()]
    assert len(rows) == 1 and rows[0]["security"]["decision"] == "BLOCK"
    assert "transformations" not in rows[0]["security"] and "evidence" not in rows[0]["findings"][0]
    empty = await client.get("/admin/governance/audit/export?tenant_id=no-such-tenant", headers=ADMIN)
    assert empty.status_code == 200 and empty.text == ""
    assert (await client.get("/admin/governance/audit/export?limit=10001", headers=ADMIN)).status_code == 422
