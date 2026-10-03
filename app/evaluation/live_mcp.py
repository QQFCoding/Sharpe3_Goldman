"""Run inside the live gateway container. No bearer tokens or response contents are printed."""
import asyncio
import json

import httpx

from app.adapters.mcp import MCPAdapter
from app.adapters.mcp_credentials import ServerCredentials
from app.adapters.mcp_protocol import headers, request
from app.settings import ROOT


async def main():
    servers = json.loads((ROOT / "config/mcp-servers.docker.json").read_text())
    credentials = ServerCredentials(ROOT / "config/demo-jwks.json", ROOT / "config/mcp-credentials.json")
    report = []
    async with httpx.AsyncClient(timeout=10, trust_env=False, follow_redirects=False) as client:
        for server in servers:
            adapter = MCPAdapter(client, server["url"], server=server, credentials=credentials)
            tools = await adapter.list_tools()
            report.append({"server": server["id"], "manifest_tools": len(tools)})
        body = request("tools/call", "isolation", {"name": "github.search", "arguments": {"query": "public"}})
        token = credentials.for_server(servers[0], ["repo:read"])
        for index, expected in [(0, 200), (1, 401)]:
            response = await client.post(servers[index]["url"] + "/mcp", json=body, headers=headers(body) | {"Authorization": "Bearer " + token})
            assert response.status_code == expected
            report.append({"internal_read_token_at": servers[index]["id"], "status": response.status_code})
        body = request("tools/call", "capability", {"name": "github.create_issue", "arguments": {"title": "public", "body": "public"}})
        response = await client.post(servers[0]["url"] + "/mcp", json=body, headers=headers(body) | {"Authorization": "Bearer " + token})
        assert response.status_code == 403
        report.append({"read_token_write": response.status_code})
    print(json.dumps({"checks": report}))
    from uuid import uuid4

    from app.core.auth import DEMO_SCOPES, approval_digest
    from app.core.transaction import OperationRequest, Principal
    from app.evaluation.chaos import FixtureSemantic
    from app.runtime import Runtime
    from app.settings import Settings
    runtime = Runtime(Settings(_env_file=None))
    await runtime.open()
    try:
        runtime.pipeline.semantic = FixtureSemantic()
        runtime.policies.active.policy.budgets.per_agent.concurrent_requests = 20
        principal = Principal(subject="phase3-eval-" + uuid4().hex, tenant_id="demo-evaluation", agent_id="execution-eval", scopes=DEMO_SCOPES)
        identity = uuid4().hex
        body = OperationRequest.model_validate({"operation": "mcp_tool_call", "resource": {"name": "trusted-internal::github.create_issue"},
            "payload": {"title": "Public runtime receipt", "body": "Synthetic public fixture"},
            "execution_id": identity, "workflow": {"workflow_id": identity}})
        tx = runtime.pipeline.prepare(body, principal)
        await runtime.pipeline.manifests.inspect(tx, runtime.pipeline.tool_adapter(tx), runtime.policies.active.policy.mcp)
        body.approval_token = await runtime.approvals.issue(approval_digest(tx, runtime.policies.active.policy.metadata.revision))
        adapter = runtime.pipeline.tool_adapter(tx)
        original_execute = adapter.execute
        dispatches = 0
        async def counted_execute(tx):
            nonlocal dispatches
            dispatches += 1
            return await original_execute(tx)
        adapter.execute = counted_execute
        results = await asyncio.gather(*(runtime.pipeline.execute(body, principal) for _ in range(20)))
        assert dispatches == 1
        assert sum(r.output is not None for r in results) == 1
        state = await runtime.executions.get(principal, identity)
        assert state["state"] == "COMPLETED"
        assert await runtime.redis.ttl(runtime.executions.key(principal, identity)) == -1
        assert (await runtime.redis.config_get("appendfsync"))["appendfsync"] == "always"
        print(json.dumps({"redis_execution": {"parallel_attempts": 20, "actual_mcp_dispatches": dispatches,
            "state": "COMPLETED", "ttl": "non-expiring", "appendfsync": "always", "audit": "actual PostgreSQL",
            "classifier": "explicit benign fixture; retry guarantee is independent of classifier"}}))
    finally:
        await runtime.close()


if __name__ == "__main__":
    asyncio.run(main())
