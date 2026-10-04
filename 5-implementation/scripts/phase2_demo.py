"""Phase 2 demonstration uses inert tools; optional real public classifier when installed."""
import asyncio
import hashlib
import os
import tempfile
from pathlib import Path

import httpx
import yaml

from app.evaluation.fixtures import SafeAdapter
from app.main import create_app
from app.semantic.deberta import DebertaProvider
from app.settings import ROOT, Settings


async def main():
    with tempfile.TemporaryDirectory() as directory:
        config = Path(directory)
        policy = yaml.safe_load((ROOT / "config/policy.yaml").read_text())
        policy["budgets"]["per_user"]["requests_per_minute"] = 100000
        (config / "policy.yaml").write_text(yaml.safe_dump(policy))
        (config / "threat-feed.yaml").write_bytes((ROOT / "config/threat-feed.yaml").read_bytes())
        app = create_app(Settings(_env_file=None, policy_path=config / "policy.yaml",
            opa_binary=ROOT / ".tools" / ("opa.exe" if os.name == "nt" else "opa")))
        async with app.router.lifespan_context(app):
            runtime = app.state.runtime
            tool = SafeAdapter(tool=True)
            runtime.pipeline.adapters.update(mock=SafeAdapter(), mcp=tool)
            if (ROOT / "models/deberta/model.safetensors").is_file():
                import torch
                torch.set_num_threads(2)
                runtime.pipeline.semantic = DebertaProvider(str(ROOT / "models/deberta"))
                await asyncio.to_thread(runtime.pipeline.semantic._load)
                runtime.pipeline.semantic_timeout = 60
                print("Optional semantic checks use real local ProtectAI weights.")
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://demo",
                    headers={"Authorization": "Bearer demo-user-token"}) as client:
                async def show(name, body, expected, headers=None):
                    response = await client.post("/v1/transactions", json=body, headers=headers)
                    security = response.json()["security"]
                    print(name, "->", security["decision"], security["reason_codes"])
                    assert security["decision"] in expected, response.text
                    return response.json()
                def action(name, payload, workflow="phase2"):
                    return {"operation": "mcp_tool_call", "resource": {"name": name}, "payload": payload,
                        "workflow": {"workflow_id": workflow}}
                parent = next(p for p in runtime.auth.records.values() if p.subject == "alice")
                from app.core.labels import DataSecurityLabel
                await runtime.workflows.absorb(parent, "untrusted", DataSecurityLabel(
                    integrity="untrusted", taints=frozenset({"untrusted_origin"})))
                await show("Untrusted document controls destructive action",
                    action("github.delete_repository", {"repository": "synthetic"}, "untrusted"), {"BLOCK"})
                protected = await show("Protected memory write", {"operation": "memory_write",
                    "payload": {"content": "Synthetic board meeting details", "source": "application", "classification": "private"},
                    "workflow": {"workflow_id": "protected"}}, {"ALLOW"})
                await show("Protected memory read", {"operation": "memory_read",
                    "payload": {"memory_id": protected["output"]["memory_id"]}, "workflow": {"workflow_id": "protected"}}, {"ALLOW"})
                await show("Transformed private data to external sink before execution",
                    action("email.send", {"to": "outside@example.org", "body": "Abstract transformed summary"}, "new-channel"), {"BLOCK"})
                assert not any(t.resource.name == "email.send" for t in tool.calls)
                # Bob has independent exposure state; Alice's protected data cannot contaminate another tenant.
                bob_headers = {"Authorization": "Bearer demo-other-token"}
                registered = await client.post("/v1/workflows", headers=bob_headers, json={"workflow_id": "aligned",
                    "goal": "Create a public issue about documentation", "allowed_effects": ["external_side_effect"],
                    "allowed_resources": ["github.create_issue"]})
                assert registered.status_code == 200
                mutation = action("github.create_issue", {"title": "Document setup", "body": "Public documentation"}, "aligned")
                await show("Alignment reviewer abstains; high-impact action requires approval", mutation,
                    {"REQUIRE_APPROVAL"}, bob_headers)
                approved = await client.post("/admin/approvals", headers={"Authorization": "Bearer demo-admin-token"},
                    json={"subject": "bob", "tenant_id": "tenant-b", "request": mutation})
                mutation["approval_token"] = approved.json()["approval_token"]
                expected = {"ALLOW", "WARN"} if isinstance(runtime.pipeline.semantic, DebertaProvider) else {"BLOCK"}
                await show("Exact approval still passes semantic and deterministic checks", mutation, expected, bob_headers)
                delegation = await client.post("/v1/delegations", json={"agent_id": "demo-child", "workflow_id": "child",
                    "scopes": ["files:read", "agents:delegate"], "capabilities": ["filesystem.read"]})
                child_headers = {"Authorization": "Bearer " + delegation.json()["token"]}
                escalated = await client.post("/v1/delegations", headers=child_headers, json={"agent_id": "demo-child",
                    "workflow_id": "child", "scopes": ["files:write"], "capabilities": ["filesystem.write"]})
                assert escalated.status_code == 403
                print("Child capability escalation -> BLOCK")
                pin = runtime.pipeline.manifests.pins["github.search"]["tool_description_hash"]
                runtime.pipeline.manifests.pins["github.search"]["tool_description_hash"] = hashlib.sha256(b"drift").hexdigest()
                await show("MCP manifest drift", action("github.search", {"query": "public"}, "manifest"), {"BLOCK"}, bob_headers)
                runtime.pipeline.manifests.pins["github.search"]["tool_description_hash"] = pin
                marker = "phase two reload marker"
                chat = {"operation": "llm_request", "payload": {"messages": [{"role": "user", "content": marker}]}}
                await show("Before policy reload", chat, {"ALLOW"}, bob_headers)
                policy["metadata"]["revision"] = "phase2-demo-policy"
                saved_models = policy["models"]["allowed"]
                policy["models"]["allowed"] = [m for m in saved_models if m["provider"] != "mock"]
                (config / "policy.yaml").write_text(yaml.safe_dump(policy))
                assert (await client.post("/admin/policy/reload",
                    headers={"Authorization": "Bearer demo-admin-token"})).status_code == 200
                await show("Policy hot reload removes model permission", chat, {"BLOCK"}, bob_headers)
                policy["metadata"]["revision"] = "phase2-demo-restored"
                policy["models"]["allowed"] = saved_models
                (config / "policy.yaml").write_text(yaml.safe_dump(policy))
                assert (await client.post("/admin/policy/reload",
                    headers={"Authorization": "Bearer demo-admin-token"})).status_code == 200
                await show("Before new signature", chat, {"ALLOW"}, bob_headers)
                feed = yaml.safe_load((config / "threat-feed.yaml").read_text())
                feed["revision"] = "phase2-demo-feed"
                feed["rules"].append({"id": "DEMO-RELOAD", "category": "demo", "regex": [marker]})
                (config / "threat-feed.yaml").write_text(yaml.safe_dump(feed))
                assert (await client.post("/admin/threat-feed/reload",
                    headers={"Authorization": "Bearer demo-admin-token"})).status_code == 200
                await show("After signature hot reload", chat, {"BLOCK"}, bob_headers)
                print("Phase 2 demo passed; live SOC: http://127.0.0.1:3000/d/aicl-security")


if __name__ == "__main__":
    asyncio.run(main())
