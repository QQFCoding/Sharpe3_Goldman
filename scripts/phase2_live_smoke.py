"""Verify live Phase 2 enforcement with public demo identities and synthetic data.

Bob retains protected exposure for the configured lifetime. No real side effects
are attempted; the stack's MCP services are inert demos. Tokens are never printed.
"""
import json
import subprocess
import sys
from pathlib import Path
from uuid import uuid4

import httpx

ROOT = Path(__file__).resolve().parents[1]


def main():
    workflow = "live-phase2-" + uuid4().hex
    headers = {"Authorization": "Bearer demo-other-token"}
    with httpx.Client(base_url="http://127.0.0.1:8000", headers=headers, timeout=15) as client:
        assert client.get("/ready").status_code == 200

        def transaction(body, expected=200, extra_headers=None):
            response = client.post("/v1/transactions", json=body, headers=extra_headers)
            assert response.status_code == expected, response.text
            return response.json()

        record = transaction({"operation": "memory_write", "payload": {
            "content": "Synthetic confidential board meeting details", "source": "application",
            "classification": "private", "ttl_seconds": 300}, "workflow": {"workflow_id": workflow}})
        for _ in range(3):
            read = transaction({"operation": "memory_read", "payload": {
                "memory_id": record["output"]["memory_id"]}, "workflow": {"workflow_id": workflow}})
            assert "private" in read["data_security"]["confidentiality"]
        blocked = transaction({"operation": "mcp_tool_call", "resource": {"name": "email.send"},
            "payload": {"to": "outside@example.org", "body": "Abstract transformed summary"},
            "workflow": {"workflow_id": workflow + "-new"}}, expected=403)
        assert "CONFIDENTIAL_DATA_TO_EXTERNAL_SINK" in blocked["security"]["reason_codes"]
        assert blocked["output"] is None

        intent = {"workflow_id": workflow, "goal": "Read a local public document",
            "allowed_effects": ["read"], "allowed_resources": ["filesystem.read"]}
        assert client.post("/v1/workflows", json=intent).status_code == 200
        assert client.post("/v1/workflows", json=intent).status_code == 409
        delegation = client.post("/v1/delegations", json={"agent_id": "demo-child", "workflow_id": workflow,
            "scopes": ["files:read", "agents:delegate"], "capabilities": ["filesystem.read"]})
        assert delegation.status_code == 200, delegation.text
        assert delegation.json()["expires_in_seconds"] == 300
        child_headers = {"Authorization": "Bearer " + delegation.json()["token"]}
        read_tool = {"operation": "mcp_tool_call", "resource": {"name": "filesystem.read"},
            "payload": {"path": "public.txt"}, "workflow": {"workflow_id": workflow}}
        transaction(read_tool, extra_headers=child_headers)
        escalation = client.post("/v1/delegations", headers=child_headers, json={"agent_id": "demo-child",
            "workflow_id": workflow, "scopes": ["files:write"], "capabilities": ["filesystem.write"]})
        assert escalation.status_code == 403
        read_tool["workflow"]["workflow_id"] = workflow + "-escaped"
        escaped = transaction(read_tool, expected=403, extra_headers=child_headers)
        assert "DELEGATION_WORKFLOW_BOUNDARY" in escaped["security"]["reason_codes"]

        jwt_token = subprocess.run([sys.executable, str(ROOT / "scripts/jwt_demo.py")],
            check=True, capture_output=True, text=True, timeout=10).stdout.strip()
        read_tool["workflow"]["workflow_id"] = workflow + "-jwt"
        transaction(read_tool, extra_headers={"Authorization": "Bearer " + jwt_token})
        policy = client.get("/admin/policy", headers={"Authorization": "Bearer demo-admin-token"})
        assert policy.status_code == 200

    permissions = subprocess.run(["docker", "compose", "exec", "-T", "postgres", "psql", "-U", "aicl",
        "-d", "aicl", "-tAc", "SELECT has_table_privilege('aicl_grafana','aicl_security_events','SELECT'), "
        "has_table_privilege('aicl_grafana','aicl_audit','SELECT'), "
        "has_table_privilege('aicl_grafana','aicl_memory','SELECT')"],
        cwd=ROOT, check=True, capture_output=True, text=True, timeout=10).stdout.strip()
    assert permissions == "t|f|f", permissions
    report = {"live_redis_label_join": "passed", "private_sink_preexecution_block": "passed",
        "immutable_intent": "passed", "delegation_attenuation_and_workflow": "passed",
        "rs256_jwt": "passed", "restricted_grafana_view": "passed"}
    path = ROOT / "artifacts/phase2-live-smoke.json"
    path.parent.mkdir(exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
