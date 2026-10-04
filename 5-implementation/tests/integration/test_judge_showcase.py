import json

import yaml

from app.client import ControlClient, tool_request
from app.policy.loader import Policy
from app.settings import ROOT
from demo.judge_showcase import run_showcase, showcase


async def test_scripted_utility_and_all_control_showcase_cases():
    report = await run_showcase("fixture")
    assert report["passed"] == 8
    assert all(case["passed"] for case in report["cases"])
    assert report["policy_engine"] == "actual OPA executable"
    assert report["semantic_provider"] == "fixture"


def test_all_profiles_preserve_hard_security_invariants():
    for name in ("strict", "balanced", "permissive"):
        policy = Policy.model_validate(yaml.safe_load((ROOT / "config/profiles" / f"{name}.yaml").read_text(encoding="utf-8")))
        assert policy.mode == "enforce" and policy.defaults.unknown_model == "deny"
        assert policy.defaults.unknown_tool == "deny" and policy.memory.enforce_tenant_boundary
        assert policy.controls.secrets.enabled
        assert policy.controls.secrets.input_action == policy.controls.secrets.output_action == "BLOCK"
        assert policy.controls.pii.enabled and policy.controls.pii.input_action in {"BLOCK", "REDACT"}
        assert policy.network.block_loopback and policy.network.block_private_ips and policy.network.resolve_dns
        assert policy.information_flow.enabled and policy.mcp.manifest_pinning
        assert "shell.exec" in policy.tools.deny and "github.create_issue" in policy.tools.require_approval


async def test_operator_approval_is_not_available_to_agent_identity():
    async with showcase() as (client, operator, runtime, state, directory):
        body = tool_request("github.create_issue", {"title": "Public", "body": "Notes"}, "separate-operator",
                            execution_id="separate-operator-1")
        response = await client.http.post("/admin/approvals", json={"subject": "alice", "tenant_id": "tenant-a",
                                                                  "request": body})
        assert response.status_code == 403 and not state.created_issues


async def test_gateway_client_rejects_invalid_auth_before_upstream():
    async with showcase() as (client, operator, runtime, state, directory):
        async with ControlClient("http://gateway", "invalid", transport=client.http._transport) as invalid:
            result = await invalid.chat("Public checkout status")
        assert result.status_code == 401 and result.security["reason_codes"] == ["UNAUTHENTICATED"]
        assert not state.calls and state.llm_calls == 0
        assert "Public checkout status" not in json.dumps(await runtime.audit.recent())
