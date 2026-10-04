import httpx
import pytest

from app.client import ControlClient, GatewayDenied, GatewayResponse, tool_request


@pytest.mark.parametrize("decision", ["BLOCK", "REQUIRE_APPROVAL", "TERMINATE", "QUARANTINE"])
def test_client_requires_permitted_output(decision):
    result = GatewayResponse(403, {"security": {"decision": decision, "reason_codes": ["DENIED"]},
                                   "output": {"content": "must not use"}})
    with pytest.raises(GatewayDenied) as error:
        result.require_output()
    assert error.value.result is result


async def test_client_does_not_retry_denied_mutation_and_carries_identity():
    calls = []
    def handle(request):
        calls.append(request)
        return httpx.Response(403, json={"security": {"decision": "REQUIRE_APPROVAL"}, "output": None})
    body = tool_request("filesystem.write", {"path": "report.txt", "content": "Public"},
                        "workflow", execution_id="operation-1")
    async with ControlClient("http://gateway", "application-token", transport=httpx.MockTransport(handle)) as client:
        result = await client.transaction(body)
    assert result.decision == "REQUIRE_APPROVAL" and len(calls) == 1
    assert calls[0].headers["authorization"] == "Bearer application-token"
    assert body["execution_id"] == "operation-1"


async def test_approval_is_separate_explicit_operator_request():
    calls = []
    def handle(request):
        calls.append(request)
        return httpx.Response(200, json={"approval_token": "synthetic-approval"})
    async with ControlClient("http://gateway", "operator-token", transport=httpx.MockTransport(handle)) as operator:
        token = await operator.issue_approval(tool_request("github.create_issue", {"title": "Public", "body": "Notes"},
            "workflow", execution_id="report-1"), subject="alice", tenant_id="tenant-a", agent_id="demo-agent")
    assert token == "synthetic-approval" and calls[0].url.path == "/admin/approvals"


def test_empty_identity_is_rejected():
    with pytest.raises(ValueError):
        ControlClient("http://gateway", "")
