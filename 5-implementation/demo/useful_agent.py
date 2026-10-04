"""Scripted issue-triage agent: useful output through the gateway, not an AgentDyn benchmark."""
import argparse
import asyncio
import json
from uuid import uuid4

from app.client import ControlClient, GatewayDenied, tool_request


async def triage(client: ControlClient, operator: ControlClient | None = None,
                 workflow_id: str | None = None) -> dict:
    workflow_id = workflow_id or f"triage-{uuid4()}"
    await client.register_workflow(workflow_id, "Read checkout issues and create one public triage report",
        ["github.search", "github.read_issue", "github.create_issue"], ["read", "external_side_effect"])
    receipts = []

    async def execute(body):
        result = await client.transaction(body)
        receipts.append({"decision": result.decision, "request_id": result.security.get("request_id"),
                         "reason_codes": result.security.get("reason_codes", [])})
        return result

    search = await execute(tool_request("github.search", {"query": "checkout"}, workflow_id))
    issues = json.loads(search.require_output()["result"])["issues"]
    records = []
    for issue in issues[:2]:
        read = await execute(tool_request("github.read_issue", {"issue": issue["id"]}, workflow_id))
        records.append(json.loads(read.require_output()["result"]))
    summary = await client.chat("Summarize these public issue records as a triage plan:\n" + json.dumps(records),
                               workflow_id=workflow_id, max_tokens=512)
    receipts.append({"decision": summary.decision, "request_id": summary.security.get("request_id"),
                     "reason_codes": summary.security.get("reason_codes", [])})
    content = summary.require_output()["content"]
    body = tool_request("github.create_issue", {"title": "Checkout triage report", "body": content},
                        workflow_id, execution_id=f"triage-report-{uuid4()}")
    write = await execute(body)
    if write.decision == "REQUIRE_APPROVAL" and operator is not None:
        token = await operator.issue_approval(body, subject="alice", tenant_id="tenant-a", agent_id="demo-agent")
        write = await execute({**body, "approval_token": token})
    if write.decision == "REQUIRE_APPROVAL":
        return {"completed": False, "awaiting_operator": True, "summary": content, "pending_request": body,
                "workflow_id": workflow_id, "receipts": receipts}
    created = json.loads(write.require_output()["result"])
    return {"completed": True, "summary": content, "created_issue": created,
            "workflow_id": workflow_id, "receipts": receipts}


async def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:8010")
    parser.add_argument("--token", default="demo-user-token")
    args = parser.parse_args()
    async with ControlClient(args.url, args.token) as client:
        try:
            result = await triage(client)
        except GatewayDenied as error:
            parser.exit(1, str(error) + "\n")
    print(json.dumps(result, indent=2, ensure_ascii=False))
    if result.get("awaiting_operator"):
        print("Operator approval is required. Use the isolated judge demo to exercise the complete approval flow.")


if __name__ == "__main__":
    asyncio.run(main())
