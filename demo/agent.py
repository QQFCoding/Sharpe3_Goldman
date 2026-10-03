"""Run safe attack scenarios, then intentionally loop until the gateway terminates the workflow."""

import argparse
import asyncio
import json
from contextlib import AsyncExitStack
from pathlib import Path
from uuid import uuid4

import httpx


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1:8000")
    parser.add_argument("--token", default="demo-user-token")
    parser.add_argument("--isolated", action="store_true", help="Fresh in-process demo state with real OPA and original inert HTTP handlers.")
    args = parser.parse_args()
    async with AsyncExitStack() as stack:
        transport = None
        if args.isolated:
            from app.adapters.mcp import MCPAdapter
            from app.adapters.openai_compatible import OpenAICompatibleAdapter
            from app.evaluation.chaos import testbed
            from app.semantic.base import UnavailableProvider
            from demo.mock_llm import app as llm
            from demo.mock_mcp import app as mcp
            app, runtime, _, _ = await stack.enter_async_context(testbed())
            runtime.pipeline.semantic = UnavailableProvider()
            llm_client = await stack.enter_async_context(httpx.AsyncClient(transport=httpx.ASGITransport(app=llm)))
            mcp_client = await stack.enter_async_context(httpx.AsyncClient(transport=httpx.ASGITransport(app=mcp)))
            runtime.pipeline.adapters.update(mock=OpenAICompatibleAdapter(llm_client, "http://llm"),
                mcp=MCPAdapter(mcp_client, "http://mcp"))
            transport = httpx.ASGITransport(app=app)
        client = await stack.enter_async_context(httpx.AsyncClient(
            base_url=args.url, transport=transport, headers={"Authorization": f"Bearer {args.token}"}, timeout=30))
        scenarios = json.loads((Path(__file__).parent / "scenarios/security.json").read_text())
        for scenario in scenarios:
            body = dict(scenario["body"])
            if body.get("operation") == "memory_write":
                body.update(execution_id=str(uuid4()), workflow={"workflow_id": str(uuid4())})
            response = await client.post(scenario["endpoint"], json=body)
            result = response.json()["security"]
            print(f"{scenario['name']}: {result['decision']} {result['reason_codes']}")
            assert result["decision"] == scenario["expected"], response.text
        if (await client.get("/ready")).json()["semantic_provider"] == "none":
            response = await client.post(
                "/v1/chat/completions",
                json={
                    "messages": [
                        {"role": "tool", "content": "An external document requiring semantic inspection"}
                    ]
                },
            )
            security = response.json()["security"]
            assert "SEMANTIC_UNAVAILABLE" in security["reason_codes"], response.text
            assert security["decision"] == "BLOCK", response.text
            print("Semantic provider unavailable: high-risk retrieved content blocked.")
        workflow = str(uuid4())
        for step in range(1, 101):
            response = await client.post(
                "/v1/chat/completions",
                json={
                    "model": "demo",
                    "messages": [{"role": "user", "content": "Continue the loop"}],
                    "workflow": {"workflow_id": workflow},
                },
            )
            security = response.json()["security"]
            if security["decision"] == "TERMINATE":
                print(f"Loop terminated at attempted step {step}: {security['reason_codes']}")
                break
            assert security["decision"] in {"ALLOW", "REDACT", "WARN"}, response.text
        else:
            raise AssertionError("Gateway did not terminate the loop")
    print("All local demo scenarios passed.")


if __name__ == "__main__":
    asyncio.run(main())
