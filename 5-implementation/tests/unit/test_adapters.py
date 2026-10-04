import httpx

from app.adapters.mcp import MCPAdapter
from app.adapters.ollama import OllamaAdapter
from app.adapters.openai_compatible import OpenAICompatibleAdapter
from app.core.transaction import Operation, Principal, Resource, SecurityTransaction
from app.semantic.ollama_classifier import OllamaSecurityProvider
from demo.mock_llm import app as llm
from demo.mock_mcp import app as mcp


def tx(operation, resource, payload):
    return SecurityTransaction(
        principal=Principal(subject="a", tenant_id="a"),
        operation=operation,
        resource=resource,
        payload=payload,
        metadata={"response_limit": 65536},
    )


async def test_mock_llm_and_mcp_wire_adapters():
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=llm), base_url="http://llm") as client:
        result = await OpenAICompatibleAdapter(client, "http://llm").execute(
            tx(
                Operation.LLM_REQUEST,
                Resource(name="demo", model="demo", provider="mock"),
                {"messages": [{"role": "user", "content": "Hello"}], "max_tokens": 256},
            )
        )
        assert "Hello" in result.output["content"]
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=mcp), base_url="http://mcp") as client:
        result = await MCPAdapter(client, "http://mcp").execute(
            tx(Operation.MCP_TOOL_CALL, Resource(name="github.search"), {"query": "safe"})
        )
        assert "Simulated" in result.output["result"]


async def test_ollama_generation_and_json_classifier():
    async def respond(request):
        import json

        body = json.loads(request.content)
        if "format" in body:
            return httpx.Response(200, json={"message": {"content": '{"prompt_injection":0.92}'}})
        return httpx.Response(200, json={"message": {"content": "Safe"}, "eval_count": 1})

    async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
        transaction = tx(
            Operation.LLM_REQUEST,
            Resource(name="qwen3:4b", model="qwen3:4b", provider="ollama"),
            {"messages": [{"role": "user", "content": "Hello"}]},
        )
        assert (await OllamaAdapter(client, "http://ollama").execute(transaction)).output["content"] == "Safe"
        risk = await OllamaSecurityProvider(client, "http://ollama", "qwen3:4b").analyze(transaction)
        assert risk.prompt_injection == 0.92
