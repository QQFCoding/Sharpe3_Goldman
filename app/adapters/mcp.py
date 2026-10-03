from app.adapters.base import UpstreamResult
from app.adapters.openai_compatible import UpstreamFailure, bounded_json


class MCPAdapter:
    """Minimal non-streaming JSON-RPC MCP tools/call adapter. Endpoint is operator-configured."""

    def __init__(self, client, url, timeout=15):
        self.client, self.url, self.timeout = client, url, timeout

    async def list_tools(self):
        result = await bounded_json(self.client, f"{self.url}/mcp",
            {"jsonrpc": "2.0", "id": "manifest", "method": "tools/list"}, 131072, self.timeout)
        if result.get("id") != "manifest" or result.get("jsonrpc") != "2.0":
            raise UpstreamFailure("Invalid manifest response")
        tools = result["result"]["tools"]
        if not isinstance(tools, list) or len(tools) > 128:
            raise UpstreamFailure("Invalid manifest list")
        return tools

    async def execute(self, transaction):
        result = await bounded_json(
            self.client,
            f"{self.url}/mcp",
            {
                "jsonrpc": "2.0",
                "id": transaction.request_id,
                "method": "tools/call",
                "params": {"name": transaction.resource.name, "arguments": transaction.payload},
            },
            transaction.metadata["response_limit"] + 4096,
            self.timeout,
        )
        if result.get("id") != transaction.request_id or result.get("jsonrpc") != "2.0" or "error" in result:
            raise UpstreamFailure("Invalid MCP response")
        return UpstreamResult(output=result["result"]["structuredContent"])
