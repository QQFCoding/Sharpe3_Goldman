from app.adapters.base import UpstreamResult
from app.adapters.mcp_credentials import validate_authorization_issuer
from app.adapters.mcp_protocol import headers, request
from app.adapters.openai_compatible import UpstreamFailure, bounded_get_json, bounded_json


class MCPAdapter:
    """Minimal non-streaming JSON-RPC MCP tools/call adapter. Endpoint is operator-configured."""

    def __init__(self, client, url, timeout=15, server=None, credentials=None):
        self.client, self.url, self.timeout = client, url, timeout
        self.server, self.credentials = server, credentials

    async def rpc(self, method, identity, params=None, limit=131072, scopes=(), schema=None):
        body = request(method, identity, params) if self.server else {
            "jsonrpc": "2.0", "id": identity, "method": method, **({"params": params} if params else {})}
        outgoing = headers(body, schema) if self.server else {}
        if self.server:
            outgoing["Authorization"] = "Bearer " + self.credentials.for_server(self.server, scopes)
        result = await bounded_json(self.client, f"{self.url}/mcp", body, limit, self.timeout, outgoing)
        if result.get("id") != identity or result.get("jsonrpc") != "2.0" or "error" in result:
            raise UpstreamFailure("Invalid MCP response")
        return result["result"]

    async def list_tools(self):
        if self.server:
            metadata = await bounded_get_json(self.client, self.url + "/.well-known/oauth-protected-resource", 16384, self.timeout)
            if metadata.get("resource") != self.server["resource"]:
                raise UpstreamFailure("MCP_CREDENTIAL_RESOURCE_MISMATCH")
            issuers = metadata.get("authorization_servers", [])
            if issuers != [self.server["issuer"]]:
                raise UpstreamFailure("MCP_ISSUER_MISMATCH")
            discovery = await self.rpc("server/discover", "discover", scopes=["mcp:discover"])
            if discovery["serverInfo"]["name"] != self.server["id"]:
                raise UpstreamFailure("MCP_SERVER_IDENTITY_CHANGED")
            validate_authorization_issuer(self.server["issuer"], discovery.get("authorizationServer"))
        result = await self.rpc("tools/list", "manifest", scopes=["mcp:discover"])
        tools = result["tools"]
        if not isinstance(tools, list) or len(tools) > 128:
            raise UpstreamFailure("Invalid manifest list")
        return tools

    async def execute(self, transaction):
        params = {"name": transaction.metadata.get("remote_tool_name", transaction.resource.name),
            "arguments": transaction.payload}
        if self.server and "execution_id" in transaction.metadata:
            params["_meta"] = {"aicl/execution_id": transaction.metadata["execution_id"]}
        result = await self.rpc("tools/call", transaction.request_id, params,
            transaction.metadata["response_limit"] + 4096,
            transaction.metadata.get("required_scopes", ()), transaction.metadata.get("input_schema"))
        if result.get("resultType") == "input_required":
            raise UpstreamFailure("MCP_REQUIRES_EXPLICIT_HANDLING")
        if "isError" in result and not isinstance(result["isError"], bool):
            raise UpstreamFailure("Invalid MCP tool error flag")
        # Business errors remain untrusted output: the pipeline applies the same schema,
        # size, provenance and injection checks before an agent can use them to recover.
        return UpstreamResult(output=result["structuredContent"], tool_error=result.get("isError", False))
