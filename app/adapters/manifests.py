import hashlib
import json
from pathlib import Path

from app.adapters.tools import TOOLS
from app.core.transaction import Finding


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


def definition(tool):
    return {"name": tool.name, "description": "Registered " + tool.name,
        "inputSchema": tool.schema, "effect": tool.effect, "required_scopes": list(tool.required_scopes),
        "version": "1.0.0"}


def manifest(tool, server_id="mock"):
    value = definition(tool)
    return {"server_id": server_id, "tool_name": tool.name,
        "tool_description_hash": digest(value["description"]), "schema_hash": digest(tool.schema),
        "effect": tool.effect, "required_scopes": list(tool.required_scopes), "approved_version": "1.0.0"}


class ManifestRegistry:
    def __init__(self, path: Path):
        self.pins = json.loads(path.read_text(encoding="utf-8"))

    async def inspect(self, tx, adapter, policy):
        if not policy.manifest_pinning or not hasattr(adapter, "list_tools"):
            return []
        name = tx.resource.name if tx.resource else ""
        expected = self.pins.get(name)
        if not expected or name not in TOOLS:
            return [Finding(code="UNKNOWN_MCP_TOOL", control="mcp-manifest")]
        try:
            tools = await adapter.list_tools()
            matches = [t for t in tools if t.get("name") == name]
            if len(matches) != 1:
                raise ValueError("Missing or duplicate tool")
            observed = matches[0]
            current = {"server_id": tx.resource.mcp_server, "tool_name": name,
                "tool_description_hash": digest(observed.get("description", "")),
                "schema_hash": digest(observed["inputSchema"]), "effect": observed.get("effect"),
                "required_scopes": observed.get("required_scopes"), "approved_version": observed.get("version")}
            tx.metadata["manifest_hash"] = digest(current)
            if current == expected:
                return []
            if current["tool_description_hash"] != expected["tool_description_hash"]:
                tx.metadata["source_category"] = "MCP_tool_description_injection"
            # Effect/scope/schema drift can change what approved arguments mean: always fail closed.
            dangerous = any(current[k] != expected[k] for k in ("effect", "required_scopes", "schema_hash", "server_id"))
            action = "BLOCK" if dangerous else policy.manifest_change
            codes = ["MCP_MANIFEST_CHANGED"]
            if current["schema_hash"] != expected["schema_hash"]:
                codes.append("MCP_SCHEMA_CHANGED")
            return [Finding(code=c, control="mcp-manifest", action=action) for c in codes]
        except Exception:
            return [Finding(code="MCP_MANIFEST_UNAVAILABLE", control="mcp-manifest")]
