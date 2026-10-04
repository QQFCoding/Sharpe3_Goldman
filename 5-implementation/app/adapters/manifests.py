import hashlib
import json
import unicodedata
from pathlib import Path

from app.adapters.tools import TOOLS
from app.core.transaction import Finding


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


def definition(tool):
    return {"name": tool.remote_name or tool.name, "description": tool.description or "Registered " + (tool.remote_name or tool.name),
        "inputSchema": tool.schema, "effect": tool.effect, "required_scopes": list(tool.required_scopes),
        "outputSchema": tool.output_schema, "version": "1.0.0"}


def manifest(tool, server_id=None):
    value = definition(tool)
    return {"server_id": server_id or tool.server_id, "tool_name": tool.remote_name or tool.name,
        "tool_description_hash": digest(value["description"]), "schema_hash": digest(tool.schema),
        "output_schema_hash": digest(tool.output_schema),
        "effect": tool.effect, "required_scopes": list(tool.required_scopes), "approved_version": "1.0.0"}


class ManifestRegistry:
    def __init__(self, path: Path, tools=None):
        self.pins = json.loads(path.read_text(encoding="utf-8"))
        self.tools = tools if tools is not None else TOOLS

    def analyze(self):
        """Names remain qualified even when a collision is intentional."""
        findings, seen = [], {}
        for alias, tool in self.tools.items():
            name = tool.remote_name or tool.name
            normalized = unicodedata.normalize("NFKC", name).casefold().translate(str.maketrans("аесорхуі", "aecopxyi"))
            if normalized in seen and seen[normalized].server_id != tool.server_id:
                other = seen[normalized]
                codes = ["MCP_TOOL_NAME_COLLISION" if (other.remote_name or other.name) == name else "MCP_CONFUSABLE_NAME"]
                if tool.effect != other.effect:
                    codes.append("MCP_EFFECT_ESCALATION")
                if set(tool.required_scopes) != set(other.required_scopes):
                    codes.append("MCP_SCOPE_ESCALATION")
                findings.extend({"code": code, "tool": alias, "other": other.name} for code in codes)
            seen[normalized] = tool
        return findings

    async def inspect(self, tx, adapter, policy):
        if adapter is None:
            return [Finding(code="MCP_SERVER_UNCONFIGURED", control="mcp-manifest")]
        if not policy.manifest_pinning or not hasattr(adapter, "list_tools"):
            return []
        name = tx.resource.name if tx.resource else ""
        expected = self.pins.get(name)
        if not expected or name not in self.tools:
            return [Finding(code="UNKNOWN_MCP_TOOL", control="mcp-manifest")]
        try:
            tools = await adapter.list_tools()
            matches = [t for t in tools if t.get("name") == (self.tools[name].remote_name or name)]
            if len(matches) != 1:
                raise ValueError("Missing or duplicate tool")
            observed = matches[0]
            current = {"server_id": tx.resource.mcp_server, "tool_name": observed["name"],
                "tool_description_hash": digest(observed.get("description", "")),
                "schema_hash": digest(observed["inputSchema"]), "output_schema_hash": digest(observed.get("outputSchema")), "effect": observed.get("effect"),
                "required_scopes": observed.get("required_scopes"), "approved_version": observed.get("version")}
            tx.metadata["manifest_hash"] = digest(current)
            if current == expected:
                return []
            if current["tool_description_hash"] != expected["tool_description_hash"]:
                tx.metadata["source_category"] = "MCP_tool_description_injection"
            # Effect/scope/schema drift can change what approved arguments mean: always fail closed.
            dangerous = any(current[k] != expected[k] for k in ("effect", "required_scopes", "schema_hash", "output_schema_hash", "server_id"))
            action = "BLOCK" if dangerous else policy.manifest_change
            codes = ["MCP_MANIFEST_CHANGED"]
            if current["schema_hash"] != expected["schema_hash"]:
                codes.append("MCP_SCHEMA_CHANGED")
            for key, code in [("effect", "MCP_EFFECT_ESCALATION"), ("required_scopes", "MCP_SCOPE_ESCALATION"), ("output_schema_hash", "MCP_OUTPUT_SCHEMA_CHANGED"), ("tool_description_hash", "MCP_DESCRIPTION_CHANGED")]:
                if current[key] != expected[key]:
                    codes.append(code)
            return [Finding(code=c, control="mcp-manifest", action=action) for c in codes]
        except Exception as error:
            if str(error) in {"MCP_SERVER_IDENTITY_CHANGED", "MCP_ISSUER_MISMATCH", "MCP_CREDENTIAL_RESOURCE_MISMATCH", "MCP_SCOPE_STEP_UP_REQUIRED"}:
                return [Finding(code=str(error), control="mcp-manifest")]
            return [Finding(code="MCP_MANIFEST_UNAVAILABLE", control="mcp-manifest")]
