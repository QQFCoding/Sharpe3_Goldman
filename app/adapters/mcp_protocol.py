"""MCP 2026-07-28 stateless JSON subset; mirrored metadata cannot change routing."""
import base64
import json
import re

VERSION = "2026-07-28"
PROTOCOL = "io.modelcontextprotocol/protocolVersion"


def header_value(value):
    text = str(value).lower() if type(value) is bool else str(value)
    if (not text or text != text.strip() or re.search(r"[^\x20-\x7e]", text)
        or re.fullmatch(r"=\?base64\?.*\?=", text)):
        return "=?base64?" + base64.b64encode(text.encode()).decode() + "?="
    return text


def decode_header(value):
    if value is None:
        raise ValueError("MCP_HEADER_MISMATCH")
    if value.startswith("=?base64?") and value.endswith("?="):
        return base64.b64decode(value[9:-2], validate=True).decode("utf-8")
    if not value or re.search(r"[^\x20-\x7e]", value):
        raise ValueError("MCP_HEADER_MISMATCH")
    return value


def headers(body, schema=None):
    result = {"MCP-Protocol-Version": VERSION, "Mcp-Method": body["method"],
        "Accept": "application/json"}
    params = body.get("params", {})
    name = params.get("name", params.get("uri"))
    if name is not None:
        result["Mcp-Name"] = header_value(name)
    seen = set()
    def walk(spec, value):
        for key, prop in spec.get("properties", {}).items():
            name = prop.get("x-mcp-header")
            if name:
                if (not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name) or name.lower() in seen
                    or prop.get("type") not in {"integer", "string", "boolean"}):
                    raise ValueError("MCP_HEADER_SCHEMA_INVALID")
                seen.add(name.lower())
                if key in value:
                    if prop.get("type") == "integer" and abs(value[key]) > 2**53 - 1:
                        raise ValueError("MCP_HEADER_VALUE_INVALID")
                    result["Mcp-Param-" + name] = header_value(value[key])
            if prop.get("type") == "object":
                walk(prop, value.get(key, {}))
    if schema:
        walk(schema, params.get("arguments", {}))
    return result


def validate(body, actual, schema=None, legacy=False):
    version = actual.get("mcp-protocol-version")
    if version is None and legacy:
        if (actual.get("mcp-method") or actual.get("mcp-name") or actual.get("mcp-session-id")
            or any(key.startswith("mcp-param-") for key in actual)
            or body.get("params", {}).get("_meta", {}).get(PROTOCOL)):
            raise ValueError("MCP_HEADER_MISMATCH")
        return
    if version != VERSION or body.get("params", {}).get("_meta", {}).get(PROTOCOL) != version:
        raise ValueError("MCP_HEADER_MISMATCH")
    expected = headers(body, schema)
    if actual.get("mcp-name") and "Mcp-Name" not in expected:
        raise ValueError("MCP_HEADER_MISMATCH")
    for key, value in expected.items():
        if key == "Accept":
            continue
        observed = actual.get(key.lower())
        if key.startswith("Mcp-Param-") or key == "Mcp-Name":
            if decode_header(observed) != decode_header(value):
                raise ValueError("MCP_HEADER_MISMATCH")
        elif observed != value:
            raise ValueError("MCP_HEADER_MISMATCH")
    if any(key.startswith("mcp-param-") and key not in {k.lower() for k in expected} for key in actual):
        raise ValueError("MCP_HEADER_MISMATCH")
    if actual.get("mcp-session-id"):
        raise ValueError("MCP_SESSION_NOT_SUPPORTED")


def request(method, identity, params=None):
    return {"jsonrpc": "2.0", "id": identity, "method": method, "params": {**(params or {}), "_meta": {
        **(params or {}).get("_meta", {}),
        PROTOCOL: VERSION, "io.modelcontextprotocol/clientInfo": {"name": "ai-control-layer", "version": "0.3"},
        "io.modelcontextprotocol/clientCapabilities": {}}}}


def strict_json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("Duplicate JSON key")
            result[key] = value
        return result
    def invalid(value):
        raise ValueError("Non-finite JSON")
    return json.loads(data, object_pairs_hook=pairs, parse_constant=invalid)
