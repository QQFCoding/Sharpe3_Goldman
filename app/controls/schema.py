from jsonschema import Draft202012Validator

from app.adapters.tools import TOOLS, obj
from app.core.transaction import Finding, Operation, SecurityTransaction

CHAT_SCHEMA = obj(
    {
        "messages": {
            "type": "array",
            "minItems": 1,
            "maxItems": 64,
            "items": obj(
                {
                    "role": {"enum": ["system", "user", "assistant", "tool"]},
                    "content": {"type": "string", "maxLength": 65536},
                },
                ["role", "content"],
            ),
        },
        "max_tokens": {"type": "integer", "minimum": 1, "maximum": 2048},
    },
    ["messages"],
)
MEMORY_WRITE_SCHEMA = obj(
    {
        "content": {"type": "string", "minLength": 1, "maxLength": 65536},
        "source": {"enum": ["application", "web", "external", "agent"]},
        "classification": {"enum": ["public", "internal", "restricted"]},
        "ttl_seconds": {"type": "integer", "minimum": 1},
    },
    ["content", "source"],
)
MEMORY_READ_SCHEMA = obj({"memory_id": {"type": "string", "minLength": 1, "maxLength": 128}}, ["memory_id"])
AGENT_SCHEMA = obj({"message": {"type": "string", "minLength": 1, "maxLength": 65536}}, ["message"])


def inspect(tx: SecurityTransaction) -> list[Finding]:
    schema = None
    if tx.operation == Operation.LLM_REQUEST:
        schema = CHAT_SCHEMA
    elif tx.operation in {Operation.TOOL_CALL, Operation.MCP_TOOL_CALL, Operation.API_CALL}:
        tool = TOOLS.get(tx.resource.name if tx.resource else "")
        schema = tool.schema if tool else None
    elif tx.operation == Operation.MEMORY_WRITE:
        schema = MEMORY_WRITE_SCHEMA
    elif tx.operation == Operation.MEMORY_READ:
        schema = MEMORY_READ_SCHEMA
    elif tx.operation == Operation.AGENT_MESSAGE:
        schema = AGENT_SCHEMA
    else:
        return [Finding(code="UNSUPPORTED_OPERATION", control="schema")]
    if schema and not Draft202012Validator(schema).is_valid(tx.payload):
        return [Finding(code="SCHEMA_INVALID", control="schema")]
    return []


def inspect_output(tx: SecurityTransaction, output) -> list[Finding]:
    if tx.operation in {Operation.TOOL_CALL, Operation.MCP_TOOL_CALL, Operation.API_CALL}:
        tool = TOOLS.get(tx.resource.name if tx.resource else "")
        if tool and not Draft202012Validator(tool.output_schema).is_valid(output):
            return [Finding(code="OUTPUT_SCHEMA_INVALID", control="output-schema")]
    elif tx.operation == Operation.LLM_REQUEST:
        if not Draft202012Validator(obj({"content": {"type": "string"}}, ["content"])).is_valid(output):
            return [Finding(code="OUTPUT_SCHEMA_INVALID", control="output-schema")]
    return []
