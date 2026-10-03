from dataclasses import dataclass

from app.core.transaction import Effect


@dataclass(frozen=True)
class Tool:
    name: str
    effect: Effect
    required_scopes: tuple[str, ...]
    schema: dict
    output_schema: dict


def obj(properties: dict, required: list[str]) -> dict:
    return {"type": "object", "properties": properties, "required": required, "additionalProperties": False}


TEXT = {"type": "string", "minLength": 1, "maxLength": 8192}
OUTPUT = obj({"result": {"type": "string", "maxLength": 65536}}, ["result"])


TOOLS = {
    tool.name: tool
    for tool in [
        Tool("github.search", Effect.READ, ("repo:read",), obj({"query": TEXT}, ["query"]), OUTPUT),
        Tool(
            "github.read_issue",
            Effect.READ,
            ("repo:read",),
            obj({"issue": {"type": "integer", "minimum": 1}}, ["issue"]),
            OUTPUT,
        ),
        Tool(
            "github.create_issue",
            Effect.EXTERNAL_SIDE_EFFECT,
            ("repo:write",),
            obj({"title": TEXT, "body": TEXT}, ["title", "body"]),
            OUTPUT,
        ),
        Tool(
            "github.delete_repository",
            Effect.DESTRUCTIVE,
            ("repo:admin",),
            obj({"repository": TEXT}, ["repository"]),
            OUTPUT,
        ),
        Tool("filesystem.read", Effect.READ, ("files:read",), obj({"path": TEXT}, ["path"]), OUTPUT),
        Tool(
            "filesystem.write",
            Effect.WRITE,
            ("files:write",),
            obj({"path": TEXT, "content": TEXT}, ["path", "content"]),
            OUTPUT,
        ),
        Tool(
            "email.send",
            Effect.EXTERNAL_SIDE_EFFECT,
            ("email:send",),
            obj({"to": TEXT, "body": TEXT}, ["to", "body"]),
            OUTPUT,
        ),
        Tool(
            "shell.exec", Effect.CODE_EXECUTION, ("shell:exec",), obj({"command": TEXT}, ["command"]), OUTPUT
        ),
        Tool("network.fetch", Effect.READ, ("network:read",), obj({"url": TEXT}, ["url"]), OUTPUT),
    ]
}
