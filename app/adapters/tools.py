from dataclasses import dataclass, field, replace

from app.core.transaction import Effect


@dataclass(frozen=True)
class Tool:
    name: str
    effect: Effect
    required_scopes: tuple[str, ...]
    schema: dict
    output_schema: dict
    server_id: str = "mock"
    remote_name: str | None = None
    description: str | None = None
    input_fields: tuple[str, ...] | None = None
    output_fields: tuple[str, ...] | None = None
    argument_rules: dict = field(default_factory=dict)
    output_trust: str | None = None
    output_classification: str = "public"
    external_sink: bool = False


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


def registered_tools():
    tools = dict(TOOLS)
    for server, names, trust in [
        ("trusted-internal", ["github.search", "github.create_issue", "filesystem.read"], "trusted"),
        ("untrusted-external", ["github.search", "network.fetch"], "untrusted"),
    ]:
        for name in names:
            alias = server + "::" + name
            tools[alias] = replace(TOOLS[name], name=alias, server_id=server, remote_name=name,
                output_trust=trust, external_sink=server == "untrusted-external")
    return tools
