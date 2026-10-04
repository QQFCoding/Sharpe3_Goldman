"""Adapter for pinned AgentDyn's original tasks, state and utility/security predicates."""
import hashlib
import inspect
import json
import subprocess
import sys

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from jsonschema import Draft202012Validator

from app.adapters.manifests import definition, digest
from app.adapters.mcp import MCPAdapter
from app.adapters.mcp_protocol import strict_json, validate
from app.adapters.tools import Tool, obj
from app.controls.base import encoded
from app.core.transaction import Effect, Finding
from app.settings import ROOT

COMMIT = "5353cf7615b135cace8d07c8f12dac53a16b6db3"
SOURCE = ROOT / ".tools/agentdyn"
READS = {"get_received_emails", "get_sent_emails", "list_directory", "read_file",
    "get_github_linked_unread_emails", "get_logged_in_github_user_information", "get_github_account_user_information",
    "get_github_repository_information", "git_get_linked_ssh_keys"}
DESTRUCTIVE = {"git_delete_repo", "delete_node", "git_delete_ssh_key"}
OUTPUT = obj({"result": {"type": "string", "maxLength": 65536}}, ["result"])


def load_suite():
    if not SOURCE.is_dir():
        raise RuntimeError("Run python scripts/setup_agentdyn.py (pinned source + optional dependencies).")
    head = subprocess.run(["git", "-C", str(SOURCE), "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
    if head != COMMIT:
        raise RuntimeError("AGENTDYN_SOURCE_PIN_MISMATCH")
    sys.path.insert(0, str(SOURCE / "src"))
    from agentdojo.task_suite import get_suite
    return get_suite("v1", "github")


def tools_for_suite(suite):
    result = {}
    for function in suite.tools:
        schema = function.parameters.model_json_schema()
        schema["additionalProperties"] = False
        name = "agentdyn::" + function.name
        effect = Effect.DESTRUCTIVE if function.name in DESTRUCTIVE else Effect.READ if function.name in READS else Effect.EXTERNAL_SIDE_EFFECT
        result[name] = Tool(name, effect, ("benchmark:read",) if effect == Effect.READ else ("benchmark:write",), schema,
            OUTPUT, server_id="agentdyn", remote_name=function.name, description=function.description,
            output_trust="untrusted", external_sink=function.name == "send_email")
    return result


def serialize(value, seen=None, path="$"):
    seen = {} if seen is None else seen
    structured = hasattr(type(value), "model_fields") or isinstance(value, (dict, list, tuple, set, frozenset))
    if structured:
        if id(value) in seen:
            return {"$ref": seen[id(value)]}
        seen[id(value)] = path
    if hasattr(type(value), "model_fields"):
        return {k: serialize(getattr(value, k), seen, path + "." + k) for k in type(value).model_fields}
    if callable(value):
        return {"callable": value.__module__ + "." + value.__qualname__}
    if hasattr(value, "isoformat"):
        return value.isoformat()
    if isinstance(value, (set, frozenset, tuple)):
        return [serialize(v, seen, path + "." + str(i)) for i, v in enumerate(value)]
    if isinstance(value, list):
        return [serialize(v, seen, path + "." + str(i)) for i, v in enumerate(value)]
    if isinstance(value, dict):
        return {k: serialize(v, seen, path + "." + str(k)) for k, v in value.items()}
    return value


class EnvironmentBridge:
    def __init__(self, suite, environment, tools, oracle):
        from agentdojo.functions_runtime import FunctionsRuntime
        self.environment, self.tools = environment, tools
        self.runtime = FunctionsRuntime(suite.tools)
        self.oracle = {(call.function, digest(call.args)) for call in oracle}
        self.authorized_pending = set()
        self.calls = []
        self.prohibited = []
        self.web_pins = {w.web_url: digest({"handlers": serialize(w.web_function), "fields": w.field_to_parameters})
            for w in environment.web_database.web_list}
        self.app = FastAPI(title="AgentDyn original inert environment MCP bridge")
        self.app.post("/mcp")(self.rpc)

    def callback(self, otp):
        account = next(a for a in self.environment.github_platform.account_list
            if a.email == self.environment.github_platform.current_account_email)
        pending = account.verification_stack.get(otp)
        if not pending:
            return None
        function, positional = pending
        name = function.__name__
        tool = self.tools.get("agentdyn::" + name)
        if not tool:
            return None
        bound = inspect.signature(function).bind(*positional).arguments
        arguments = {k: v for k, v in bound.items() if k in tool.schema["properties"] and v is not None}
        return name, digest(arguments)

    def approved(self, name, arguments):
        normalized = {k: v for k, v in arguments.items() if v is not None}
        if (name, digest(normalized)) in self.oracle:
            return True
        if name == "verify_github_account":
            pending = self.callback(arguments.get("otp"))
            return pending is not None and pending in self.oracle and pending in self.authorized_pending
        return False

    def preflight(self, name, args):
        # Original FunctionsRuntime accepts nested FunctionCall objects: never expose that shortcut.
        def nested(value):
            return isinstance(value, dict) and ("function" in value and "args" in value or any(nested(v) for v in value.values())) or isinstance(value, list) and any(nested(v) for v in value)
        if nested(args):
            return [Finding(code="AGENTDYN_NESTED_TOOL_CALL_DENIED", control="benchmark-adapter")]
        if name == "verify_github_account":
            pending = self.callback(args.get("otp"))
            if pending and (pending[0] in DESTRUCTIVE or pending not in self.authorized_pending):
                return [Finding(code="AGENTDYN_NESTED_EFFECT_DENIED", control="benchmark-adapter")]
        if name in {"browse_webpage", "input_to_webpage"}:
            url = args.get("url", "").removeprefix("https://").removeprefix("http://")
            page = next((w for w in self.environment.web_database.web_list if w.web_url == url), None)
            if page and page.web_function:
                current = digest({"handlers": serialize(page.web_function), "fields": page.field_to_parameters})
                if current != self.web_pins.get(url):
                    return [Finding(code="AGENTDYN_WEB_HANDLER_DRIFT", control="benchmark-adapter")]
                if any(f.handler in DESTRUCTIVE or f.handler not in self.runtime.functions for f in page.web_function):
                    return [Finding(code="AGENTDYN_NESTED_EFFECT_DENIED", control="benchmark-adapter")]
        return []

    async def rpc(self, request: Request):
        body = strict_json(await request.body())
        identity = body.get("id")
        try:
            validate(body, request.headers, legacy=True)
            if body["method"] == "tools/list":
                return {"jsonrpc": "2.0", "id": identity, "result": {"tools": [definition(t) for t in self.tools.values()]}}
            params = body["params"]
            name, args = params["name"], params["arguments"]
            tool = self.tools["agentdyn::" + name]
            if not Draft202012Validator(tool.schema).is_valid(args) or self.preflight(name, args):
                raise ValueError("AGENTDYN_ARGUMENT_INVALID")
            from agentdojo.functions_runtime import FunctionCall
            self.calls.append(FunctionCall(function=name, args=args))
            approved = self.approved(name, args)
            if tool.effect != Effect.READ and not approved:
                self.prohibited.append({"function": name, "argument_hash": digest(args)})
            if approved and name != "verify_github_account":
                self.authorized_pending.add((name, digest({k: v for k, v in args.items() if v is not None})))
            value, error = self.runtime.run_function(self.environment, name, args)
            # These unused credentials are returned by the benchmark's account-info read.
            # They are never needed for repository tasks; project them before model exposure.
            if isinstance(value, dict):
                value = {k: v for k, v in value.items() if k not in {"password", "verification_code"}}
            text = json.dumps(serialize(value), ensure_ascii=False) if not isinstance(value, str) else value
            return {"jsonrpc": "2.0", "id": identity, "result": {"structuredContent": {"result": text if not error else error}, "isError": bool(error)}}
        except (ValueError, KeyError):
            return JSONResponse({"jsonrpc": "2.0", "id": identity, "error": {"code": -32602, "message": "AGENTDYN_REQUEST_INVALID"}}, status_code=400)


class AgentDynAdapter(MCPAdapter):
    def __init__(self, client, bridge):
        super().__init__(client, "http://agentdyn", 30)
        self.bridge = bridge
    async def preflight(self, tx):
        return self.bridge.preflight(tx.metadata["remote_tool_name"], tx.payload)


def environment_digest(environment):
    return hashlib.sha256(encoded(serialize(environment))).hexdigest()
