"""Inert local issue tracker and deterministic summarizer for the judge showcase.

No GitHub, disk, shell, email or external network side effects occur. Tool calls
still traverse the actual gateway, schema controls, authorization and adapters.
"""
import json
from dataclasses import dataclass, field

from fastapi import FastAPI

from app.adapters.manifests import definition
from app.adapters.tools import TOOLS

ISSUES = {
    101: {"id": 101, "title": "Checkout retry loses cart", "priority": "high",
          "description": "Retrying checkout after a temporary timeout clears the cart."},
    102: {"id": 102, "title": "Checkout progress has no accessible label", "priority": "medium",
          "description": "The progress indicator needs a screen-reader label."},
}


@dataclass
class ShowcaseState:
    calls: list[dict] = field(default_factory=list)
    created_issues: list[dict] = field(default_factory=list)
    llm_calls: int = 0


def create_services():
    state = ShowcaseState()
    mcp = FastAPI(title="Inert showcase issue tracker")
    llm = FastAPI(title="Deterministic showcase summarizer; not an autonomous model")

    @mcp.post("/mcp")
    async def rpc(body: dict):
        response = {"jsonrpc": "2.0", "id": body.get("id")}
        if body.get("method") == "tools/list":
            response["result"] = {"tools": [definition(t) for t in TOOLS.values()]}
            return response
        if body.get("method") != "tools/call":
            return {**response, "error": {"code": -32601, "message": "Method not supported"}}
        params = body["params"]
        name, args = params["name"], params["arguments"]
        state.calls.append({"name": name, "arguments": dict(args)})
        if name == "github.search":
            result = json.dumps({"issues": [{"id": i, "title": x["title"]} for i, x in ISSUES.items()]})
        elif name == "github.read_issue" and args["issue"] in ISSUES:
            result = json.dumps(ISSUES[args["issue"]])
        elif name == "github.create_issue":
            issue = {"id": 103 + len(state.created_issues), **args}
            state.created_issues.append(issue)
            result = json.dumps(issue)
        else:
            result = f"Simulated {name}: no external side effect."
        response["result"] = {"content": [{"type": "text", "text": result}],
            "structuredContent": {"result": result}, "isError": False}
        return response

    @llm.post("/v1/chat/completions")
    async def complete(body: dict):
        state.llm_calls += 1
        text = body["messages"][-1]["content"]
        if text.startswith("Summarize these public issue records as a triage plan:\n"):
            records = json.loads(text.split("\n", 1)[1])
            lines = [f"{r['priority'].upper()}: #{r['id']} {r['title']} — {r['description']}" for r in records]
            answer = "Checkout triage\n" + "\n".join(lines) + "\nFix the high-priority retry issue first."
        else:
            answer = "Local bounded response: " + text[:120]
        answer = answer[:body.get("max_tokens", 512)]
        return {"choices": [{"message": {"role": "assistant", "content": answer}}],
            "usage": {"prompt_tokens": len(text.encode()), "completion_tokens": len(answer.encode())}}

    @mcp.get("/health")
    @llm.get("/health")
    async def health():
        return {"status": "ok", "kind": "inert-showcase"}

    return llm, mcp, state


llm_app, mcp_app, state = create_services()
