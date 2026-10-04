"""Small async client for the gateway's supported buffered HTTP API.

The client never retries an operation or obtains approval automatically. Keep the
operator credential out of an agent process in deployed systems.
"""
from dataclasses import dataclass
from typing import Any
from uuid import uuid4

import httpx


class GatewayDenied(RuntimeError):
    def __init__(self, result: "GatewayResponse"):
        self.result = result
        super().__init__(f"Gateway decision {result.decision}: {result.security.get('reason_codes', [])}")


@dataclass(frozen=True)
class GatewayResponse:
    status_code: int
    data: dict[str, Any]

    @property
    def security(self) -> dict[str, Any]:
        return self.data.get("security", {})

    @property
    def decision(self) -> str:
        return self.security.get("decision", "TRANSPORT_ERROR")

    def require_output(self) -> dict[str, Any]:
        if self.status_code != 200 or self.decision not in {"ALLOW", "REDACT", "WARN"}:
            raise GatewayDenied(self)
        output = self.data.get("output")
        if not isinstance(output, dict):
            raise GatewayDenied(self)
        return output


def tool_request(name: str, arguments: dict, workflow_id: str, *, execution_id: str | None = None) -> dict:
    body = {"operation": "mcp_tool_call", "resource": {"name": name}, "payload": arguments,
            "workflow": {"workflow_id": workflow_id}}
    if execution_id is not None:
        body["execution_id"] = execution_id
    return body


class ControlClient:
    """Use separate instances for the application identity and operator identity."""

    def __init__(self, base_url: str, token: str, *, transport=None, timeout: float = 30):
        if not token:
            raise ValueError("A gateway identity token is required")
        self.http = httpx.AsyncClient(base_url=base_url.rstrip("/"), transport=transport,
            headers={"Authorization": f"Bearer {token}"}, timeout=timeout, trust_env=False,
            follow_redirects=False)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.http.aclose()

    async def transaction(self, request: dict) -> GatewayResponse:
        response = await self.http.post("/v1/transactions", json=request)
        return GatewayResponse(response.status_code, response.json())

    async def chat(self, text: str, *, workflow_id: str | None = None, model: str = "demo",
                   provider: str = "mock", max_tokens: int = 512) -> GatewayResponse:
        response = await self.http.post("/v1/chat/completions", json={"model": model,
            "provider": provider, "messages": [{"role": "user", "content": text}],
            "max_tokens": max_tokens, "workflow": {"workflow_id": workflow_id or str(uuid4())}})
        return GatewayResponse(response.status_code, response.json())

    async def register_workflow(self, workflow_id: str, goal: str, resources: list[str],
                                effects: list[str]) -> dict:
        response = await self.http.post("/v1/workflows", json={"workflow_id": workflow_id,
            "goal": goal, "allowed_resources": resources, "allowed_effects": effects})
        response.raise_for_status()
        return response.json()

    async def issue_approval(self, request: dict, *, subject: str, tenant_id: str,
                             agent_id: str | None = None) -> str:
        body = {"subject": subject, "tenant_id": tenant_id, "request": request}
        if agent_id is not None:
            body["agent_id"] = agent_id
        response = await self.http.post("/admin/approvals", json=body)
        response.raise_for_status()
        return response.json()["approval_token"]
