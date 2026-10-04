"""Deterministic dependency faults exercise real gateway, Rego, parsers and storage adapters."""
import asyncio
import json
import shutil
import socket
import tempfile
from contextlib import asynccontextmanager
from unittest.mock import patch

import httpx
from psycopg import OperationalError

from app.adapters.base import UpstreamResult
from app.adapters.manifests import definition
from app.adapters.mcp import MCPAdapter
from app.adapters.tools import TOOLS
from app.audit.repository import AuditRepository
from app.budget.manager import RedisBudgetManager
from app.core.auth import approval_digest
from app.core.transaction import OperationRequest
from app.main import create_app
from app.policy.engine import OpaEngine
from app.semantic.base import SemanticRisk, UnavailableProvider
from app.semantic.task_alignment import TaskAlignmentGuard
from app.settings import ROOT, Settings

FAILURES = ["opa_unavailable", "opa_timeout", "opa_before_dispatch", "redis_unavailable", "redis_timeout", "audit_postgres_unavailable",
    "semantic_unavailable", "ollama_unavailable", "mcp_timeout", "mcp_malformed_json", "mcp_disconnect_after_execution",
    "dns_changes", "threat_feed_reload_failed", "policy_reload_failed"]


class FixtureSemantic:
    async def analyze(self, tx):
        return SemanticRisk(prompt_injection=0)


class FixtureTool:
    def __init__(self):
        self.calls = 0
    async def execute(self, tx):
        self.calls += 1
        return UpstreamResult(output={"result": "Safe fixture receipt"})


@asynccontextmanager
async def testbed():
    from pathlib import Path
    with tempfile.TemporaryDirectory(prefix="chaos-", dir=ROOT / ".tools") as tmp:
        directory = Path(tmp)
        for name in ["policy.yaml", "threat-feed.yaml"]:
            shutil.copyfile(ROOT / "config" / name, directory / name)
        settings = Settings(_env_file=None, policy_path=directory / "policy.yaml",
            opa_binary=ROOT / ".tools" / ("opa.exe" if __import__("os").name == "nt" else "opa"))
        app = create_app(settings)
        async with app.router.lifespan_context(app):
            runtime = app.state.runtime
            runtime.pipeline.semantic = FixtureSemantic()
            fixture = FixtureTool()
            runtime.pipeline.adapters["mcp"] = fixture
            yield app, runtime, fixture, directory


async def fault_case(failure):
    async with testbed() as (app, runtime, fixture, directory):
        principal = runtime.auth.authenticate("demo-user-token")
        body = OperationRequest.model_validate({"operation": "mcp_tool_call", "resource": {"name": "filesystem.write"},
            "payload": {"path": "receipt.txt", "content": "Safe fixture"}, "execution_id": failure,
            "workflow": {"workflow_id": failure}})
        tx = runtime.pipeline.prepare(body, principal)
        body.approval_token = await runtime.approvals.issue(approval_digest(tx, runtime.policies.active.policy.metadata.revision))
        phase, possible = "before_tool", False
        @asynccontextmanager
        async def failed_connection():
            raise OperationalError("synthetic PostgreSQL failure")
            yield
        class FailedPool:
            connection = staticmethod(failed_connection)
        class FailedRedis:
            async def eval(self, *args, **kwargs):
                raise TimeoutError() if failure == "redis_timeout" else ConnectionError()
        def failed_transport(request):
            raise httpx.ReadTimeout("fixture timeout") if "timeout" in failure else httpx.ConnectError("fixture unavailable")
        async with httpx.AsyncClient(transport=httpx.MockTransport(failed_transport)) as failing_client:
            if failure.startswith("opa_"):
                failed_engine = OpaEngine(failing_client, "http://failed")
                if failure == "opa_before_dispatch":
                    original_engine = runtime.pipeline.engine
                    class LateFailure:
                        calls = 0
                        async def evaluate(self, *args, **kwargs):
                            self.calls += 1
                            return await (failed_engine if self.calls >= 3 else original_engine).evaluate(*args, **kwargs)
                    runtime.pipeline.engine = LateFailure()
                else:
                    runtime.pipeline.engine = failed_engine
            elif failure.startswith("redis_"):
                runtime.pipeline.budgets = RedisBudgetManager(FailedRedis())
            elif failure == "audit_postgres_unavailable":
                runtime.pipeline.audit = AuditRepository(FailedPool())
            elif failure == "semantic_unavailable":
                runtime.pipeline.semantic = UnavailableProvider()
            elif failure == "ollama_unavailable":
                runtime.pipeline.alignment = TaskAlignmentGuard(failing_client, "http://failed", "qwen3:4b")
                await runtime.workflows.register(principal, failure, "Write a public receipt", ["write"], ["filesystem.write"])
                # To expose reviewer failure rather than a previously granted approval, remove the token.
                body.approval_token = None
            elif failure.startswith("mcp_"):
                phase, possible = "during_tool", True
                def mcp_transport(request):
                    fixture.calls += 1
                    if failure == "mcp_malformed_json":
                        return httpx.Response(200, content=b'{"result":', headers={"content-type": "application/json"})
                    raise httpx.ReadTimeout() if failure == "mcp_timeout" else httpx.ReadError("lost after fixture effect")
                async with httpx.AsyncClient(transport=httpx.MockTransport(mcp_transport)) as mcp_client:
                    class PinnedFixture(MCPAdapter):
                        async def list_tools(self):
                            return [definition(TOOLS["filesystem.write"])]
                    runtime.pipeline.adapters["mcp"] = PinnedFixture(mcp_client, "http://mcp", .05)
                    tx = runtime.pipeline.prepare(body, principal)
                    await runtime.pipeline.manifests.inspect(tx, runtime.pipeline.adapters["mcp"], runtime.policies.active.policy.mcp)
                    body.approval_token = await runtime.approvals.issue(approval_digest(tx, runtime.policies.active.policy.metadata.revision))
                    result = await runtime.pipeline.execute(body, principal)
                return check_report(failure, result, fixture.calls, phase, possible)
            elif failure == "dns_changes":
                body = OperationRequest.model_validate({"operation": "mcp_tool_call", "resource": {"name": "network.fetch"},
                    "payload": {"url": "https://changing.example.org/status"}, "workflow": {"workflow_id": failure}})
                # Policy inspection observes a rebinding to private IP; connection pinning has separate tests.
                with patch.object(socket, "getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))]):
                    result = await runtime.pipeline.execute(body, principal)
                return check_report(failure, result, fixture.calls, phase, possible)
            elif failure.endswith("reload_failed"):
                revision = runtime.policies.active.policy.metadata.revision
                path = directory / ("policy.yaml" if failure.startswith("policy") else "threat-feed.yaml")
                path.write_text("invalid: [unterminated")
                try:
                    await runtime.policies.reload()
                    raise AssertionError("Invalid reload accepted")
                except (ValueError, __import__("yaml").YAMLError):
                    pass
                assert runtime.policies.active.policy.metadata.revision == revision
                # Last-known-good destructive deny must still be active.
                body = OperationRequest.model_validate({"operation": "mcp_tool_call", "resource": {"name": "github.delete_repository"},
                    "payload": {"repository": "fixture"}, "workflow": {"workflow_id": failure}})
            result = await runtime.pipeline.execute(body, principal)
        return check_report(failure, result, fixture.calls, phase, possible)


def check_report(failure, result, calls, phase, possible):
    expected = "REQUIRE_APPROVAL" if failure == "ollama_unavailable" else "BLOCK"
    assert result.security.decision.value == expected, result.model_dump()
    assert calls == (1 if possible else 0)
    codes = result.security.reason_codes
    expected_code = ("POLICY_ENGINE_UNAVAILABLE" if failure.startswith("opa_") else
        "BUDGET_UNAVAILABLE" if failure.startswith("redis_") else
        "SEMANTIC_UNAVAILABLE" if failure == "semantic_unavailable" else
        "TASK_ALIGNMENT_UNCERTAIN" if failure == "ollama_unavailable" else
        "UNSAFE_URL" if failure == "dns_changes" else "DESTRUCTIVE_ACTION" if failure.endswith("reload_failed") else
        "UPSTREAM_OR_STORAGE_UNAVAILABLE")
    assert expected_code in codes, codes
    if possible:
        assert result.execution["state"] == "UNCERTAIN"
    return {"failure": failure, "affected_operation": "network.fetch" if failure == "dns_changes" else
        "github.delete_repository" if failure.endswith("reload_failed") else "filesystem.write", "fault_phase": phase,
        "decision": result.security.decision.value, "reason_codes": codes, "expected_behavior": "fail_closed",
        "tool_dispatches": calls, "side_effects_may_have_occurred": possible, "execution": result.execution,
        "injection": "deterministic test transport/store fault; inert environment"}


async def run_matrix():
    rows = []
    for failure in FAILURES:
        rows.append(await fault_case(failure))
        print(f"{failure}: {rows[-1]['decision']}, dispatched={rows[-1]['tool_dispatches']}", flush=True)
    return rows


def main():
    rows = asyncio.run(run_matrix())
    (ROOT / "artifacts").mkdir(exist_ok=True)
    (ROOT / "artifacts/chaos-security.json").write_text(json.dumps({"cases": rows, "passed": len(rows)}, indent=2) + "\n")
