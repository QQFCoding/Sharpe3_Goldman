import asyncio
import json
from contextlib import AsyncExitStack

import httpx
from psycopg_pool import AsyncConnectionPool
from redis.asyncio import Redis

from app.adapters.manifests import ManifestRegistry
from app.adapters.mcp import MCPAdapter
from app.adapters.mcp_credentials import ServerCredentials
from app.adapters.network import NetworkAdapter
from app.adapters.ollama import OllamaAdapter
from app.adapters.openai_compatible import OpenAICompatibleAdapter
from app.adapters.tools import registered_tools
from app.audit.repository import AuditEvent, AuditRepository
from app.budget.manager import InMemoryBudgetManager, RedisBudgetManager
from app.core.auth import ApprovalStore, Authenticator
from app.core.decision import Decision, DecisionResult, GatewayResult
from app.core.delegation import DelegationStore
from app.core.executions import ExecutionStore
from app.core.jwt_auth import JwtVerifier
from app.core.pipeline import Pipeline
from app.core.transaction import Operation, Principal, SecurityTransaction
from app.core.values import ValueStore
from app.core.workflows import WorkflowStore
from app.memory.service import MemoryService
from app.policy.engine import OpaEngine
from app.policy.loader import PolicyStore
from app.semantic.base import UnavailableProvider
from app.semantic.deberta import DebertaProvider
from app.semantic.ollama_classifier import OllamaSecurityProvider
from app.semantic.prompt_guard import PromptGuardProvider
from app.semantic.task_alignment import TaskAlignmentGuard
from app.settings import ROOT
from app.telemetry.metrics import Metrics
from app.telemetry.tracing import create_tracer


class Runtime:
    def __init__(self, settings):
        self.settings = settings
        self.policies = PolicyStore(settings.policy_path)
        self.auth = Authenticator(settings.demo_mode, settings.auth_file)
        jwks_path = settings.jwt_jwks_path
        if jwks_path is None and settings.demo_mode and (ROOT / "config/demo-jwks.json").is_file():
            jwks_path = ROOT / "config/demo-jwks.json"
        if jwks_path:
            self.auth.jwt = JwtVerifier(jwks_path, settings.jwt_issuer,
                settings.jwt_audience, self.auth.records)
        self.stack = AsyncExitStack()
        self.metrics = Metrics()
        self.trace_provider, self.tracer = create_tracer(settings.otlp_endpoint)
        self.redis = self.pool = None

    async def open(self):
        await self.stack.__aenter__()
        self.client = await self.stack.enter_async_context(
            httpx.AsyncClient(
                follow_redirects=False,
                trust_env=False,
                timeout=self.settings.upstream_timeout,
                limits=httpx.Limits(max_connections=32, max_keepalive_connections=16),
            )
        )
        if self.settings.redis_url:
            self.redis = Redis.from_url(
                self.settings.redis_url, decode_responses=True, socket_timeout=3, socket_connect_timeout=3
            )
            self.stack.push_async_callback(self.redis.aclose)
            await self.redis.ping()
        if self.settings.database_url:
            self.pool = AsyncConnectionPool(self.settings.database_url, open=False, max_size=8, timeout=3)
            await self.stack.enter_async_context(self.pool)
            await self.pool.wait(timeout=10)
        self.audit = AuditRepository(self.pool)
        self.memory = MemoryService(self.pool)
        await self.audit.initialize()
        await self.memory.initialize()
        self.approvals = ApprovalStore(self.redis)
        self.workflows = WorkflowStore(self.redis)
        self.values = ValueStore(self.workflows)
        self.delegations = DelegationStore(self.workflows)
        self.executions = ExecutionStore(self.redis)
        self.budgets = RedisBudgetManager(self.redis) if self.redis else InMemoryBudgetManager()
        self.engine = OpaEngine(self.client, self.settings.opa_url, self.settings.opa_binary)
        semantic = UnavailableProvider()
        if self.settings.semantic_provider == "prompt_guard":
            semantic = PromptGuardProvider(self.settings.prompt_guard_path)
        elif self.settings.semantic_provider == "deberta":
            semantic = DebertaProvider(self.settings.deberta_path)
        elif self.settings.semantic_provider == "ollama":
            semantic = OllamaSecurityProvider(
                self.client, self.settings.ollama_url, self.settings.ollama_model
            )
        self.pipeline = Pipeline(
            self.policies,
            self.engine,
            self.budgets,
            self.approvals,
            semantic,
            self.memory,
            self.audit,
            self.metrics,
            self.tracer,
            {
                "mock": OpenAICompatibleAdapter(
                    self.client, self.settings.llm_url, self.settings.upstream_timeout
                ),
                "ollama": OllamaAdapter(
                    self.client, self.settings.ollama_url, self.settings.upstream_timeout
                ),
                "mcp": MCPAdapter(self.client, self.settings.mcp_url, self.settings.upstream_timeout),
            },
            self.settings.semantic_timeout,
            self.settings.upstream_timeout,
        )
        if not self.settings.demo_mode:
            self.pipeline.adapters["network"] = NetworkAdapter()
        self.pipeline.mcp_output_trust = self.settings.mcp_output_trust or (
            "trusted" if self.settings.demo_mode else "untrusted"
        )
        self.pipeline.workflows = self.workflows
        self.pipeline.executions = self.executions
        self.pipeline.require_execution_id = not self.settings.demo_mode
        self.pipeline.values = self.values
        self.pipeline.tools = registered_tools()
        self.pipeline.public_actions = json.loads((ROOT / "config/public-actions.json").read_text(encoding="utf-8"))
        self.pipeline.manifests = ManifestRegistry(ROOT / "config/tool-manifests.json", self.pipeline.tools)
        if self.settings.mcp_servers_path:
            servers = json.loads(self.settings.mcp_servers_path.read_text(encoding="utf-8"))
            credentials = ServerCredentials(ROOT / "config/demo-jwks.json", self.settings.mcp_credentials_path)
            for server in servers:
                self.pipeline.adapters["mcp:" + server["id"]] = MCPAdapter(
                    self.client, server["url"], self.settings.upstream_timeout, server, credentials)
        self.pipeline.alignment = TaskAlignmentGuard(
            self.client if self.settings.alignment_provider == "ollama" else None,
            self.settings.ollama_url, self.settings.ollama_model)
        self.metrics.revisions(self.policies.active)
        return self

    async def close(self):
        await self.stack.aclose()
        await asyncio.to_thread(self.trace_provider.shutdown)

    async def reject(self, code, control="http", principal=None):
        """Transport failures cannot reach upstreams; still produce a structured audit event."""
        principal = principal or Principal(
            subject="anonymous", tenant_id="unknown", authenticated=False, authentication_method="none"
        )
        tx = SecurityTransaction(principal=principal, operation=Operation.API_CALL, payload={})
        snapshot = self.policies.active
        decision = DecisionResult(
            decision=Decision.BLOCK,
            reason_codes=[code],
            controls=[control],
            policy_revision=snapshot.policy.metadata.revision,
            threat_feed_revision=snapshot.feed.revision,
            request_id=tx.request_id,
        )
        with self.tracer.start_as_current_span(
            "security.transport_rejection", record_exception=False, set_status_on_exception=False
        ) as span:
            trace_id = f"{span.get_span_context().trace_id:032x}"
            await self.audit.append(AuditEvent.from_transaction(tx, decision, "", trace_id, {}))
        self.metrics.record(tx, decision, [], 0)
        return GatewayResult(security=decision)
