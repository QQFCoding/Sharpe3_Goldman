import asyncio
import hashlib
import time

from app.adapters.base import UpstreamResult
from app.adapters.tools import TOOLS
from app.audit.repository import AuditEvent
from app.budget.manager import Reservation
from app.budget.pricing import actual_credits, estimate
from app.controls import encoded_content, pii, prompt_patterns, schema, secrets, tool_arguments
from app.controls.base import canonicalize, encoded, transform
from app.controls.information_flow import facts as flow_facts
from app.controls.ssrf import NetworkGuard
from app.controls.tool_firewall import input_minimize, output_sanitize
from app.core.auth import approval_digest
from app.core.decision import PERMITTED, Decision, GatewayResult
from app.core.executions import ExecutionStore, ReplayRejected
from app.core.labels import DataSecurityLabel, source_label
from app.core.transaction import (
    Effect,
    Finding,
    Operation,
    Resource,
    SecurityContext,
    SecurityTransaction,
)
from app.detection.report import detection_report
from app.detection.trace import emit
from app.semantic.base import SemanticRisk
from app.semantic.task_alignment import AlignmentRisk


class Pipeline:
    def __init__(
        self,
        policies,
        engine,
        budgets,
        approvals,
        semantic,
        memory,
        audit,
        metrics,
        tracer,
        adapters,
        semantic_timeout=5,
        upstream_timeout=15,
    ):
        self.policies, self.engine, self.budgets = policies, engine, budgets
        self.approvals, self.semantic, self.memory = approvals, semantic, memory
        self.audit, self.metrics, self.tracer = audit, metrics, tracer
        self.adapters = adapters
        self.mcp_output_trust = "untrusted"
        self.semantic_timeout, self.upstream_timeout = semantic_timeout, upstream_timeout
        self.workflows = self.manifests = self.alignment = None
        self.executions = ExecutionStore()
        self.tools = dict(TOOLS)
        self.values = None
        self.public_actions = {}
        self.trusted_system_hashes = set()
        self.require_execution_id = False

    async def timed(self, tx, stage, awaitable):
        started = time.perf_counter()
        with self.tracer.start_as_current_span(stage, record_exception=False, set_status_on_exception=False):
            try:
                return await awaitable
            finally:
                seconds = time.perf_counter() - started
                timings = tx.metadata.setdefault("stage_latencies", {})
                timings[stage] = timings.get(stage, 0) + seconds
                self.metrics.stages.labels(stage).observe(seconds)

    def prepare(self, request, principal):
        resource = request.resource.model_copy(deep=True) if request.resource else None
        effect = Effect.READ
        if request.operation == Operation.LLM_REQUEST and resource is None:
            resource = Resource(name="demo", provider="mock", model="demo")
        if request.operation in {Operation.TOOL_CALL, Operation.MCP_TOOL_CALL, Operation.API_CALL}:
            tool = self.tools.get(resource.name if resource else "")
            effect = tool.effect if tool else Effect.READ
            if resource:
                resource.mcp_server = tool.server_id if tool else "mock"
        if request.operation in {Operation.MEMORY_READ, Operation.MEMORY_WRITE}:
            effect = Effect.WRITE if request.operation == Operation.MEMORY_WRITE else Effect.READ
            resource = resource or Resource(
                name="memory", tenant_id=principal.tenant_id, owner=principal.subject
            )
        context = SecurityContext(workflow=request.workflow.model_copy(deep=True))
        if request.operation == Operation.MEMORY_WRITE:
            context.source = request.payload.get("source", "external")
            context.source_trust = (
                "trusted"
                if context.source == "application" and "memory:trusted_write" in principal.scopes
                else "untrusted"
            )
        if request.operation == Operation.LLM_REQUEST and any(
            message.get("role") == "tool"
            for message in request.payload.get("messages", [])
            if isinstance(message, dict)
        ):
            context.source, context.source_trust = "retrieved", "untrusted"
        transaction = SecurityTransaction(
            principal=principal,
            operation=request.operation,
            resource=resource,
            effect=effect,
            context=context,
            payload=request.payload.copy(),
        )
        transaction.metadata["requested_execution_id"] = request.execution_id
        if request.operation == Operation.LLM_REQUEST:
            transaction.metadata["semantic_trusted_paths"] = [
                ["messages", i, "content"] for i, message in enumerate(request.payload.get("messages", []))
                if isinstance(message, dict) and message.get("role") == "system" and isinstance(message.get("content"), str)
                and hashlib.sha256(message["content"].encode()).hexdigest() in self.trusted_system_hashes]
        if request.operation in {Operation.TOOL_CALL, Operation.MCP_TOOL_CALL, Operation.API_CALL} and tool:
            transaction.metadata.update(input_schema=tool.schema, output_schema=tool.output_schema,
                registered_tool_name=tool.name, external_sink=tool.external_sink,
                remote_tool_name=tool.remote_name or tool.name, required_scopes=list(tool.required_scopes))
        return transaction

    async def controls(self, tx, snapshot, output=False):
        privacy_started=time.perf_counter()
        policy = snapshot.policy
        findings = snapshot.feed.match(tx)
        if (
            tx.operation == Operation.MEMORY_WRITE and not output and not policy.memory.scan_before_write
        ) or (tx.operation == Operation.MEMORY_READ and output and not policy.memory.scan_after_read):
            return findings
        if policy.controls.secrets.enabled:
            action = policy.controls.secrets.output_action if output else policy.controls.secrets.input_action
            findings += secrets.inspect(tx, action)
        if policy.controls.pii.enabled:
            action = policy.controls.pii.output_action if output else policy.controls.pii.input_action
            findings += pii.inspect(tx, action)
        findings += encoded_content.inspect(tx, policy.controls.secrets.enabled, policy.controls.pii.enabled)
        emit("privacy",{"finding_codes":[f.code for f in findings],
            "sensitive_content_present":any(f.control in {"secret-scanner","pii-scanner","decoded-secrets","decoded-privacy","reconstructed-secrets","reconstructed-privacy"} for f in findings)},
            (time.perf_counter()-privacy_started)*1000)
        if not output:
            findings += tool_arguments.inspect(tx)
        if (
            policy.controls.prompt_injection.enabled
            and policy.controls.prompt_injection.deterministic_enabled
        ):
            findings += prompt_patterns.inspect(tx)
        findings += await NetworkGuard(policy.network).inspect(tx)

        # JSON keys are not redacted because changing them could bypass a strict protocol schema.
        # Sensitive keys are rejected, including on arbitrary upstream objects.
        def key_findings(value):
            if isinstance(value, dict):
                for key, item in value.items():
                    key_tx = tx.model_copy(update={"payload": str(key)})
                    if secrets.inspect(key_tx, "BLOCK") or pii.inspect(key_tx, "BLOCK"):
                        findings.append(Finding(code="SENSITIVE_JSON_KEY", control="schema"))
                    key_findings(item)
            elif isinstance(value, list):
                for item in value:
                    key_findings(item)

        key_findings(tx.payload)
        return findings

    def facts(self, tx, findings, high_risk=False, memory_quarantined=False):
        tool = self.tools.get(tx.resource.name if tx.resource else "")
        return {
            "findings": [f.model_dump() for f in findings],
            "high_risk": high_risk,
            "tool": {
                "known": tool is not None,
                "required_scopes": list(tool.required_scopes) if tool else [],
            },
            "memory_quarantined": memory_quarantined,
            "data_flow": tx.metadata.get("data_flow", {"enabled": False}),
            "trusted_intent": tx.metadata.get("trusted_intent"),
            "semantic_provider": getattr(self.semantic, "provider_id", "none"),
        }

    async def decide(self, tx, snapshot, facts):
        started = time.perf_counter()
        with self.tracer.start_as_current_span(
            "policy.evaluate", record_exception=False, set_status_on_exception=False
        ):
            decision = await self.engine.evaluate(tx, snapshot, facts)
        self.metrics.policy_evaluations.inc()
        self.metrics.policy_latency.observe(time.perf_counter() - started)
        self.metrics.stages.labels("opa").observe(time.perf_counter() - started)
        if "POLICY_ENGINE_UNAVAILABLE" in decision.reason_codes:
            self.metrics.opa_failures.inc()
        return decision

    async def semantic_scan(self, tx, snapshot, findings, high_risk):
        config = snapshot.policy.controls.prompt_injection
        thresholds = config.semantic.provider_thresholds.get(getattr(self.semantic, "provider_id", "none"), config.semantic)
        tx.metadata["ai_detection"] = {"detector": getattr(self.semantic, "provider_id", "none"), "type": "ai",
            "status": "not_required", "verdict": "not_run", "score": None, "latency_ms": 0,
            "block_threshold": thresholds.block_threshold, "review_threshold": thresholds.review_threshold,
            "preprocessing_version": getattr(self.semantic, "preprocessing_version", "provider_defined")}
        if (tx.operation == Operation.MEMORY_WRITE and not snapshot.policy.memory.scan_before_write) or (
            tx.operation == Operation.MEMORY_READ
            and tx.context.phase == "output"
            and not snapshot.policy.memory.scan_after_read
        ):
            return
        necessary = (high_risk or bool(tx.risk.prompt_injection) or config.semantic.always_scan
            or (tx.operation == Operation.LLM_REQUEST and getattr(self.semantic, "provider_id", "none") != "none"))
        tx.context.semantic_required = necessary
        if not config.enabled or not config.semantic.enabled or not necessary:
            return
        # Deterministic blocking facts are sufficient. Never send detected credentials to a classifier.
        if any(f.action in {"BLOCK", "QUARANTINE"} for f in findings):
            tx.metadata["ai_detection"]["status"] = "skipped_deterministic_denial"
            return
        started = time.perf_counter()
        with self.tracer.start_as_current_span(
            "semantic.analyze", record_exception=False, set_status_on_exception=False
        ):
            try:
                sanitized, _ = transform(tx.payload, findings)
                scan_tx = tx.model_copy(update={"payload": sanitized}, deep=True)
                risk = await asyncio.wait_for(self.semantic.analyze(scan_tx), self.semantic_timeout)
                risk = SemanticRisk.model_validate(risk)
                tx.risk.prompt_injection = max(tx.risk.prompt_injection, risk.prompt_injection)
                tx.risk.data_exfiltration = risk.data_exfiltration
                tx.risk.tool_misuse = risk.tool_misuse
                tx.risk.semantic_status = "ok"
                score = max(risk.prompt_injection, risk.data_exfiltration, risk.tool_misuse)
                tx.metadata["ai_detection"].update(status="ok", score=score,
                    **scan_tx.metadata.get("semantic_details",{}),
                    model_revision=getattr(self.semantic, "model_revision", "operator_pinned_or_provider_defined"),
                    verdict="malicious" if score >= thresholds.block_threshold else
                    "review" if score >= thresholds.review_threshold else "benign")
                tx.risk.risk_band = ("HIGH_RISK" if score >= thresholds.block_threshold else
                    "UNCERTAIN" if score >= thresholds.review_threshold else "LOW_RISK")
                self.metrics.scores.labels("prompt_injection").observe(risk.prompt_injection)
                self.metrics.scores.labels("exfiltration").observe(risk.data_exfiltration)
            except Exception:
                tx.risk.semantic_status = "unavailable"
                tx.metadata["ai_detection"].update(status="unavailable", verdict="unknown")
        tx.metadata["ai_detection"]["latency_ms"] = (time.perf_counter() - started) * 1000
        self.metrics.semantic_scans.labels(tx.risk.semantic_status).inc()
        self.metrics.semantic_providers.labels(getattr(self.semantic, "provider_id", "none"), tx.risk.semantic_status).inc()
        self.metrics.semantic_latency.observe(time.perf_counter() - started)
        self.metrics.stages.labels("semantic").observe(time.perf_counter() - started)

    async def alignment_scan(self, tx, snapshot, label):
        intent = await self.workflows.intent(tx.principal, tx.context.workflow.workflow_id)
        if not intent or not snapshot.policy.task_alignment.enabled:
            return
        try:
            risk = await self.timed(tx, "task_alignment", asyncio.wait_for(
                self.alignment.analyze(intent, tx, label, {"steps": tx.budget.steps,
                    "llm_calls": tx.budget.llm_calls, "tool_calls": tx.budget.tool_calls}),
                self.semantic_timeout))
            risk = AlignmentRisk.model_validate(risk)
            tx.risk.task_alignment = risk.task_alignment
            tx.risk.goal_deviation = risk.goal_deviation
            tx.risk.data_exfiltration_intent = risk.data_exfiltration_intent
            tx.risk.unexpected_side_effect = risk.unexpected_side_effect
            tx.risk.alignment_confidence = risk.confidence
            tx.risk.alignment_status = "ok"
            self.metrics.scores.labels("task_alignment").observe(risk.task_alignment)
        except Exception:
            tx.risk.alignment_status = "unavailable"

    async def execute(self, request, principal):
        with self.tracer.start_as_current_span(
            "security.transaction", record_exception=False, set_status_on_exception=False
        ) as span:
            return await self._execute(request, principal, f"{span.get_span_context().trace_id:032x}", span)

    async def _execute(self, request, principal, trace_id, span):
        started = time.perf_counter()
        tx = self.prepare(request, principal)
        snapshot = self.policies.active  # One revision for the entire transaction, including output.
        policy = snapshot.policy
        try:
            prompt_hash = hashlib.sha256(encoded(tx.payload)).hexdigest()
        except (ValueError, RecursionError):
            return await self.transport_invalid(tx, snapshot, trace_id)
        findings = []
        latencies = {}
        tx.metadata["stage_latencies"] = latencies
        label = source_label(tx)
        record = None
        output = None
        input_decision = None
        reservation = Reservation()
        reconciled = False
        executed = False
        execution_ticket = None
        execution_view = None
        field_labels = {}
        value_handles = {}
        public_action_verified = False
        reserved_at = None
        tokens_used = 0
        credits_used = 0
        try:
            control_start = time.perf_counter()
            if request.public_action:
                recipe = self.public_actions.get(request.public_action)
                if (not recipe or request.payload or request.value_references or not tx.resource
                    or recipe["operation"] != tx.operation or recipe["tool"] != tx.resource.name):
                    findings.append(Finding(code="PUBLIC_ACTION_PARAMETERS_FORBIDDEN", control="information-flow"))
                else:
                    tx.payload = recipe["arguments"].copy()
                    public_action_verified = True
            for field, handle in request.value_references.items():
                if field in tx.payload or not self.values:
                    findings.append(Finding(code="DATA_REFERENCE_OVERRIDE", control="information-flow"))
                    continue
                try:
                    tx.payload[field], field_labels[field] = await self.values.resolve(principal, handle)
                except PermissionError:
                    findings.append(Finding(code="DATA_REFERENCE_NOT_ACCESSIBLE", control="information-flow"))
            findings += schema.inspect(tx)
            raw_size = len(encoded(tx.payload))
            if raw_size > policy.limits.request_bytes:
                findings.append(Finding(code="REQUEST_TOO_LARGE", control="size"))
            if raw_size > policy.limits.max_input_tokens:
                findings.append(Finding(code="INPUT_TOKEN_LIMIT_EXCEEDED", control="size"))
            if tx.payload.get("max_tokens", 256) > policy.limits.max_output_tokens:
                findings.append(Finding(code="OUTPUT_TOKEN_LIMIT_EXCEEDED", control="size"))
            try:
                normalize_started = time.perf_counter()
                with self.tracer.start_as_current_span("normalize", record_exception=False, set_status_on_exception=False):
                    normalized = canonicalize(tx.payload)
                    tx.metadata["normalization"] = {"version": "NFKC/format-character removal",
                        "changed": normalized != tx.payload}
                    tx.payload = normalized
                latencies["normalize"] = time.perf_counter() - normalize_started
                self.metrics.stages.labels("normalize").observe(latencies["normalize"])
            except ValueError:
                findings.append(Finding(code="CANONICALIZATION_INVALID", control="schema"))
            tx.metadata["response_limit"] = policy.limits.response_bytes
            if tx.effect != Effect.READ or tx.operation == Operation.AGENT_MESSAGE:
                if self.require_execution_id and not request.execution_id:
                    findings.append(Finding(code="EXECUTION_ID_REQUIRED", control="replay-protection"))
                tx.metadata["execution_id"] = request.execution_id or self.executions.logical_id(tx)
                tx.metadata["execution_arguments"] = tx.payload.copy()
            tx.metadata["network_policy"] = policy.network.model_dump()
            # Lookup is scoped before content is inspected; cross-tenant lookups return no record.
            if tx.operation == Operation.MEMORY_READ and not findings:
                record = await self.memory.lookup(tx.payload["memory_id"], principal.tenant_id)
                if record:
                    tx.resource = Resource(
                        name=record.memory_id,
                        tenant_id=record.tenant_id,
                        owner=record.owner,
                        classification=record.classification,
                    )
                    tx.context.source, tx.context.source_trust = record.source, record.source_trust
                else:
                    findings.append(Finding(code="MEMORY_NOT_FOUND", control="memory-authz"))
            category = "direct_user_injection"
            if tx.operation == Operation.MEMORY_READ or tx.operation == Operation.MEMORY_WRITE:
                category = "memory_injection"
            elif tx.operation == Operation.AGENT_MESSAGE:
                category = "agent_message_injection"
            elif tx.context.source == "retrieved":
                category = "retrieved_document_injection"
            tx.metadata["source_category"] = category
            label = DataSecurityLabel.join(
                await self.workflows.label(principal, tx.context.workflow.workflow_id),
                source_label(tx, "memory" if record else "user"))
            if record and record.data_security:
                label = DataSecurityLabel.join(label, record.data_security)
            if field_labels:
                label = DataSecurityLabel.join(label, *field_labels.values())
            if public_action_verified:
                # Only operator-sealed constant arguments bypass coarse exposure. No caller text is included.
                label = source_label(tx, "system", trust="trusted", classification="public")
            if tx.operation == Operation.MEMORY_WRITE:
                label = DataSecurityLabel.join(label, source_label(tx, "memory",
                    classification=tx.payload.get("classification", "internal")))
            tx.metadata["data_label"] = label.model_dump(mode="json")
            tool = self.tools.get(tx.resource.name if tx.resource else "")
            if tool and tx.operation in {Operation.MCP_TOOL_CALL, Operation.TOOL_CALL, Operation.API_CALL}:
                tx.payload, tool_findings = input_minimize(tool, tx.payload, {k: field_labels.get(k, label) for k in tx.payload})
                findings += tool_findings
                approved_fields = set(tool.output_fields if tool.output_fields is not None else tool.output_schema.get("properties", {}))
                if request.result_fields is not None and not set(request.result_fields) <= approved_fields:
                    findings.append(Finding(code="OUTPUT_FIELD_NOT_APPROVED", control="tool-output-sanitizer"))
            tx.metadata["data_flow"] = flow_facts(tx, label, policy)
            intent = await self.workflows.intent(principal, tx.context.workflow.workflow_id)
            tx.metadata["trusted_intent"] = intent.model_dump(mode="json") if intent else None
            if principal.delegated_workflow and tx.operation in {Operation.TOOL_CALL, Operation.MCP_TOOL_CALL,
                    Operation.API_CALL, Operation.AGENT_MESSAGE}:
                if not tx.resource or tx.resource.name not in principal.capabilities:
                    findings.append(Finding(code="DELEGATION_CAPABILITY_DENIED", control="delegation"))
            if tx.operation in {Operation.MCP_TOOL_CALL, Operation.TOOL_CALL}:
                findings += await self.timed(tx, "mcp_manifest", self.manifests.inspect(
                    tx, self.tool_adapter(tx), policy.mcp))
                adapter = self.tool_adapter(tx)
                if adapter is not None and hasattr(adapter, "preflight"):
                    findings += await adapter.preflight(tx)
            findings += await self.timed(tx, "deterministic_controls", self.controls(tx, snapshot))
            digest = approval_digest(tx, policy.metadata.revision)
            tx.context.approval_verified = await self.approvals.check(request.approval_token, digest)
            findings = [f for f in findings if not (
                f.control == "mcp-manifest" and f.action == "REQUIRE_APPROVAL" and tx.context.approval_verified)]
            latencies["controls"] = time.perf_counter() - control_start
            self.metrics.control_latency.observe(latencies["controls"])
            tokens, credits = estimate(tx, policy)
            try:
                reservation = await self.timed(tx, "budget_reservation", self.budgets.reserve(tx, policy, tokens, credits))
                reserved_at = time.perf_counter()
                tx.budget.available = bool(reservation.id)
                tx.budget.reservation_id = reservation.id
                tx.budget.reserved_credits = reservation.credits
                tx.budget.violations = reservation.violations
                tx.budget.steps, tx.budget.llm_calls, tx.budget.tool_calls = (
                    reservation.steps,
                    reservation.llm_calls,
                    reservation.tool_calls,
                )
            except Exception:
                tx.budget.available = False
            high_risk = (
                tx.context.source_trust == "untrusted"
                or (
                    tx.operation in {Operation.MCP_TOOL_CALL, Operation.TOOL_CALL, Operation.API_CALL}
                    and tx.effect != Effect.READ
                )
                or bool(tx.resource and tx.resource.classification == "restricted")
            )
            # Skip expensive inference for requests already denied by deterministic policy.
            preliminary = await self.decide(
                tx, snapshot, self.facts(tx, findings, high_risk, bool(record and record.quarantined))
            )
            if preliminary.decision in PERMITTED:
                await self.semantic_scan(tx, snapshot, findings, high_risk)
            if preliminary.decision in PERMITTED | {Decision.REQUIRE_APPROVAL}:
                await self.alignment_scan(tx, snapshot, label)
            decision = await self.decide(
                tx, snapshot, self.facts(tx, findings, high_risk, bool(record and record.quarantined))
            )
            input_decision = decision.model_copy(deep=True)
            remaining_reservation = (
                (policy.budgets.per_agent.reservation_ttl_seconds - (time.perf_counter() - reserved_at))
                if reserved_at
                else 0
            )
            if decision.decision in PERMITTED and remaining_reservation <= 0.05:
                findings.append(Finding(code="RESERVATION_EXPIRED", control="budget"))
                decision = await self.decide(tx, snapshot, self.facts(tx, findings, high_risk))
            if decision.decision in PERMITTED:
                tx.payload, changes = transform(tx.payload, findings)
                decision.transformations += changes
                transformed_findings = schema.inspect(tx)
                if len(encoded(tx.payload)) > policy.limits.request_bytes:
                    transformed_findings.append(Finding(code="TRANSFORMED_REQUEST_TOO_LARGE", control="size"))
                if transformed_findings:
                    findings += transformed_findings
                    decision = await self.decide(tx, snapshot, self.facts(tx, findings, high_risk))
                input_decision = decision.model_copy(deep=True)
                if decision.decision in PERMITTED and "execution_id" in tx.metadata:
                    try:
                        execution_ticket = await self.executions.reserve(tx, policy.metadata.revision)
                        execution_view = self.executions.public(execution_ticket)
                    except ReplayRejected as error:
                        execution_view = self.executions.public(error.record)
                        findings.append(Finding(code=error.code, control="replay-protection"))
                        decision = await self.decide(tx, snapshot, self.facts(tx, findings, high_risk))
                # Consumption is atomic; two concurrent requests cannot execute with one approval.
                if decision.decision not in PERMITTED:
                    pass
                elif tx.context.approval_verified and not await self.approvals.check(
                    request.approval_token, digest, consume=True
                ):
                    findings.append(Finding(code="APPROVAL_ALREADY_USED", control="approval"))
                    decision = await self.decide(tx, snapshot, self.facts(tx, findings, high_risk))
                else:
                    # Record authorization durably before performing a side effect.
                    await self.timed(tx, "audit", self.audit.append(
                        AuditEvent.from_transaction(
                            tx, input_decision, prompt_hash, trace_id, latencies, phase="authorization"
                        )
                    ))
                    await self.workflows.absorb(principal, tx.context.workflow.workflow_id, label)
                    if not await self.budgets.begin(reservation):
                        findings.append(Finding(code="RESERVATION_EXPIRED", control="budget"))
                        raise RuntimeError("Reservation could not start execution")
                    remaining_reservation = policy.budgets.per_agent.reservation_ttl_seconds - (
                        time.perf_counter() - reserved_at
                    )
                    if remaining_reservation <= 0.05:
                        findings.append(Finding(code="RESERVATION_EXPIRED", control="budget"))
                        raise RuntimeError("Reservation expired before execution")
                    # Re-check availability after durable audit/reservation, immediately before dispatch.
                    final_gate = await self.decide(tx, snapshot, self.facts(tx, findings, high_risk))
                    if final_gate.decision not in PERMITTED:
                        decision = final_gate
                        raise RuntimeError("Final policy gate refused dispatch")
                    upstream_started = time.perf_counter()
                    if execution_ticket:
                        await self.executions.start(execution_ticket)
                    with self.tracer.start_as_current_span(
                        "upstream.execute", record_exception=False, set_status_on_exception=False
                    ):
                        executed = True
                        result = await asyncio.wait_for(
                            self.upstream(tx, record, policy),
                            min(self.upstream_timeout, remaining_reservation - 0.01),
                        )
                    latencies["upstream"] = time.perf_counter() - upstream_started
                    if execution_ticket:
                        if result.tool_error:
                            await self.executions.fail(execution_ticket, uncertain=True)
                        else:
                            await self.executions.complete(execution_ticket)
                        execution_view = self.executions.public(execution_ticket)
                    self.metrics.stages.labels("upstream").observe(latencies["upstream"])
                    output_started = time.perf_counter()
                    tokens_used = max(tx.budget.estimated_input_tokens, result.input_tokens) + max(
                        0, result.output_tokens
                    )
                    credits_used = actual_credits(
                        tx,
                        policy,
                        max(tx.budget.estimated_input_tokens, result.input_tokens),
                        max(0, result.output_tokens),
                    )
                    output_findings = schema.inspect_output(tx, result.output)
                    if result.tool_error:
                        output_findings.append(Finding(code="MCP_TOOL_REPORTED_ERROR", control="tool-output", action="WARN"))
                    sanitized = result.output
                    if tool and tx.operation in {Operation.MCP_TOOL_CALL, Operation.TOOL_CALL, Operation.API_CALL}:
                        sanitized, sanitizer_findings = output_sanitize(tool, result.output,
                            policy.limits.response_bytes, request.result_fields)
                        output_findings += sanitizer_findings
                    if len(encoded(result.output)) > policy.limits.response_bytes:
                        output_findings.append(Finding(code="RESPONSE_TOO_LARGE", control="output-size"))
                    if (
                        result.output_tokens > tx.budget.max_output_tokens
                        and tx.operation == Operation.LLM_REQUEST
                    ):
                        output_findings.append(
                            Finding(code="UPSTREAM_TOKEN_LIMIT_EXCEEDED", control="output-size")
                        )
                    out_tx = tx.model_copy(deep=True)
                    out_tx.metadata["stage_latencies"] = latencies
                    out_tx.context.phase = "output"
                    if tx.operation in {Operation.MCP_TOOL_CALL, Operation.TOOL_CALL, Operation.API_CALL}:
                        out_tx.context.source_trust = (
                            "untrusted"
                            if "network" in self.adapters and tx.operation == Operation.API_CALL
                            else self.mcp_output_trust
                        )
                        if tool and tool.output_trust:
                            out_tx.context.source_trust = tool.output_trust
                    out_tx.payload = canonicalize(sanitized if sanitized is not None else {})
                    output_label = DataSecurityLabel.join(label,
                        source_label(out_tx, "memory" if record else "mcp" if tx.operation in {
                            Operation.MCP_TOOL_CALL, Operation.TOOL_CALL} else "api" if tx.operation == Operation.API_CALL
                            else "agent" if tx.operation == Operation.AGENT_MESSAGE else "system"),
                        derived=tx.operation == Operation.LLM_REQUEST)
                    if tool:
                        output_label = DataSecurityLabel.join(output_label, source_label(out_tx,
                            "mcp", trust=out_tx.context.source_trust, classification=tool.output_classification))
                    self.metrics.tokens.labels("input").inc(max(tx.budget.estimated_input_tokens, result.input_tokens))
                    self.metrics.tokens.labels("output").inc(max(0, result.output_tokens))
                    tx.metadata["data_label"] = output_label.model_dump(mode="json")
                    out_tx.metadata["data_label"] = tx.metadata["data_label"]
                    if tx.operation in {Operation.MCP_TOOL_CALL, Operation.TOOL_CALL}:
                        out_tx.metadata["source_category"] = "tool_output_injection"
                    out_tx.risk.semantic_status = "not_required"
                    out_tx.metadata.pop("deterministic_detection", None)
                    out_tx.metadata.pop("ai_detection", None)
                    output_findings += await self.timed(out_tx, "output_controls", self.controls(out_tx, snapshot, output=True))
                    output_high_risk = high_risk or tx.operation in {
                        Operation.MEMORY_READ,
                        Operation.MCP_TOOL_CALL,
                        Operation.TOOL_CALL,
                        Operation.API_CALL,
                    }
                    # Outputs are untrusted; semantic scans are conditional, as configured.
                    await self.semantic_scan(
                        out_tx,
                        snapshot,
                        output_findings,
                        output_high_risk and out_tx.context.source_trust == "untrusted",
                    )
                    output_decision = await self.decide(
                        out_tx, snapshot, self.facts(out_tx, output_findings, output_high_risk)
                    )
                    findings += output_findings
                    tx.metadata["output_detection_report"] = detection_report(out_tx, output_decision, output_findings)
                    if output_findings or out_tx.risk.risk_band != "LOW_RISK":
                        tx.metadata["source_category"] = out_tx.metadata.get("source_category", "direct_user_injection")
                    if output_decision.decision in PERMITTED:
                        output, changes = transform(out_tx.payload, output_findings)
                        output_decision.transformations += changes
                        if len(encoded(output)) > policy.limits.response_bytes:
                            finding = Finding(code="TRANSFORMED_RESPONSE_TOO_LARGE", control="output-size")
                            findings.append(finding)
                            output_findings.append(finding)
                            output_decision = await self.decide(
                                out_tx, snapshot, self.facts(out_tx, output_findings, output_high_risk)
                            )
                            output = None
                        else:
                            order = {Decision.ALLOW: 0, Decision.WARN: 1, Decision.REDACT: 2}
                            output_decision.decision = max(
                                [decision.decision, output_decision.decision],
                                key=lambda action: order[action],
                            )
                            output_decision.reason_codes = sorted(
                                set(decision.reason_codes + output_decision.reason_codes)
                            )
                            output_decision.controls = sorted(
                                set(decision.controls + output_decision.controls)
                            )
                            output_decision.transformations = (
                                decision.transformations + output_decision.transformations
                            )
                        decision = output_decision
                    else:
                        decision = output_decision
                        if decision.decision == Decision.QUARANTINE and tool:
                            await self.audit.append(AuditEvent.from_transaction(tx, decision,
                                hashlib.sha256(encoded(result.output)).hexdigest(), trace_id, latencies,
                                phase="tool_quarantine"))
                        if record and decision.decision == Decision.QUARANTINE:
                            await self.memory.quarantine(record)
                    latencies["output_controls"] = time.perf_counter() - output_started
                    if output is not None and decision.decision in PERMITTED:
                        await self.workflows.absorb(principal, tx.context.workflow.workflow_id, output_label)
            elif decision.decision == Decision.QUARANTINE:
                # Only persist quarantined content after memory authorization passed. Rego enforces this.
                if tx.operation == Operation.MEMORY_WRITE:
                    if (
                        "SCHEMA_INVALID" not in decision.reason_codes
                        and "SECRET_DETECTED" not in decision.reason_codes
                    ):
                        try:
                            execution_ticket = await self.executions.reserve(tx, policy.metadata.revision)
                        except ReplayRejected as error:
                            findings.append(Finding(code=error.code, control="replay-protection"))
                            execution_view = self.executions.public(error.record)
                            raise RuntimeError("Quarantine execution replay refused") from error
                        await self.audit.append(
                            AuditEvent.from_transaction(
                                tx, decision, prompt_hash, trace_id, latencies, phase="quarantine"
                            )
                        )
                        if not await self.budgets.begin(reservation):
                            findings.append(Finding(code="RESERVATION_EXPIRED", control="budget"))
                            raise RuntimeError("Quarantine reservation expired")
                        await self.executions.start(execution_ticket)
                        executed = True
                        quarantined = await self.memory.write(
                            tx, policy.memory.max_ttl_seconds, quarantined=True
                        )
                        await self.executions.complete(execution_ticket)
                        tokens_used, credits_used = tx.budget.estimated_input_tokens, reservation.credits
                        output = {"memory_id": quarantined.memory_id, "quarantined": True}
                elif record:
                    await self.memory.quarantine(record)
            tx.budget.consumed_credits = credits_used
            try:
                reconciled = await self.timed(tx, "budget_reconciliation",
                    self.budgets.reconcile(reservation, tokens_used, credits_used))
            except Exception:
                reconciled = False
            if not reconciled:
                findings.append(Finding(code="BUDGET_RECONCILIATION_FAILED", control="budget"))
                decision = await self.decide(tx, snapshot, self.facts(tx, findings, high_risk))
                output = None
        except asyncio.CancelledError:
            if execution_ticket:
                try:
                    await asyncio.shield(self.executions.fail(execution_ticket, uncertain=executed))
                except Exception:
                    pass
            if reservation.id:
                await asyncio.shield(
                    self.budgets.reconcile(
                        reservation,
                        reservation.tokens if executed else 0,
                        reservation.credits if executed else 0,
                    )
                )
            raise
        except Exception:
            # Error details can contain attacker-controlled evidence or upstream secrets; never return them.
            findings.append(Finding(code="UPSTREAM_OR_STORAGE_UNAVAILABLE", control="availability"))
            decision = await self.decide(tx, snapshot, self.facts(tx, findings))
            output = None
            if executed:
                tokens_used, credits_used = reservation.tokens, reservation.credits
            if not reconciled:
                try:
                    await self.budgets.reconcile(reservation, tokens_used, credits_used)
                except Exception:
                    pass
            tx.budget.consumed_credits = credits_used
        if execution_ticket:
            try:
                await self.executions.fail(execution_ticket, uncertain=executed)
                execution_view = self.executions.public(execution_ticket)
            except Exception:
                findings.append(Finding(code="EXECUTION_STATE_UNAVAILABLE", control="replay-protection"))
                execution_view = {"execution_id": tx.metadata["execution_id"], "state": "UNCERTAIN"}
                decision = await self.decide(tx, snapshot, self.facts(tx, findings))
                output = None
        if output is not None and decision.decision in PERMITTED and isinstance(output, dict) and self.values:
            try:
                for field, value in output.items():
                    value_handles[field] = await self.values.issue(principal, value,
                        DataSecurityLabel.model_validate(tx.metadata["data_label"]))
            except Exception:
                findings.append(Finding(code="DATA_REFERENCE_STORAGE_UNAVAILABLE", control="information-flow"))
                decision = await self.decide(tx, snapshot, self.facts(tx, findings))
                output, value_handles = None, {}
        latencies["total"] = time.perf_counter() - started
        span.set_attribute("security.decision", decision.decision.value)
        span.set_attribute("security.request_id", tx.request_id)
        span.set_attribute("security.policy_revision", decision.policy_revision)
        report = detection_report(tx, decision, findings)
        if "output_detection_report" in tx.metadata:
            report["output_inspection"] = tx.metadata["output_detection_report"]
        tx.metadata["detection_report"] = report
        try:
            await self.timed(tx, "audit", self.audit.append(
                AuditEvent.from_transaction(tx, decision, prompt_hash, trace_id, latencies)
            ))
        except Exception:
            findings.append(Finding(code="AUDIT_UNAVAILABLE", control="audit"))
            decision = await self.decide(tx, snapshot, self.facts(tx, findings))
            output = None
            report = detection_report(tx, decision, findings)
        self.metrics.record(tx, decision, findings, latencies["total"])
        return GatewayResult(
            security=decision, output=output, input_security=input_decision, budget=tx.budget.model_dump(),
            data_security=tx.metadata.get("data_label", {}), execution=execution_view, value_handles=value_handles,
            detection_report=report
        )

    async def upstream(self, tx, record, policy):
        if tx.operation == Operation.MEMORY_WRITE:
            record = await self.memory.write(tx, policy.memory.max_ttl_seconds)
            return UpstreamResult(output={"memory_id": record.memory_id, "source_trust": record.source_trust})
        if tx.operation == Operation.MEMORY_READ:
            actual = await self.memory.get(
                record.memory_id,
                tx.principal.tenant_id,
                tx.principal.subject,
                "memory:admin" in tx.principal.scopes,
            )
            if actual is None or actual.quarantined:
                raise RuntimeError("Memory no longer accessible")
            record.content = actual.content
            tx.context.source, tx.context.source_trust = actual.source, actual.source_trust
            return UpstreamResult(
                output={
                    "content": record.content,
                    "source": record.source,
                    "source_trust": record.source_trust,
                    "classification": record.classification,
                    "security_labels": record.security_labels,
                }
            )
        if tx.operation == Operation.AGENT_MESSAGE:
            return UpstreamResult(output={"message": tx.payload["message"], "agent": tx.resource.name,
                "metadata": {"sender_agent": tx.principal.agent_id, "tenant_id": tx.principal.tenant_id,
                "delegator": tx.principal.delegator, "delegation_depth": tx.principal.delegation_depth,
                "capabilities": tx.principal.capabilities, "workflow_id": tx.context.workflow.workflow_id,
                "parent_agent": tx.principal.parent_agent}})
        key = tx.resource.provider if tx.operation == Operation.LLM_REQUEST else "mcp"
        if tx.operation == Operation.API_CALL and "network" in self.adapters:
            key = "network"
        adapter = self.tool_adapter(tx) if key == "mcp" else self.adapters.get(key)
        if adapter is None:
            raise RuntimeError("No configured adapter")
        return await adapter.execute(tx)

    def tool_adapter(self, tx):
        server = tx.resource.mcp_server if tx.resource else "mock"
        return self.adapters.get("mcp:" + server, self.adapters.get("mcp") if server == "mock" else None)

    async def transport_invalid(self, tx, snapshot, trace_id):
        finding = Finding(code="JSON_INVALID", control="schema")
        verdict = await self.decide(
            tx.model_copy(update={"payload": {}}), snapshot, self.facts(tx, [finding])
        )
        await self.audit.append(AuditEvent.from_transaction(tx, verdict, "", trace_id, {}))
        self.metrics.record(tx, verdict, [finding], 0)
        return GatewayResult(security=verdict)
