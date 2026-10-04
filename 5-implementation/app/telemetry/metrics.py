from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram, generate_latest

from app.core.decision import Decision


class Metrics:
    def __init__(self):
        self.registry = CollectorRegistry()

        def counter(name, description, labels=()):
            return Counter(name, description, labels, registry=self.registry)

        def histogram(name, description):
            return Histogram(
                name,
                description,
                registry=self.registry,
                buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 15),
            )

        self.requests = counter("aicl_requests_total", "Protected operations")
        self.decisions = counter(
            "aicl_decisions_total", "Decisions by triggering control", ("decision", "control")
        )
        self.policy_evaluations = counter("aicl_policy_evaluations_total", "OPA evaluations")
        self.policy_latency = histogram("aicl_policy_eval_seconds", "OPA evaluation latency")
        self.semantic_scans = counter("aicl_semantic_scans_total", "Semantic scans", ("status",))
        self.semantic_providers = counter("aicl_semantic_provider_scans_total", "Semantic scans by provider", ("provider", "status"))
        self.semantic_latency = histogram("aicl_semantic_scan_seconds", "Semantic scan latency")
        self.injections = counter("aicl_prompt_injection_total", "Prompt injection detections")
        self.pii = counter("aicl_pii_redactions_total", "PII spans redacted")
        self.secrets = counter("aicl_secret_blocks_total", "Transactions blocked for secrets")
        self.tools = counter("aicl_tool_calls_total", "Tool decisions", ("tool", "decision"))
        self.budget_used = counter("aicl_budget_used_total", "Resource credits consumed")
        self.budget_rejections = counter("aicl_budget_rejections_total", "Budget rejections")
        self.terminations = counter("aicl_agent_terminations_total", "Agent terminations", ("reason",))
        self.quarantines = counter("aicl_memory_quarantines_total", "Memory quarantines")
        self.threat_hits = counter("aicl_threat_rule_hits_total", "Threat signature hits", ("rule",))
        self.latency = histogram("aicl_request_seconds", "Total protected operation latency")
        self.control_latency = histogram("aicl_control_seconds", "Deterministic controls latency")
        self.stages = Histogram("aicl_stage_seconds", "Gateway stage latency", ("stage",),
            registry=self.registry, buckets=(.001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 15, 60))
        self.scores = Histogram("aicl_risk_score", "Numeric risk distributions", ("signal",),
            registry=self.registry, buckets=(.1, .25, .3, .5, .6, .7, .85, .95, 1))
        self.security_events = counter("aicl_security_events_total", "Final decisions by bounded categories",
            ("operation", "decision", "semantic_status", "effect"))
        self.risk_bands = counter("aicl_risk_bands_total", "Semantic abstention bands", ("band",))
        self.reloads = counter("aicl_config_reloads_total", "Configuration reload outcomes", ("kind", "status"))
        self.active_revision = Gauge("aicl_active_revision", "Active configuration revision", ("kind", "revision"),
            registry=self.registry)
        self.opa_failures = counter("aicl_opa_failures_total", "OPA failures")
        self.tokens = counter("aicl_tokens_total", "Executed input/output token usage", ("direction",))
        self.depth = Histogram("aicl_workflow_depth", "Workflow and delegation depth", ("kind",),
            registry=self.registry, buckets=(0, 1, 2, 3, 4, 8, 16, 32))

    def revisions(self, snapshot):
        self.active_revision.clear()
        self.active_revision.labels("policy", snapshot.policy.metadata.revision).set(1)
        self.active_revision.labels("threat_feed", snapshot.feed.revision).set(1)

    def record(self, tx, decision, findings, seconds):
        from app.adapters.tools import TOOLS

        self.requests.inc()
        self.security_events.labels(tx.operation, decision.decision, decision.risk.semantic_status, tx.effect).inc()
        self.risk_bands.labels(decision.risk.risk_band).inc()
        self.depth.labels("workflow").observe(tx.context.workflow.depth)
        self.depth.labels("delegation").observe(tx.principal.delegation_depth)
        # 'final' provides an exclusive series for ratio dashboards without double counting controls.
        self.decisions.labels(decision.decision, "final").inc()
        for control in decision.controls:
            self.decisions.labels(decision.decision, control).inc()
        if tx.operation in {"tool_call", "mcp_tool_call", "api_call"}:
            name = tx.resource.name if tx.resource and (tx.resource.name in TOOLS or tx.metadata.get("registered_tool_name") == tx.resource.name) else "unknown"
            self.tools.labels(name, decision.decision).inc()
        if (
            any(f.code == "PROMPT_INJECTION_PATTERN" for f in findings)
            or "SEMANTIC_HIGH_RISK" in decision.reason_codes
        ):
            self.injections.inc()
        self.pii.inc(
            sum(f.control == "pii-scanner" and f.action == "REDACT" for f in findings)
            if decision.transformations
            else 0
        )
        if (
            decision.decision in {Decision.BLOCK, Decision.QUARANTINE}
            and "SECRET_DETECTED" in decision.reason_codes
        ):
            self.secrets.inc()
        if not tx.budget.available:
            self.budget_rejections.inc()
        if decision.decision == Decision.TERMINATE:
            for reason in decision.reason_codes:
                if reason.startswith("MAX_"):
                    self.terminations.labels(reason).inc()
        if decision.decision == Decision.QUARANTINE:
            self.quarantines.inc()
        for rule in {f.rule_id for f in findings if f.rule_id}:
            self.threat_hits.labels(rule).inc()
        self.budget_used.inc(tx.budget.consumed_credits)
        self.latency.observe(seconds)

    def render(self):
        return generate_latest(self.registry)
