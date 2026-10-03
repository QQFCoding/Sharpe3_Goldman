from prometheus_client import CollectorRegistry, Counter, Histogram, generate_latest

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

    def record(self, tx, decision, findings, seconds):
        from app.adapters.tools import TOOLS

        self.requests.inc()
        # 'final' provides an exclusive series for ratio dashboards without double counting controls.
        self.decisions.labels(decision.decision, "final").inc()
        for control in decision.controls:
            self.decisions.labels(decision.decision, control).inc()
        if tx.operation in {"tool_call", "mcp_tool_call", "api_call"}:
            name = tx.resource.name if tx.resource and tx.resource.name in TOOLS else "unknown"
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
