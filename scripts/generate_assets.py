"""Regenerate the Pydantic policy schema and provisioned Grafana dashboard."""

import json
from pathlib import Path

from app.policy.loader import Policy

ROOT = Path(__file__).resolve().parents[1]


def main():
    (ROOT / "config/policy.schema.json").write_text(json.dumps(Policy.model_json_schema(), indent=2) + "\n")
    panels = []

    def panel(title, expression, kind="stat", unit="short", width=6, legend=None):
        i = len(panels)
        panels.append(
            {
                "id": i + 1,
                "title": title,
                "type": kind,
                "datasource": {"type": "prometheus", "uid": "prometheus"},
                "gridPos": {"x": (i % 4) * 6, "y": (i // 4) * 8, "w": width, "h": 8},
                "targets": [{"expr": expression, "refId": "A", "legendFormat": legend or "{{decision}}"}],
                "fieldConfig": {
                    "defaults": {"unit": unit, "color": {"mode": "palette-classic"}},
                    "overrides": [],
                },
                "options": {
                    "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
                    "legend": {"displayMode": "list", "placement": "bottom"},
                },
            }
        )

    panel("Protected requests", "sum(aicl_requests_total)")
    panel(
        "Allow / redact / block ratio", 'sum by(decision) (aicl_decisions_total{control="final"})', "piechart"
    )
    panel(
        "Blocked interactions",
        'sum(aicl_decisions_total{control="final",decision=~"BLOCK|QUARANTINE|TERMINATE"})',
    )
    panel("Request rate", "sum(rate(aicl_requests_total[$__rate_interval]))", "timeseries", "reqps")
    panel("Prompt injection attempts", "sum(aicl_prompt_injection_total)")
    panel("Secret leak attempts blocked", "sum(aicl_secret_blocks_total)")
    panel("PII spans redacted", "sum(aicl_pii_redactions_total)")
    panel("Unauthorized tools", 'sum(aicl_decisions_total{control="tool-authz",decision="BLOCK"})')
    panel("Resource credits consumed", "sum(aicl_budget_used_total)")
    panel("Budget rejections", "sum(aicl_budget_rejections_total)")
    panel("Agent terminations", "sum(aicl_agent_terminations_total)")
    panel("Memory quarantines", "sum(aicl_memory_quarantines_total)")
    panel(
        "Latency p50 / p95 / p99",
        "histogram_quantile(0.95, sum by(le) (rate(aicl_request_seconds_bucket[$__rate_interval])))",
        "timeseries",
        "s",
    )
    panels[-1]["targets"] = [
        {
            "refId": label,
            "expr": f"histogram_quantile({quantile}, sum by(le) (rate(aicl_request_seconds_bucket[$__rate_interval])))",
            "legendFormat": label,
        }
        for label, quantile in [("p50", 0.5), ("p95", 0.95), ("p99", 0.99)]
    ]
    panel(
        "Semantic scans by status",
        "sum by(status) (aicl_semantic_scans_total)",
        "timeseries",
        legend="{{status}}",
    )
    panel(
        "OPA evaluation p95",
        "histogram_quantile(0.95, sum by(le) (rate(aicl_policy_eval_seconds_bucket[$__rate_interval])))",
        "timeseries",
        "s",
    )
    panel(
        "Semantic scan p95",
        "histogram_quantile(0.95, sum by(le) (rate(aicl_semantic_scan_seconds_bucket[$__rate_interval])))",
        "timeseries",
        "s",
    )
    panel(
        "Top blocked tools",
        'topk(5, sum by(tool) (aicl_tool_calls_total{decision="BLOCK"}))',
        "bargauge",
        legend="{{tool}}",
    )
    panel(
        "Top threat signatures",
        "topk(5, sum by(rule) (aicl_threat_rule_hits_total))",
        "bargauge",
        legend="{{rule}}",
    )
    dashboard = {
        "uid": "aicl-security",
        "title": "AI Control Layer — Security",
        "schemaVersion": 39,
        "version": 1,
        "refresh": "5s",
        "timezone": "browser",
        "tags": ["aicl", "security"],
        "time": {"from": "now-15m", "to": "now"},
        "panels": panels,
    }
    path = ROOT / "observability/grafana/dashboards/security.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(dashboard, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
