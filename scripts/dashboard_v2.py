"""SQL filters own investigation cardinality; Prometheus panels are explicitly global."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VARIABLES = {"tenant": "tenant_id", "agent": "agent_id", "workflow": "workflow_id",
    "operation": "operation", "decision": "decision", "tool": "tool", "semantic_status": "semantic_status",
    "policy_revision": "policy_revision", "threat_feed_revision": "threat_feed_revision"}
WHERE = " AND ".join(f"('__all__' IN (${{{name}:sqlstring}}) OR {column} IN (${{{name}:sqlstring}}))"
    for name, column in VARIABLES.items())
WHERE += " AND ('__all__' IN (${control:sqlstring}) OR controls && ARRAY[${control:sqlstring}]::text[])"
WHERE += " AND ('__all__' IN (${reason_code:sqlstring}) OR reason_codes && ARRAY[${reason_code:sqlstring}]::text[])"
BASE = "FROM aicl_security_events WHERE $__timeFilter(timestamp) AND " + WHERE
TRACE_LINK = '/explore?left={"datasource":"tempo","queries":[{"refId":"A","queryType":"traceql","query":"${__value.raw}"}]}'


def build():
    panels, y = [], 0
    def row(title):
        nonlocal y
        panels.append({"id": len(panels) + 1, "type": "row", "title": title, "collapsed": False,
            "gridPos": {"x": 0, "y": y, "w": 24, "h": 1}})
        y += 1
    def sql(title, query, kind="stat", width=6):
        nonlocal y
        panels.append({"id": len(panels) + 1, "title": title, "type": kind,
            "datasource": {"type": "postgres", "uid": "security-audit"},
            "gridPos": {"x": 0, "y": y, "w": width, "h": 6},
            "targets": [{"refId": "A", "rawSql": query, "format": "time_series" if kind == "timeseries" else "table"}],
            "fieldConfig": {"defaults": {"color": {"mode": "palette-classic"}}, "overrides": []},
            "options": {"reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
                "legend": {"displayMode": "list", "placement": "bottom"}}})
        y += 6
    def prom(title, query, kind="timeseries"):
        sql(title, "SELECT 0", kind, 24)
        panels[-1].update(datasource={"type": "prometheus", "uid": "prometheus"},
            description="Global aggregate: tenant/agent/workflow filtering applies to SQL event panels. "
                "No per-request, tenant, agent or workflow Prometheus labels.",
            targets=[{"refId": "A", "expr": query, "legendFormat": "{{stage}} {{signal}} {{kind}} {{status}}"}])
    row("1 — Live overview (filtered audit events)")
    sql("Protected requests", "SELECT count(*) AS requests " + BASE)
    for decision in ["ALLOW", "BLOCK", "REQUIRE_APPROVAL"]:
        sql(decision + " rate", f"SELECT COALESCE(avg((decision='{decision}')::int),0) AS rate " + BASE)
    sql("Security event timeline", "SELECT $__timeGroupAlias(timestamp,'1m'), decision AS metric, count(*) AS value " +
        BASE + " GROUP BY 1,2 ORDER BY 1", "timeseries", 24)
    prom("Active policy and feed revision (global)", "aicl_active_revision", "table")
    row("2 — Attack activity")
    sql("Reasons and source channels", "SELECT unnest(reason_codes) AS reason, source_category, count(*) AS events " +
        BASE + " GROUP BY 1,2 ORDER BY 3 DESC LIMIT 30", "table", 24)
    for code, title in [("PROMPT_INJECTION_PATTERN", "Prompt injection"), ("SECRET_DETECTED", "Secret leakage"),
        ("PII_DETECTED", "PII"), ("UNSAFE_URL", "SSRF"), ("CONFIDENTIAL_DATA_TO_EXTERNAL_SINK", "Pre-execution exfiltration")]:
        sql(title, "SELECT count(*) AS events " + BASE + f" AND '{code}'=ANY(reason_codes)")
    row("3 — Agent behavior")
    sql("Tools, effects and decisions", "SELECT operation, effect, decision, count(*) AS events " + BASE +
        " GROUP BY 1,2,3 ORDER BY 4 DESC", "table", 24)
    sql("Delegation depths", "SELECT delegation_depth, count(*) AS events " + BASE + " GROUP BY 1", "barchart", 24)
    prom("Workflow/delegation depth (global)", "sum by(le,kind)(aicl_workflow_depth_bucket)")
    row("4 — Semantic security")
    sql("Semantic status and abstention", "SELECT semantic_status, risk_band, count(*) AS events " + BASE +
        " GROUP BY 1,2", "table", 24)
    sql("Semantic score distribution", "SELECT width_bucket(injection_risk,0,1,10) AS bucket, count(*) AS events " +
        BASE + " GROUP BY 1 ORDER BY 1", "barchart", 24)
    prom("Injection, alignment and exfiltration distributions (global)", "sum by(le,signal)(aicl_risk_score_bucket)")
    prom("Semantic scans / failures (global)", "sum by(status)(rate(aicl_semantic_scans_total[$__rate_interval]))")
    prom("Classifier provider breakdown (global)", "sum by(provider,status)(aicl_semantic_provider_scans_total)")
    row("5 — Budget and resources")
    sql("Credits consumed", "SELECT COALESCE(sum(credits),0) AS credits " + BASE)
    sql("Top workflows by consumption", "SELECT workflow_id, sum(credits) AS credits " + BASE +
        " GROUP BY 1 ORDER BY 2 DESC LIMIT 20", "table", 24)
    prom("Token usage (global)", "sum by(direction)(rate(aicl_tokens_total[$__rate_interval]))")
    prom("Budget denials (global)", "rate(aicl_budget_rejections_total[$__rate_interval])")
    row("6 — Policy and threat feed")
    sql("Decisions by revision", "SELECT policy_revision, threat_feed_revision, decision, count(*) AS events " +
        BASE + " GROUP BY 1,2,3", "table", 24)
    prom("Reload successes and failures (global)", "sum by(kind,status)(aicl_config_reloads_total)")
    prom("Threat rule hits (global)", "sum by(rule)(aicl_threat_rule_hits_total)")
    row("7 — Performance")
    for quantile in [.5, .95, .99]:
        prom(f"Stage p{int(quantile * 100)} (global)",
            f"histogram_quantile({quantile},sum by(le,stage)(rate(aicl_stage_seconds_bucket[$__rate_interval])))")
    sql("Filtered request latency", "SELECT $__timeGroupAlias(timestamp,'1m'), percentile_cont(.95) "
        "WITHIN GROUP(ORDER BY latency) AS p95_seconds " + BASE + " GROUP BY 1 ORDER BY 1", "timeseries", 24)
    row("8 — Security event investigation")
    sql("Recent Security Events", "SELECT timestamp,tenant_id,agent_id,workflow_id,operation,resource_category,"
        "decision,reason_codes,controls,injection_risk,task_alignment,policy_revision,threat_feed_revision,"
        "credits,latency,trace_id " + BASE + " ORDER BY timestamp DESC LIMIT 250", "table", 24)
    links = [{"matcher": {"id": "byName", "options": "trace_id"},
        "properties": [{"id": "links", "value": [{"title": "Open in Tempo", "targetBlank": True, "url": TRACE_LINK}]}]}]
    panels[-1]["fieldConfig"]["overrides"] = links
    row("9 — Traces")
    sql("Recent trace IDs (click to investigate)", "SELECT timestamp,decision,trace_id " + BASE +
        " ORDER BY timestamp DESC LIMIT 50", "table", 24)
    panels[-1]["fieldConfig"]["overrides"] = links
    variables = []
    queries = VARIABLES | {"control": "unnest(controls)", "reason_code": "unnest(reason_codes)"}
    for name, column in queries.items():
        variables.append({"name": name, "label": name, "type": "query", "refresh": 2,
            "datasource": {"type": "postgres", "uid": "security-audit"},
            "query": f"SELECT DISTINCT {column} FROM aicl_security_events ORDER BY 1 LIMIT 1000",
            "multi": True, "includeAll": True, "allValue": "'__all__'", "current": {"text": "All", "value": "$__all"}})
    return {"uid": "aicl-security", "title": "AI Control Layer — Security Operations", "schemaVersion": 39,
        "version": 2, "refresh": "5s", "timezone": "browser", "tags": ["aicl", "security"],
        "time": {"from": "now-15m", "to": "now"}, "templating": {"list": variables}, "panels": panels}


def write():
    path = ROOT / "observability/grafana/dashboards/security.json"
    path.write_text(json.dumps(build(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    write()
