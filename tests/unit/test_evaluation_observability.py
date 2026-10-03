import json

import yaml

from app.settings import ROOT


def test_dashboard_filters_datasources_safe_events_and_alerts():
    dashboard = json.loads((ROOT / "observability/grafana/dashboards/security.json").read_text(encoding="utf-8"))
    variables = {v["name"] for v in dashboard["templating"]["list"]}
    assert {"tenant", "agent", "workflow", "operation", "decision", "control", "tool", "reason_code",
        "semantic_status", "policy_revision", "threat_feed_revision"} == variables
    assert len([p for p in dashboard["panels"] if p["type"] == "row"]) == 9
    events = next(p for p in dashboard["panels"] if p["title"] == "Recent Security Events")
    query = events["targets"][0]["rawSql"]
    assert "${tenant:sqlstring}" in query and "${agent:sqlstring}" in query
    assert "prompt_hash" not in query and "content" not in query
    assert "tempo" in json.dumps(events["fieldConfig"]["overrides"])
    data = yaml.safe_load((ROOT / "observability/grafana/provisioning/datasources/datasources.yaml").read_text())
    assert {d["uid"] for d in data["datasources"]} == {"prometheus", "tempo", "security-audit"}
    postgres = next(d for d in data["datasources"] if d["uid"] == "security-audit")
    assert postgres["user"] == "aicl_grafana"
    alerts = yaml.safe_load((ROOT / "observability/grafana/provisioning/alerting/security.yaml").read_text())
    assert alerts["groups"][0]["rules"]
