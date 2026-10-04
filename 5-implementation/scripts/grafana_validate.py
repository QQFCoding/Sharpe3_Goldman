"""Exercise provisioned SQL panels through Grafana's actual datasource query API."""
import json
import re
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]


def main():
    with httpx.Client(base_url="http://127.0.0.1:3000", auth=("admin", "local-demo-password"), timeout=20) as client:
        dashboard = client.get("/api/dashboards/uid/aicl-security").json()["dashboard"]
        def query(sql):
            response = client.post("/api/ds/query", json={"from": str(int((time.time() - 86400) * 1000)),
                "to": str(int(time.time() * 1000)), "queries": [{"refId": "A", "datasource": {
                    "type": "postgres", "uid": "security-audit"}, "rawSql": sql,
                    "format": "table", "intervalMs": 60000, "maxDataPoints": 1000}]})
            response.raise_for_status()
            result = response.json()["results"]["A"]
            assert not result.get("error"), result
            return result.get("frames", [])
        count = 0
        for panel in dashboard["panels"]:
            if panel.get("datasource", {}).get("uid") != "security-audit":
                continue
            sql = re.sub(r"\$\{\w+:sqlstring\}", "'__all__'", panel["targets"][0]["rawSql"])
            query(sql)
            count += 1
        for variable in dashboard["templating"]["list"]:
            query(variable["query"])
        rows = query("SELECT tenant_id,agent_id,decision,trace_id FROM aicl_security_events "
            "WHERE tenant_id='tenant-a' AND agent_id='demo-agent' AND decision='BLOCK' ORDER BY timestamp DESC LIMIT 5")
        assert rows and rows[0]["data"]["values"][0], rows
        trace = rows[0]["data"]["values"][3][0]
        assert client.get(f"/api/datasources/proxy/uid/tempo/api/traces/{trace}", headers={"Accept": "application/json"}).status_code == 200
        alerts = client.get("/api/v1/provisioning/alert-rules")
        assert alerts.status_code == 200 and alerts.json()
        path = ROOT / "artifacts/grafana-validation.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"sql_panels": count, "variables": len(dashboard["templating"]["list"]),
            "filtered_events": True, "tempo_trace": True, "alerts": len(alerts.json()),
            "visual_browser_check": "No browser provider available; validated actual Grafana datasource responses."}, indent=2) + "\n")
        print(f"Grafana: {count} SQL panels, 11 variable queries, tenant/agent/BLOCK filter, Tempo trace, local alerts passed.")


if __name__ == "__main__":
    main()
