"""Provision local alerts without contact points or external notifications."""
import copy
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def main():
    path = ROOT / "observability/grafana/provisioning/alerting/security.yaml"
    data = yaml.safe_load(path.read_text())
    template = data["groups"][0]["rules"][0]
    rules = [template]
    for uid, title, expression, threshold in [
        ("injection-spike", "Prompt injection spike", "sum(increase(aicl_prompt_injection_total[5m]))", 10),
        ("semantic-failure", "Semantic provider failures", 'sum(increase(aicl_semantic_scans_total{status="unavailable"}[5m]))', 5),
        ("opa-failure", "OPA failures", "sum(increase(aicl_opa_failures_total[5m]))", 0),
        ("budget-spike", "Budget rejection spike", "sum(increase(aicl_budget_rejections_total[5m]))", 10),
        ("latency-high", "Gateway p95 latency high", "histogram_quantile(0.95,sum by(le)(rate(aicl_request_seconds_bucket[5m])))", 2),
        ("termination-spike", "Agent termination spike", "sum(increase(aicl_agent_terminations_total[5m]))", 3),
    ]:
        rule = copy.deepcopy(template)
        rule.update(uid="aicl-" + uid, title=title, annotations={"summary": title})
        rule["data"][0]["model"]["expr"] = expression
        rule["data"][1]["model"]["expression"] = f"$A > {threshold}"
        rules.append(rule)
    data["groups"][0]["rules"] = rules
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")


if __name__ == "__main__":
    main()
