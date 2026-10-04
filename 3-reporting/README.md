# 3 — Reporting

The native dashboard provides a Threat Observatory, live detection lab, grouped security flags, model diagnostics and Policy & budgets. It displays actual gateway data and authenticated operator views. Grafana adds provisioned metrics/audit panels; Tempo provides linked traces. A separate Streamlit frontend calls the same gateway.

## Dashboard screenshots

![Threat Observatory dashboard](screenshots/threat-observatory.png)

![Policy and budgets dashboard](screenshots/policy-and-budgets.png)

The [security-alert screenshot](screenshots/security-alerts.png) shows grouped request findings. These are existing, saved demonstration captures, copied into the submission for review. The Observatory/alert captures come from iteration 3; Policy & budgets comes from the later governance browser validation. They are not new screenshots of a production deployment. The governance capture explicitly has its semantic provider disabled; configured thresholds are displayed separately from provider availability.

Screenshot provenance:

| Submission image | Original local evidence |
|---|---|
| `screenshots/threat-observatory.png` | `5-implementation/docs/iteration3/observatory-desktop.png` |
| `screenshots/security-alerts.png` | `5-implementation/docs/iteration3/alerts-desktop.png` |
| `screenshots/policy-and-budgets.png` | `5-implementation/artifacts/final/governance/governance-desktop.png` |

The saved [governance validation](../5-implementation/docs/final/governance-browser.json) records nine browser checks with no page errors. The [iteration 3 browser evidence](../5-implementation/docs/iteration3/browser-qa.json) covers its live operator interface. These reports retain their original scope and dates.

## Implemented metrics and reports

The full, code-backed inventory is [METRICS.md](METRICS.md). Implemented reporting covers:

- Request counts, final decision ratios and triggering controls.
- Prompt-injection detections, secret blocks, PII redactions, quarantines and threat-rule hits.
- Tool decisions, semantic availability/provider status, risk distributions and detector disagreements.
- Total request, deterministic control, OPA, semantic and individual-stage latency, including histogram-derived percentiles.
- Credits consumed/rejected, token usage, terminations and workflow/delegation depth.
- Scoped budget snapshots: usage, active reservations, remaining limits, steps/calls, concurrency, rate and elapsed time.
- Active policy/feed revisions, reload outcomes and OPA failures.
- Offline labeled evaluations: confusion counts, precision, recall, F1, FPR/FNR, AUROC/AUPRC, complementarity and cohort/language breakdowns.

Live unlabeled requests have no accuracy or recall estimate. Offline evaluation evidence includes source/dataset/model binding and freshness checks. Configured credits are accounting units; no live provider billing is measured.

Audit export is authenticated, bounded NDJSON (up to 10,000 recent events), optionally filtered by tenant/subject within that window. It includes decisions, reason/rule IDs, revisions, hashes, identity, accounting and timings; it excludes raw prompts and arbitrary evidence. The local in-memory history resets on restart. Deployment mode uses PostgreSQL.

## Open the dashboard

From `5-implementation` with dependencies, OPA and pinned model installed:

```text
python scripts/final_demo.py
```

Open `http://127.0.0.1:8012/dashboard` and connect using the isolated demo operator token `demo-admin-token`. To launch Streamlit as well, use `python scripts/final_demo.py --streamlit` and open `http://127.0.0.1:8502`. The launchers refuse occupied ports and stop only their own processes on Ctrl+C.

Native UI source: [HTML](../5-implementation/app/dashboard.html), [JavaScript](../5-implementation/app/dashboard.js), [CSS](../5-implementation/app/dashboard.css). Grafana source: [dashboard JSON](../5-implementation/observability/grafana/dashboards/security.json). Operator APIs: [Observatory](../5-implementation/app/api/observatory.py), [governance](../5-implementation/app/api/governance.py).
