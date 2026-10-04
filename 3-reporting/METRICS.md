# Implemented metric inventory

Prometheus definitions are in [metrics.py](../5-implementation/app/telemetry/metrics.py). The authenticated gateway endpoint is `GET /metrics`. Histograms expose `_bucket`, `_sum` and `_count` series; p50/p95/p99 are derived from histogram buckets. Counter values reflect this gateway's instrumentation, not all traffic in an external agent ecosystem.

| Metric | Type / labels | Meaning |
|---|---|---|
| `aicl_requests_total` | Counter | Recorded protected operations |
| `aicl_decisions_total` | Counter: `decision`, `control` | Final decisions and individual triggering controls; use `control="final"` for exclusive decision ratios |
| `aicl_security_events_total` | Counter: `operation`, `decision`, `semantic_status`, `effect` | Decisions by bounded security categories |
| `aicl_policy_evaluations_total` | Counter | OPA evaluations |
| `aicl_policy_eval_seconds` | Histogram | OPA evaluation latency |
| `aicl_opa_failures_total` | Counter | OPA failures |
| `aicl_semantic_scans_total` | Counter: `status` | Semantic scans and availability status |
| `aicl_semantic_provider_scans_total` | Counter: `provider`, `status` | Semantic scans by provider/status |
| `aicl_semantic_scan_seconds` | Histogram | Semantic scan latency |
| `aicl_control_seconds` | Histogram | Deterministic control latency |
| `aicl_request_seconds` | Histogram | Total recorded protected-operation latency |
| `aicl_stage_seconds` | Histogram: `stage` | Gateway stage latency |
| `aicl_risk_score` | Histogram: `signal` | Numeric risk distributions |
| `aicl_risk_bands_total` | Counter: `band` | Semantic risk/abstention bands |
| `aicl_prompt_injection_total` | Counter | Rule/semantic prompt-injection detections |
| `aicl_pii_redactions_total` | Counter | PII spans recorded as redacted |
| `aicl_secret_blocks_total` | Counter | Transactions blocked/quarantined for secrets |
| `aicl_tool_calls_total` | Counter: `tool`, `decision` | Tool/API decisions; denied calls can be counted without upstream dispatch |
| `aicl_budget_used_total` | Counter | Configured resource credits consumed |
| `aicl_budget_rejections_total` | Counter | Budget rejections |
| `aicl_agent_terminations_total` | Counter: `reason` | Agent terminations for recorded maximum-limit reasons |
| `aicl_memory_quarantines_total` | Counter | Quarantine decisions |
| `aicl_threat_rule_hits_total` | Counter: `rule` | Unique triggering threat rules per recorded request |
| `aicl_config_reloads_total` | Counter: `kind`, `status` | Policy/feed reload outcomes |
| `aicl_active_revision` | Gauge: `kind`, `revision` | Active policy/feed revision |
| `aicl_tokens_total` | Counter: `direction` | Executed input/output token usage |
| `aicl_workflow_depth` | Histogram: `kind` | Workflow/delegation depth |

## Dashboard/API quantities

These quantities are implemented dashboard/API data, separate from Prometheus metric series:

| Surface | Reported quantities |
|---|---|
| Request report / detection lab | Rule verdict, real AI score/status, final OPA decision, findings, rule IDs, severity, transformations, stage timings and detector disagreement |
| Threat Observatory / Security flags | Recent requests, grouped request alerts, decision/control distributions and filterable privacy-safe events |
| Model diagnostics | Source/model availability and freshness, labeled evaluation confusion tables, F1/precision/recall/FPR/FNR, score distributions, cohort/language breakdowns, disagreement and complementary correct detections |
| Policy & budgets | Active/previous revisions, effective control actions/thresholds, provider availability, model/tool allowlists, limits, configured credit rates and reload results |
| Scoped budget API | Charged credits/tokens, active unstarted reservations, remaining allowances, step/LLM/tool counters, live concurrency, last-minute admission attempts and workflow elapsed/remaining time |
| Audit export | Authorization/final decisions, reason/rule IDs, identity, hashed resource/workflow identifiers, revisions, credits and timing summaries |

Budget snapshots come from the actual backend for an exact tenant/subject/agent/workflow identity. Unknown workflows report no accounting state; unavailable accounting returns an error instead of invented usage. Detection-lab inspection never dispatches a tool and does not consume execution workflow budgets.

For offline quality, [evaluation statistics](../5-implementation/app/evaluation/statistics.py) calculate labeled metrics. AUROC/AUPRC require suitable labels/scores; absent values must remain unavailable. Measured latency evidence and quality limitations are in [architecture](../2-architecture/README.md).
