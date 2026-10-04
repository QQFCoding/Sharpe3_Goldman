# Governance and audit delivery

The native dashboard now has a **Policy & budgets** view. It shows the active policy/feed revisions, previous valid revision, enabled controls, input/output actions, effective semantic thresholds for the selected provider, provider availability, model/tool allowlists, request limits and configured credit rates. Configuration and provider availability are displayed separately.

Operators can reload the configured server-side policy/feed pair. The same atomic validation used by the gateway preserves the active snapshot when validation fails. The dashboard displays the most recent reload performed through its governance endpoint in that process. Existing `/admin/policy/reload` and `/admin/threat-feed/reload` remain compatible; their calls are counted in metrics but do not populate the governance endpoint's process-local last-result field.

Budget inspection requires the exact identity and workflow ID used by the integration. This is a snapshot of the actual accounting backend, not a global estimate derived from audit events. The useful agent report returns a `triage-<UUID>` workflow; the budget demonstration returns a `budget-<UUID>` workflow. Enter the returned value and select `tenant-a / alice / demo-agent` for those demo identities.

Budget quantities are:

- Credits/tokens: charged usage, unstarted active reservations, remaining and limit. Started operations retain the maximum charge until reconciliation, including after hold expiry.
- Steps, LLM calls and tool calls: admitted workflow counters and remaining limits.
- Concurrency: live holds for the same principal across workflows.
- Rate: reservation attempts for the same subject and tenant during the last 60 seconds, including rejected attempts.
- Workflow elapsed time and remaining wall-time allowance.

The Redis snapshot is one atomic read-only Lua evaluation; expired holds are excluded without modifying admission state. The in-memory snapshot uses the same lock as admissions/reconciliation. Identity selection uses configured principals and the existing budget key derivation. Unavailable accounting returns `503 BUDGET_ACCOUNTING_UNAVAILABLE`; unknown workflows explicitly report no accounting state. The inert detection lab does not reserve these execution budgets. Configured credits are accounting units, not verified provider billing.

All governance endpoints require the existing admin bearer authentication and disable response caching:

```text
GET  /admin/governance
GET  /admin/governance/budget?subject=alice&tenant_id=tenant-a&agent_id=demo-agent&workflow_id=RETURNED_WORKFLOW_ID
POST /admin/governance/reload              {"kind":"policy"} or {"kind":"threat_feed"}
GET  /admin/governance/audit/export?limit=1000
```

The audit export downloads NDJSON summaries from a maximum 10,000-event bounded window (newest first), optionally filtered by `tenant_id` and `subject` within that window. It contains decisions, reason/rule IDs, revisions, identity, hashed resource/workflow identifiers, configured credit accounting and timings. It excludes raw prompts, excerpts, transformation details and arbitrary metadata. Headers state scanned/exported counts and scope. Full historical pagination is not claimed. PostgreSQL persistence is available in deployment mode; the local demo's bounded in-memory audit history clears on restart.

Verification: **27 focused Python tests passed**, including the new governance integration cases, observatory regression cases and atomic memory/Redis budget tests. The executable test wrapper also passed **27 Rego tests** and Ruff. **9 isolated Edge browser checks passed** with zero JavaScript page errors: authenticated navigation, controls, unknown workflow accounting, stale-scope clearing, actual reload success/rejection, bounded audit download and mobile layout. Governance-only browser validation used a disabled semantic provider and real OPA; it is not a new model-performance measurement. Evidence: `docs/final/governance-browser.json`; desktop/mobile screenshots: `artifacts/final/governance/`.
