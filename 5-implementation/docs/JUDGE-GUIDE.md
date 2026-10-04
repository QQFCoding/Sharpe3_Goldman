# Judge workflow

The final demonstration combines a real gateway and OPA policy engine with the pinned DeBERTa detector and inert upstream services. Its issue-triage agent is a deterministic task script: it searches two public issue records, reads their content, asks a local deterministic summarizer for a report, and creates one issue in an in-memory mock tracker after exact-operation operator approval. No GitHub, email, file, shell or external network action is performed. This demonstrates useful integration and enforcement, not autonomous AgentDyn benchmark improvement.

## Prepare and run

From `5-implementation` (the runnable project root), use the Python environment described in the README. On a fresh machine:

```text
python scripts/bootstrap.py --semantic
python scripts/download_models.py --model deberta
```

Activate the resulting `.venv` before the remaining commands. The downloader pins the reviewed model commit and verifies the weight SHA-256. The model is approximately 738 MB; download and first-load time are excluded from steady-state request latency.

```text
python scripts/judge_check.py
python scripts/judge_demo.py
```

`judge_check.py` runs real Rego tests, lint and all Python implementation tests. The control tests use explicit semantic fixtures where appropriate. It does **not** claim detector accuracy or require the long model corpus. `judge_demo.py` uses real DeBERTa by default and writes `artifacts/judge-showcase.json`. Its eight scenarios prove:

1. Useful issue triage completes through gateway adapters and creates one local report.
2. An injection/exfiltration request is blocked before a tool is dispatched.
3. A mutation requires operator approval; changed arguments are refused and replay has no second side effect.
4. Strict, balanced and permissive policy files reload and preserve hard destructive-operation denial. Each report includes the configured PII action and actual final verdict, including independent semantic reviews.
5. Editing the policy to two workflow steps, incrementing its revision and reloading allows two operations, then terminates the third before upstream dispatch.
6. Invalid configuration is rejected while the previous active revision remains enforced.

For a fast fixture-only demonstration, `python scripts/judge_demo.py --semantic fixture` is explicitly labeled fixture evidence. It must not be substituted for the real detector demonstration. No running user services are stopped or changed; the showcase uses isolated ASGI HTTP handlers and an actual OPA executable, with temporary policy files under `.tools`.

The longer detector-quality command is separate:

```text
python -m scripts.self_test --robustness
```

Its gates are frozen. A failure is a reported remaining detection limitation, not a reason to relax thresholds to make the test green. Read the latest measurement report for current recall, false-positive and latency results.

## Interactively inspect the running gateway

Start the final local demo command from the README. Open its native dashboard and use its operator token to inspect live requests, grouped findings, Policy & budgets, effective controls and latency. The Streamlit presentation is an additional interface to the same enforcement layer. The dashboard's inspect-only lab does not dispatch tools; use the useful-agent command or isolated judge showcase when assessing end-to-end execution.

```text
python -m demo.useful_agent --url http://127.0.0.1:8010
```

This network-facing agent never obtains an admin token. It returns a public summary and the exact pending request when approval is required. The isolated judge command demonstrates the complete operator-approved flow. An operator can also inspect and approve that exact request using the authenticated API; see [integration](INTEGRATION.md).

In Policy & budgets, select `alice / tenant-a / demo-agent` and paste the returned `triage-<UUID>` or `budget-<UUID>` workflow ID. Budget accounting is per exact identity and workflow. API equivalent:

```text
GET /admin/governance/budget?subject=alice&tenant_id=tenant-a&agent_id=demo-agent&workflow_id=<returned workflow ID>
```

## Demonstrate a live configuration change

Use an isolated configured policy copy. Keep `threat-feed.yaml` next to it. Review `config/profiles/README.md`, copy the chosen profile into that configured `policy.yaml`, and set a unique revision for subsequent edits. In Policy & budgets click Reload policy, or call:

```text
POST /admin/governance/reload
Authorization: Bearer <operator token>
Content-Type: application/json

{"kind":"policy"}
```

Compare active revision, PII actions, effective provider thresholds and remaining budget. Existing workflows retain their consumption; a lowered limit does not erase usage. Repeat the public PII input and a denied `shell.exec` call. A final decision can be stricter than a single configured control action. Attempt invalid YAML and verify that the active revision remains unchanged.

The isolated judge command executes the equivalent file-edit/reload/budget sequence automatically and records decision reasons. The network demo's active policy path should be read from its launcher; editing the main repository policy has no effect on an isolated copy.

## Scope and delivery limits

Hosted standalone mode is explicitly opt-in (`AICL_CLOUD_STANDALONE=true`), uses real pinned DeBERTa/OPA on loopback, and starts only inert tools. Its state is shared in-memory demonstration state and is lost on restart. Host resource limits can prevent the real model starting; this must be shown as unavailable rather than replaced with a fake detector. Operator audit/reload controls require the configured operator credential. Production deployment requires shared Redis/PostgreSQL, real identities, upstream authentication and appropriate network isolation.

The prior AgentDyn benign utility result remains a separate, unresolved result unless a new benchmark is actually run. A successful scripted triage does not replace that measurement. License and deployment validation evidence are provided separately in the final report.
