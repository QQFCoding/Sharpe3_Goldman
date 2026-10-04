# Phase 2 security hardening

## Enforcement contract

The gateway treats the connected model as potentially compromised. Authentication,
capabilities, information flow, OPA decisions, approvals and budgets are external
to that model. Output inspection supplements pre-execution authorization.

`DataSecurityLabel` carries integrity, confidentiality, server source/owner/tenant,
provenance and taints. Confidentiality is joined, never overwritten by derived
content. Summarization changes integrity to `derived` but preserves
`untrusted_origin`. Memory retains the label and authorized reads restore it.
MCP/tool/API output adds server-assigned source trust. Agent messages carry
server identity/delegation/workflow metadata and retain the workflow label.

Shared Redis state atomically joins workflow labels. Protected exposure is also
retained per tenant/subject, across workflow IDs and agents acting for that subject.
This deliberately conservative rule prevents laundering by starting a new
workflow or transforming a literal value. It can block unrelated outbound work
after a protected read; explicit scoped declassification is the escape hatch.
Exposure/intent retention is 24 hours. Integrations must preserve provenance
outside that lifetime and protect routes to upstreams; arbitrary untracked data
copied through external applications cannot be reconstructed by this prototype.

Before external/mutating sinks, OPA blocks private/secret confidentiality unless
the policy explicitly declassifies that classification for the exact sink and the
authenticated identity has the required scope. Approval is not declassification.
Read-only GitHub searches are also sinks because query arguments leave the gateway.
Untrusted influence on destructive/code execution is blocked. Untrusted influence
on ordinary mutations requires approval by default. Existing unconditional
destructive-tool denial remains stronger than semantic review.

Example operator policy (not enabled by default):

```yaml
information_flow:
  enabled: true
  untrusted_to_mutating: REQUIRE_APPROVAL
  declassification:
    - sinks: [github.create_issue]
      classifications: [private]
      required_scope: data:declassify
```

## Immutable intent and alignment

An authenticated root identity with `workflow:intent` registers `POST /v1/workflows`:

```json
{"workflow_id":"issue-task","goal":"Create a public documentation issue",
 "allowed_effects":["external_side_effect"],"allowed_resources":["github.create_issue"]}
```

Registration is atomic and immutable during retention. Delegated agents cannot
register/rewrite it. User-declared intent never grants capabilities: normal scopes,
tool allowlists, approvals, budgets and data-flow policy still apply.
OPA deterministically checks allowed effects/resources. Optional `TaskAlignmentGuard`
uses local Ollama to assess goal relationship, deviation, exfiltration intent,
unexpected effects and confidence. Strict numeric output is only a risk signal.
High-confidence deviation blocks; uncertain high-impact actions require approval;
uncertain reads follow policy. An unavailable reviewer abstains. Injection-provider
unavailability independently follows the existing fail-closed policy.

Set `AICL_ALIGNMENT_PROVIDER=ollama` to enable the actual integration. Live Ollama
alignment inference was not measured in this run. Regression tests use explicit
reviewer fixtures; those are never represented as real model evaluation.
`python scripts/task_alignment_eval.py` evaluates illustrative real local Ollama
cases when a model is available. The heavier model is outside the fast path.

## Delegation, manifests and authentication

`POST /v1/delegations` issues a five-minute opaque credential. Child scopes and
resource capabilities must both be subsets of the parent. Tenant and subject are
inherited; roles are removed. Credentials bind workflow, parent/delegator and depth.
OPA also checks current depth/peer policy on every request. Redis shares credentials
across workers. This is a local delegation demo, not a complete revocation service.

The checked-in MCP manifest pins server, name, description/schema hashes, effect,
scopes and approved version. The adapter compares `tools/list` before execution.
Description/version drift follows configured WARN/approval/BLOCK; changed schema,
effect, scopes or server always blocks. The manifest hash binds approval tokens.
Pin updates are operator-reviewed configuration changes, not automatic discovery.
The sample MCP protocol includes effect/scope/version metadata; external servers
need an adapter supplying that trusted inventory contract.

Local JWT verification uses only operator-provided public RS256 JWKS. It verifies
issuer, audience, expiry/issued-at, subject, tenant and agent, then bounds token scopes
by the configured identity. Token roles are ignored; remote key URLs and algorithm
confusion are rejected. Generate a local key/token using
`python scripts/jwt_demo.py --generate`. Private keys remain ignored. Restart the
demo gateway after replacing JWKS; use the returned token immediately (five-minute
expiry). Deployment JWKS requires explicit configuration.

`make security-scan` inventories the active environment and matches a small synthetic
offline advisory example. It is not a comprehensive vulnerability scan or an
all-clear. `make update-threat-feed` optionally queries OSV for explicit dependencies;
its advisory artifact is separate from runtime attack signatures.

Injection uncertainty on read effects follows
`controls.prompt_injection.semantic.uncertain_read`: ALLOW, WARN, or REQUIRE_APPROVAL.
The default remains REQUIRE_APPROVAL to preserve existing behavior. Uncertain
mutations still require approval; this setting cannot bypass a high-risk block.

## Real semantic evaluation and calibration

Setup is explicit and never occurs during startup or normal unit tests:

```sh
python scripts/bootstrap.py --semantic
python scripts/download_models.py --model deberta
make semantic-eval
```

The public model is
[ProtectAI DeBERTa v2](https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2),
pinned to `e6535ca4ce3ba852083e75ec585d7c8aeb4be4c5`. The 737,719,272-byte safetensors
file is verified against SHA-256
`6521cb8d0ac08148c81464899c424e6148fcc62befa371089fa4061d8b6e0424`.
Inference is CPU/local-only with overlapping windows, no remote model code and
bounded concurrent inference. The optional gated Prompt Guard runner remains available
with `--provider prompt_guard --path models/prompt-guard`. Gated weights were not
downloaded. No comparison claims are made for unmeasured candidates.

The original corpus has 60 cases: 30 calibration and 30 held-out, spanning fifteen
categories, English/Polish/mixed language, indirect sources, obfuscation and long
input. Wording does not overlap between splits. Mutation variants are evaluated
separately. This small corpus is illustrative, not a generalization guarantee.

Calibration selected block threshold **0.9999991655349731**, maximizing F1 with a
calibration false-positive rate <=10%. Raw scores were heavily saturated: thresholds
0.3–0.99 yielded 26.7% calibration FPR. The selected threshold reduced it to 6.7%,
at the cost of recall. Scores are not calibrated attack probabilities. The precision
of this fitted threshold does not imply production stability; re-evaluate a larger
deployment corpus before using it. Scores >=0.30 below the block threshold abstain
for review. Only the DeBERTa profile uses this threshold; existing providers retain
their previous defaults.

Held-out results: accuracy **80%**, precision **100%**, recall **60%**, F1 **0.75**,
FPR **0%**, FNR **40%**, AUROC **0.9444**, average precision **0.9568**. Six malicious
cases were missed. Model-only enforcement is therefore insufficient.
The 60-case run used two CPU threads, about 944 MB process RSS, p50 136.6 ms,
p95 3610.6 ms, p99 4815.9 ms. Long overlapping inputs dominate the tail.
Reports include load time separately and per-category/language results.
The held-out Polish attack was missed; there were only two Polish cases, so no
multilingual robustness claim is supported.

`make redteam` runs bounded gateway/static/mutation/paired scenarios with inert tools.
`make redteam-semantic` adds the real classifier. Reports separate input detection
from prohibited sink execution. With real semantics, all 30 benign fixture tasks
completed; all 44 transformed-private-data sink attempts were blocked, including
missed injections. **40.9% of malicious prompts still reached the inert LLM fixture.**
Zero prohibited sink executions is an IFC test result, not universal attack immunity.
Utility under attack is measured on two paired poison/recovery tasks only.
Regex/classifier/combined detection ablations are reported separately; alignment-only
measurements require the real optional reviewer and explicitly report not measured
when it is absent. Full AgentDojo/InjecAgent integration and LLM-generated adaptive
attacks are not included; the checked-in finite mutator is reproducible offline.
Offline classifier ablations score every case; the gateway's selective scanning
policy scans eligible cases only. Those detection rates have different boundaries.
With no classifier installed, fail-closed handling reduced benign fixture completion
to 86.7%; the four unavailable-review denials are counted in the false-block metric.

## SOC dashboard and performance

Grafana provisions Prometheus, Tempo and a restricted PostgreSQL role/view. Nine rows
cover overview, attacks, agents, semantics, budgets, policy, performance, events and
traces. An idempotent Compose initialization job provisions the role for existing
Phase 1 database volumes as well as fresh installations.
Eleven SQL filters include tenant, agent, workflow, operation, decision,
control, tool, reason, semantic status and both revisions. SQL quoting protects
variable interpolation. Workflow identifiers are hashed in audit storage.

All SQL panels honor filters. Prometheus stage/aggregate panels are explicitly marked
global: tenant/agent/workflow/request/trace identifiers are not metric labels.
Safe event tables link trace IDs to Tempo. Seven local alerts need no external
notification account. Revision gauges and reload success/failure counters expose
configuration changes. Traces record safe stage names and identifiers, not payloads.

Live validation executed 21 SQL panels and all eleven variable queries through Grafana,
verified tenant/agent/BLOCK filtering, fetched a linked Tempo trace, checked datasource
health, and confirmed provisioned alerts. Browser rendering could not be inspected
because this session had no available browser provider.

Commands:

```sh
make up
make test
make semantic-eval
make benchmark-fast
make benchmark-semantic
make benchmark-concurrency
make redteam
make redteam-semantic
make demo
python scripts/compose_smoke.py
python scripts/grafana_validate.py
python scripts/phase2_live_smoke.py
```

Benchmarks use 200 requests, isolated policy settings, real OPA HTTP, ASGI gateway and
inert upstreams. Concurrency mode creates/removes its own actual Redis container;
other modes use the in-memory budget backend unless `--redis-url` is supplied.
They report throughput, duration, p50/p95/p99, server errors and security denials
separately. These are not full external-HTTP/PostgreSQL or production-load measurements.
The legacy HTTP benchmark remains available for the running Compose stack.

| Mode, 200 requests | p50 ms | p95 ms | p99 ms | Requests/sec |
|---|---:|---:|---:|---:|
| Fast path, concurrency 1 | 10.46 | 14.48 | 18.90 | 91.53 |
| Real classifier, concurrency 1 | 353.38 | 1205.31 | 1354.18 | 2.29 |
| Redis Lua, concurrency 8 | 104.39 | 141.30 | 166.08 | 72.28 |

All three runs completed without server errors or security denials. Measurements
are local Windows CPU results; they support no production throughput guarantee.

Full reports stay in ignored `artifacts/`; small measurement summaries are checked in
under `docs/measurements.json`. Original tests remain, with new IFC, delayed/mutated
attacks, delegation, manifest, alignment, JWT, dashboard and metric coverage.
Optional P2 processing/trace graphs/hash chaining are intentionally not part of this phase.
