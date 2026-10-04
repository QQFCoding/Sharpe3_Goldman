# 1 — Solution

AI Control Layer is an enforcement gateway between an agent and its models, tools, APIs, other agents and memory. It authenticates requests, turns them into a common security transaction, inspects input, reserves workflow resources and asks OPA/Rego for authorization before dispatch. It buffers and inspects upstream output before returning it.

Deterministic scanners produce findings; optional real classifiers produce risk signals. **OPA makes the authorization decision.** Only `ALLOW`, `REDACT` and `WARN` permit dispatch. `BLOCK`, `REQUIRE_APPROVAL`, `QUARANTINE` and `TERMINATE` stop dispatch. Missing or malformed OPA responses fail closed. Semantic unavailability follows the configured failure policy.

The default demonstration uses inert model/tool services and needs no paid API. The optional DeBERTa demonstration uses a real, pinned classifier. The useful issue-triage agent is a scripted integration example; its mock summarizer does not establish autonomous model utility.

## Implemented controls and guardrails

| Control | Enforced behavior | Implementation |
|---|---|---|
| Authentication and scopes | Server-owned identity, tenant and capabilities; bearer authentication and optional RS256 JWT validation | [Authentication](../5-implementation/app/core/auth.py), [JWT](../5-implementation/app/core/jwt_auth.py) |
| Protocol and schema validation | Strict operation/tool schemas, bounded bodies, duplicate/non-finite JSON rejection and input/output projections | [Schema](../5-implementation/app/controls/schema.py), [MCP protocol](../5-implementation/app/adapters/mcp_protocol.py) |
| Prompt-injection rules | Pattern/context checks, normalized Unicode, bounded decoding and message/field reconstruction | [Controls](../5-implementation/app/controls/), [rule detector](../5-implementation/app/controls/prompt_patterns.py) |
| Semantic inspection | Real local classifiers or Ollama signals; review/block thresholds; timeout, busy and unavailable handling | [Semantic providers](../5-implementation/app/semantic/) |
| Secret protection | Blocks credentials, private keys, connection strings and reconstructed secrets on input/output | [Secret scanner](../5-implementation/app/controls/secrets.py) |
| PII protection | Configurable redaction/blocking of email, phone, IP, payment/identity/account formats; checksum checks where supported | [PII scanner](../5-implementation/app/controls/pii.py) |
| Model/tool/API permissions | Allowlists, deny lists, registered effects, argument checks and exact-operation approvals for mutations | [Tool firewall](../5-implementation/app/controls/tool_firewall.py), [Rego](../5-implementation/opa/) |
| Network restrictions | DNS/IP checks, redirect validation and loopback/private/link-local/reserved-address blocking | [SSRF control](../5-implementation/app/controls/ssrf.py), [network adapter](../5-implementation/app/adapters/network.py) |
| Provenance and information flow | Persistent trust/classification labels, protected-data egress checks and review of untrusted mutations | [Information flow](../5-implementation/app/controls/information_flow.py), [labels](../5-implementation/app/core/labels.py) |
| Memory isolation | Tenant/owner authorization, TTL, scanning before writes/after reads and poisoned-record quarantine | [Memory service](../5-implementation/app/memory/service.py) |
| Workflow and delegation | Immutable registered intent, optional task-alignment signals, capability attenuation and delegation-depth limits | [Workflows](../5-implementation/app/core/workflows.py), [delegation](../5-implementation/app/core/delegation.py) |
| MCP supply-chain checks | Server identity, capability credentials, pinned manifests and drift blocking | [MCP adapter](../5-implementation/app/adapters/mcp.py), [manifests](../5-implementation/app/adapters/manifests.py) |
| Replay and approval protection | One-use approvals bound to the exact request and durable execution identities; uncertain mutations cannot be retried as new effects | [Execution store](../5-implementation/app/core/executions.py) |
| Resource budgets | Atomic credits/tokens, steps, calls, depth, time, rate and concurrency admission; actual-usage reconciliation | [Budget manager](../5-implementation/app/budget/manager.py) |
| Threat intelligence | Reloadable bounded-time signatures and trusted tool/package/hash/server indicators | [Feed loader](../5-implementation/app/threatintel/loader.py) |
| Audit and observability | Privacy-safe authorization/final audit events, metrics, traces and authenticated operator views | [Audit](../5-implementation/app/audit/), [reporting](../3-reporting/README.md) |

## Configuration and enforceable policies

The active configuration is [policy.yaml](../5-implementation/config/policy.yaml), validated against [policy.schema.json](../5-implementation/config/policy.schema.json). Rego authorization lives in [opa](../5-implementation/opa/). Runtime settings are documented in [.env.example](../5-implementation/.env.example) and [settings.py](../5-implementation/app/settings.py).

| Policy area | Current default/example |
|---|---|
| Unknown resources | Deny unknown models and tools |
| PII / secrets | PII input/output `REDACT`; secrets input/output `BLOCK` |
| Allowed tools | Read/search operations such as `github.search`, `github.read_issue`, `filesystem.read`, `network.fetch` and selected server-qualified variants |
| Mutation approvals | `github.create_issue`, `filesystem.write`, `email.send` and the configured internal issue-creation tool |
| Explicit denial | `shell.exec`, `github.delete_repository` |
| Semantic failure | `block_high_risk`; alternatives are `block_all` or explicit `warn` |
| Semantic thresholds | General review/block `0.50 / 0.85`; DeBERTa override `0.30 / 0.9999991655349731` |
| Scan eligibility | High-risk/untrusted/suspicious requests; `always_scan: false` |
| Agent budgets | 25 steps, 20 LLM calls, 20 tool calls, depth 8, 120 seconds, 100,000 tokens, 100 credits, concurrency 4 |
| User rate | 60 requests/minute |
| Payload/token limits | 65,536 bytes per request/response; 16,000 input and 2,048 output tokens |
| Memory | Tenant isolation, scan on write/read, injection quarantine, maximum TTL 86,400 seconds |
| Information flow | Untrusted-to-mutating action requires approval; no default declassification grants |
| MCP / delegation | Block manifest changes; attenuate capabilities; maximum delegation depth 4 |
| Audit | `store_raw_prompts: false` |

The default semantic provider is `none`. Setting a policy control to enabled does not load a model. Select `AICL_SEMANTIC_PROVIDER=deberta`, `prompt_guard` or `ollama`, install its dependencies and configure the reviewed model/upstream separately. Task-alignment configuration is present, but its runtime provider is also disabled by default.

[Strict, balanced and permissive profiles](../5-implementation/config/profiles/README.md) provide complete enforce-mode configurations. Strict blocks PII, always scans and uses smaller budgets; balanced redacts PII with selective inference; permissive raises resource allowances and review thresholds. All retain secret blocking, tenant boundaries, resource restrictions and mutation approvals. These profiles are operating examples, with no claim of newly calibrated model quality.

Operators can reload policy or threat-feed configuration through authenticated `POST /admin/governance/reload` with `{"kind":"policy"}` or `{"kind":"threat_feed"}`. Every material policy edit needs a new `metadata.revision`; invalid reloads preserve the previous snapshot. Policy and adjacent feed files are validated together. Provider choice, model paths, identity/storage settings and upstream URLs require a restart.

See [architecture and measurements](../2-architecture/README.md), [showcase cases](../4-testing/README.md) and [deployment/integration](../5-implementation/DEPLOYMENT.md) for the enforcement path, evidence and supported integration boundaries.
