# AI Control Layer

A local-first enforcement gateway for LLM requests, agent messages, MCP/tool calls, read-only API calls, and memory. Python scanners produce security facts; **OPA/Rego makes the authorization decision**. Only ALLOW, REDACT, and WARN reach an upstream. Blocked, unapproved, quarantined, and terminated requests never invoke a provider or tool.

The demo needs no paid API or model download. It uses safe mock services: file, shell, GitHub, network, and email MCP tools only return simulated results. The semantic providers are optional real integrations, not heuristic scanners presented as AI.

## Run locally

Python 3.12+ is required. From this directory:

```powershell
python scripts/bootstrap.py
.\.venv\Scripts\python.exe scripts\serve.py
```

In another terminal:

```powershell
.\.venv\Scripts\python.exe demo\agent.py
.\.venv\Scripts\python.exe scripts\test.py
```

On Linux/macOS, use `.venv/bin/python` in place of `.venv\Scripts\python.exe`. You can also activate the virtual environment and use `make dev`, `make test`, or `make demo`. Bootstrap downloads OPA **1.4.2**, verifies its published SHA-256 checksum, and creates an isolated Python environment. Startup itself does not download models.

Gateway/API documentation: http://127.0.0.1:8000/docs. All local launcher services bind to loopback. Ctrl+C stops the launcher and its child services.

For a self-contained check that starts and stops its own local services:

```powershell
.\.venv\Scripts\python.exe scripts\smoke.py
```

## Run with Docker

```sh
docker compose up --build -d
python demo/agent.py
docker compose ps
```

Compose runs the gateway, OPA, Redis, PostgreSQL, mock LLM, mock MCP, Prometheus, Grafana, OpenTelemetry Collector, and Tempo. Redis and PostgreSQL persist in project-scoped volumes. Grafana automatically provisions the Security dashboard and both data sources.

| Service | Local address | Demo authentication |
|---|---|---|
| Gateway | http://127.0.0.1:8000 | Bearer `demo-user-token` (Alice, tenant A) or `demo-other-token` (Bob, tenant B) |
| Admin API and metrics | http://127.0.0.1:8000/admin/policy | Bearer `demo-admin-token` |
| Grafana dashboard | http://127.0.0.1:3000/d/aicl-security | `admin` / `local-demo-password` |
| Prometheus | http://127.0.0.1:9090 | Loopback demo |

Stop the stack with `docker compose down`. This preserves database volumes. Demo credentials are public and are suitable only for this loopback demo. If you change `AICL_ADMIN_TOKEN`, also change the Prometheus scrape credential in `observability/prometheus.yml`.

## Protected operations

`POST /v1/transactions` accepts the common operation format:

```json
{
  "operation": "mcp_tool_call",
  "resource": {"name": "github.search"},
  "payload": {"query": "least privilege"},
  "workflow": {"workflow_id": "my-workflow"}
}
```

The supported operations are `llm_request`, `mcp_tool_call`, `tool_call`, `api_call`, `memory_read`, `memory_write`, and `agent_message`. `llm_response` is represented internally for integrations; callers cannot submit it as an execution request. Effects, identities, provenance, risk, and budget facts come from server-side adapters and stores. Request bodies cannot inject those facts.

`POST /v1/chat/completions` accepts `model`, `provider` (`mock` or `ollama`), `messages`, `max_tokens`, `workflow`, and an optional `approval_token`. Successful responses include chat choices and a security envelope. Streaming is disabled so output inspection completes before any content is returned. The API implements the buffered chat subset rather than every OpenAI API feature.

`POST /v1/mcp` implements the demo JSON-RPC `tools/list` and `tools/call` subset. Arguments use strict JSON schemas, including `additionalProperties: false`. Tool names, effects, scopes, and the upstream MCP endpoint come from the server registry. This is not a complete MCP transport/session implementation.

Every execution response includes an explainable decision:

```json
{
  "security": {
    "decision": "BLOCK",
    "reason_codes": ["SECRET_DETECTED"],
    "controls": ["secret-scanner"],
    "policy_revision": "dev-001",
    "threat_feed_revision": "local-001",
    "risk": {"prompt_injection": 0, "data_exfiltration": 0, "tool_misuse": 0, "semantic_status": "not_required"},
    "transformations": [],
    "request_id": "..."
  },
  "output": null
}
```

HTTP statuses: allowed/redacted/warned = 200; approval needed = 409; blocked/quarantined = 403; terminated = 429; authentication failed = 401; invalid schema = 422; oversized transport body = 413. Quarantine may return a record ID and status, never the poisoned content.

## Enforcement path

1. Authenticate and validate the wire protocol; reject oversized/ambiguous JSON.
2. Normalize into `SecurityTransaction`; enforce schema, byte/token bounds, signatures, secrets, PII, and network checks.
3. Supply registered tool metadata and authoritative memory ownership/provenance to OPA.
4. Atomically reserve credits, tokens, call counts, steps, depth, rate, concurrency, and workflow time.
5. Skip semantic inference for deterministic denials. Scan eligible high-risk requests; validate numeric model signals.
6. Ask OPA for the final decision. Apply redactions and atomically consume any exact-operation approval.
7. Persist the authorization audit event and atomically mark execution started before invoking the upstream.
8. Buffer and inspect the complete output, reconcile actual usage, persist the final audit, and record metrics/traces.

OPA has no Python authorization fallback. An unavailable or malformed OPA response blocks execution. Redis/storage failures also block. The in-memory backends are for single-process demos/tests; deployment mode requires shared Redis and PostgreSQL.

Secret controls cover synthetic API keys, bearer tokens, GitHub tokens, AWS access identifiers, private keys, password/secret assignments, and connection strings, plus keyed entropy checks. PII controls cover emails, international phone numbers, IPv4/IPv6, cards with Luhn checks, PESEL checksums, and basic IBAN length/mod-97 validation for PL/GB/DE/FR/ES/IT/NL. Detection uses practical patterns and checksums, not a guarantee of complete data classification.

The network guard parses targets, checks normalized IPs (including IPv4-mapped IPv6), rejects ambiguous numeric hosts and non-HTTP schemes, validates **all** DNS answers, and revalidates redirects. The read-only `api_call` adapter uses a transport that pins the connection to an approved IP while preserving Host and TLS SNI. In demo mode that operation is simulated through mock MCP; deployment mode enables the guarded real HTTP GET adapter. Operator-configured provider/MCP service URLs are trusted infrastructure, outside user-controlled fetch targets.

## Policy and feed reload

Edit `config/policy.yaml` or `config/threat-feed.yaml`, then call `POST /admin/policy/reload` or `POST /admin/threat-feed/reload` with the admin bearer token. Both validate and publish the policy/feed pair atomically. Invalid YAML, unknown keys, invalid ranges, overlapping tool lists, duplicate rule IDs, or invalid regexes leave the active snapshot untouched. Each in-flight transaction uses its original snapshot through output inspection.

`GET /admin/policy` shows the active snapshot and previous known-good revision. `config/policy.schema.json` is generated from the same Pydantic types used by the loader. Policy changes require a new revision so outstanding approvals become invalid. Feed rules support bounded-time regex matching, tool identifiers, package/version metadata, artifact hashes, and MCP server IDs. Metadata indicators require facts from trusted adapters; clients cannot supply inventory metadata.

To demonstrate a new signature: send a benign marker (e.g. `new historical marker`), append a feed rule matching that marker, increment the feed revision, reload, and send the same request. It now blocks without a restart. `tests/integration/test_gateway.py` verifies this sequence and failed reload rollback.

## Approvals

An admin can issue a five-minute, one-use approval with `POST /admin/approvals`:

```json
{
  "subject": "alice",
  "tenant_id": "tenant-a",
  "request": {
    "operation": "mcp_tool_call",
    "resource": {"name": "github.create_issue"},
    "payload": {"title": "Demo", "body": "Safe mock issue"},
    "workflow": {"workflow_id": "approval-demo"}
  }
}
```

Send the exact same operation, including the workflow, with the returned `approval_token`. The digest binds the principal, tenant, agent, operation, effect, normalized arguments, resource, workflow, and policy revision. Atomic consumption prevents concurrent replay. Approvals cannot bypass denied tools, destructive/code-execution restrictions, scopes, semantic blocking, tenant boundaries, or budgets. With the default failure policy, an approved high-risk mutation still blocks if no semantic provider is available.

## Semantic providers

The fast path avoids model inference. Untrusted retrieved content (`role: tool`), untrusted memory writes, restricted resources, suspicious patterns, high-risk tools, or `always_scan` can trigger the slow path. External/web/agent memory is always untrusted. Marking application memory trusted also requires the server-granted `memory:trusted_write` scope.

The default is `AICL_SEMANTIC_PROVIDER=none` and `semantic_failure: block_high_risk`. The app starts and ordinary chat/read operations remain functional. High-risk operations fail closed when inspection is required. `block_all` and explicit `warn` modes are also available in policy. Tests inject semantic signals to exercise policy outcomes without needing model weights. Safe demo mock outputs are trusted fixtures; deployment MCP/tool outputs default to untrusted and receive semantic inspection. Operators can explicitly configure `AICL_MCP_OUTPUT_TRUST` for a trusted internal server.

For [Llama Prompt Guard 2 86M](https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M): install `.[semantic]`, obtain access to its gated weights and accept its license, then download an explicitly reviewed model commit:

```sh
python scripts/download_models.py --revision <hugging-face-commit-sha>
```

Set `AICL_SEMANTIC_PROVIDER=prompt_guard` and `AICL_PROMPT_GUARD_PATH=./models/prompt-guard`. Loading is local-only. The provider scans overlapping 512-token windows and rejects incompatible classifier shapes. Timed-out inference remains a single background job; subsequent requests fail closed while it is busy.

For optional Ollama:

```sh
docker compose --profile semantic up -d ollama
docker compose exec ollama ollama pull qwen3:4b
```

Set `AICL_SEMANTIC_PROVIDER=ollama` and restart the gateway (`docker compose up -d gateway`). The default model is Qwen3 4B; `AICL_OLLAMA_MODEL=phi4-mini` selects the fallback after pulling it. The provider requests JSON matching a strict numeric risk schema. Malformed JSON, prose, extra fields, non-finite scores, or timeouts produce an unavailable signal; Rego applies the configured failure behavior. Provider choice is an environment setting, not part of policy hot reload. No model can authorize an action.

## Budget, memory, and telemetry

Redis Lua atomically admits a maximum reservation and checks all workflow limits. Input-token estimates use UTF-8 byte counts as a conservative tokenizer-independent bound. Local resource prices are configurable by model and tool. On execution start, the maximum charge becomes provisional usage; reconciliation refunds the unused amount and detects overruns. Unstarted abandoned reservations expire and release capacity. A worker that crashes after starting an action retains the maximum charge, preventing expiry from becoming a free-execution loophole. A failed/unknown upstream execution conservatively charges its reservation.

Attempted calls/steps and request rates count security denials conservatively. Workflow keys include tenant, subject, agent, and workflow ID. Parent depths are derived from stored request lineage, so a caller cannot reset a child's depth to zero. Per-user rate limits and per-agent concurrency limits span workflows. An agent creating new workflow IDs can still start new workflows; persistent application session/workflow assignment is an integration responsibility.

Memory records store tenant, owner, creator, source, trust, classification, security labels, content, timestamps, TTL, and quarantine status. Reads are tenant-scoped before returning content; Rego checks owner and scopes. Writes and retrieved outputs are scanned. Poisoned records are quarantined only after access authorization; cross-tenant content is never quarantined on an attacker's behalf.

Audit events store hashes instead of prompts, both authorization and final decisions, policy/feed revisions, semantic scores, reserved/consumed credits, trace IDs, and stage latency. Unregistered resource names are hashed to prevent secret-bearing names from entering audit storage. Quarantined memory content is retained in the memory store, separately from the audit trail. `GET /admin/audit` provides bounded recent events.

Prometheus exposes requests, exclusive final decisions and triggering controls, OPA/semantic/request latency histograms, injections, secret blocks, PII redactions, tools, budget use/rejections, terminations, quarantines, and threat-rule hits. Grafana shows decision ratios, security counters, budget use, p50/p95/p99 latency, and top blocked tools/signatures. Tempo receives trace spans through the collector. Traces contain identifiers and decisions, never prompts or arguments.

`python scripts/benchmark.py` writes `artifacts/benchmark.json`. The measurement includes HTTP, OPA, and the safe mock upstream; it is not a real-model latency benchmark. `make test` runs actual Rego tests, Ruff, and Python tests including concurrency tests against the Redis Lua scripts via fakeredis. `python scripts/compose_smoke.py` checks the running Compose stack, PostgreSQL persistence, Redis state, metrics scraping, and Grafana provisioning.

## Deployment boundaries

This is a production-oriented prototype with a runnable hackathon demo. To use deployment mode, set `AICL_DEMO_MODE=false`, configure Redis/PostgreSQL, provide an admin token of at least 24 characters, and supply an `AICL_AUTH_FILE` JSON list of `{token_sha256, principal}` records. Provision scopes server-side and protect the auth/config files. TLS termination, enterprise identity federation, database migration/retention management, encryption of memory/evidence, approval UI, egress isolation, and real provider/tool integrations remain deployment work. Basic startup does not provision those systems automatically.

Buffered inspection prevents leaking partial output. It cannot undo a side effect an already authorized upstream performed before its response was blocked, a deadline expired, or an audit finalization failed. The durable pre-execution audit and conservative budget charging preserve evidence and accounting in those cases. Disable direct access to protected upstreams in a deployed network; clients must route their operations through the gateway.

Rego policies live in `opa/`; scanner and transport protocols are independent of FastAPI. These boundaries allow replacing the Python data plane later without changing the canonical transaction or policy contract. Regenerate the policy schema and dashboard with `python scripts/generate_assets.py` after changing their source definitions.
