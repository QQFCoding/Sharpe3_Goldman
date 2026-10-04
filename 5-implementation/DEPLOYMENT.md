# Deployment and existing agent ecosystems

Run installation, launchers, tests and Docker Compose from this directory. The gateway supports buffered chat, canonical transactions, a demo MCP JSON-RPC subset, agent messages, network operations and memory. Integrations must route each protected model/tool action through those endpoints and consume only permitted output.

## Local Docker demonstration

```text
python scripts/mcp_demo_credentials.py
docker compose up --build -d
python demo/agent.py
docker compose ps
```

[Compose](docker-compose.yml) provisions OPA, Redis, PostgreSQL, mock LLM/MCP services, isolated capability-scoped MCP demo servers, Prometheus, Grafana, OpenTelemetry collector and Tempo. Published ports bind loopback. `docker compose down` stops the stack and preserves database volumes. This configuration uses public demo credentials and inert upstream tools.

The default [Docker image](Dockerfile) excludes heavy semantic dependencies/model weights. A real-classifier image must install the semantic dependencies and mount the reviewed local weights. Select a provider explicitly and check its availability before relying on semantic inspection.

## Connect an existing agent or orchestrator

1. Give the application a server-provisioned identity/scopes and a stable workflow ID. Register immutable workflow intent if the application uses that control.
2. Send supported model calls to `POST /v1/chat/completions`. Send tool, MCP, API, memory and agent operations to `POST /v1/transactions`; use `POST /v1/mcp` only for the implemented JSON-RPC subset.
3. Register tool schemas, effects, server identities, upstream credentials and output trust on the gateway. Client-supplied metadata must not determine authority or trust.
4. Handle every security decision. On `REQUIRE_APPROVAL`, present the exact operation to a separate operator client. Resume only with its bound approval token. Retain the same execution ID across retries; do not bypass an uncertain result with direct upstream execution.
5. Preserve gateway provenance/protected-value receipts across retrieval, summaries, memory and agent handoffs where supported. Route downstream steps through the gateway as well.
6. Configure network paths so protected upstreams are reachable only through the gateway; instrument the application to retain request/workflow IDs for audit correlation.

The built-in [ControlClient](app/client.py) provides a small async integration:

```python
import asyncio
from app.client import ControlClient, tool_request

async def main():
    async with ControlClient("http://127.0.0.1:8000", "demo-user-token") as gateway:
        summary = await gateway.chat("Summarize public issue status", workflow_id="triage-1")
        print(summary.require_output()["content"])

        request = tool_request("github.search", {"query": "checkout"}, "triage-1")
        issues = await gateway.transaction(request)
        print(issues.require_output()["result"])

asyncio.run(main())
```

An existing framework can wrap its model client and tool executor with this API boundary. There are no claims of universal, built-in framework plugins. The [integration guide](docs/INTEGRATION.md), [scripted useful agent](demo/useful_agent.py) and [showcase](demo/judge_showcase.py) show the actual contract. Chat supports a buffered subset rather than every OpenAI API feature; streaming and complete MCP transport/session support are not implemented.

## Persistent deployment configuration

Set `AICL_DEMO_MODE=false`, provide shared `AICL_REDIS_URL` and `AICL_DATABASE_URL`, a distinct `AICL_ADMIN_TOKEN` of at least 24 characters, and an `AICL_AUTH_FILE` containing server-provisioned token-hash/principal records. Optional JWT verification settings are in [settings.py](app/settings.py). Protect identity/configuration files and upstream credentials; grant only application-required scopes.

Configure `AICL_POLICY_PATH`, model/tool upstream URLs, MCP server/credential registries, semantic provider/model paths and telemetry destination. Use [policy profiles](config/profiles/README.md) as reviewed starting examples and set application-specific resource limits. Policy/feed actions reload atomically; provider/store/authentication/upstream environment changes require restart.

TLS termination, enterprise federation, database migrations/retention, memory/evidence encryption, approval UI integration and service egress isolation remain deployment work. In-memory stores support single-process demonstrations. Production accounting and execution state require shared backends and operational recovery procedures.

## Architecture and implementation considerations

- Python scanners and adapters produce facts; OPA remains the authorization authority with no Python authorization fallback.
- Semantic failure is explicit policy behavior. A configured but unavailable provider provides no semantic protection; task-alignment review is disabled by default.
- Buffered output scanning prevents partial-output disclosure. It cannot undo a side effect already performed by an authorized upstream. The pre-execution audit, execution tombstone and conservative accounting preserve evidence in uncertain outcomes.
- Sensitive real adapters must validate scope, resource roots, symlinks and platform-specific paths before side effects. The demonstration's inert tools do not establish the safety of arbitrary real tools.
- Logical model timeouts cannot cancel a running Torch thread. Review admission limits, worker capacity, shared-store failure behavior and model resource requirements for the deployment.
- Saved classification reports retain known misses and failed gates. The prior real AgentDyn result of 0/5 benign tasks remains unresolved; a successful scripted demo does not replace that measurement.

## Streamlit hosting entrypoint

The entrypoint relative to the **repository root** is now `5-implementation/cloud/streamlit_app.py`. Its neighboring requirements file remains [cloud/requirements.txt](cloud/requirements.txt). For local commands in this directory the entrypoint stays `cloud/streamlit_app.py`. Root and local `.streamlit/config.toml` copies preserve the theme in both launch contexts.

Hosted standalone mode is an opt-in, ephemeral demonstration with real OPA/DeBERTa and inert upstreams. Persistent frontend mode connects to an existing gateway. See the updated [Streamlit guide](docs/STREAMLIT-DEPLOY.md); no new public deployment is claimed by this reorganization.
