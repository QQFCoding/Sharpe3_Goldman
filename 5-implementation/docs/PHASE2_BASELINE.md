# Phase 2 baseline

Baseline commit: `540c87029ebdfbf8f82f68b288d1b436d0e4b54e`.

Before editing runtime code, inspected core, controls, adapters, semantic providers,
policy/Rego, memory, audit, telemetry, tests, configuration and dashboard provisioning.

- `python scripts/test.py`: 90 Python tests passed; actual OPA 20/20; Ruff passed.
- Compose: all ten services running; gateway, Redis and PostgreSQL healthy.
- Ten-request HTTP/OPA/mock-upstream baseline: p50 22.65 ms, p95/p99 30.19 ms.
  This small deterministic-path sample is not a production performance claim.

Identified gaps: no authoritative cross-request data-flow lattice; no immutable
workflow intent; no delegated credentials/capability attenuation; no MCP manifest
pin; real classifier weights untested; dashboard lacks SQL investigation/filtering;
stage telemetry incomplete. Preserve existing operation/schema/approval/budget
behavior while extending these contracts.
