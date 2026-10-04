# 4 — Testing and showcase cases

The executable suite is kept with the runnable project in [5-implementation/tests](../5-implementation/tests/). Rego policy tests are in [opa/tests](../5-implementation/opa/tests/). This section maps review scenarios to their demonstrations and regression coverage.

The post-reorganization [validation record](VALIDATION.md) reports 439 Python tests, 27 Rego tests, Ruff and all eight fixture showcase scenarios passing. The portable [showcase results](showcase-results.json) include the observed decisions and dispatch counts.

## Run the showcase

Run these commands from `5-implementation` after the [setup](../5-implementation/IMPLEMENTATION.md):

```text
python scripts/judge_check.py
python scripts/judge_demo.py --semantic fixture
```

The first command runs real OPA tests, Ruff and the Python suite. The second exercises a real gateway/OPA with explicitly labeled semantic fixtures and inert upstream services, writing `artifacts/judge-showcase.json`. It requires no model download. For the real pinned DeBERTa showcase, install semantic dependencies/weights and run:

```text
python scripts/judge_demo.py
```

The eight scripted scenarios demonstrate useful public issue triage, injection blocking, exact-operation approval, changed-argument/replay rejection, the three operating profiles, live budget tightening and rejected reload rollback. The task is scripted, with one local mock issue created after approval.

## Test cases the solution can showcase

| Case | Traffic/action | Expected enforcement | Executable evidence |
|---|---|---|---|
| Benign request | Public chat or registered issue search | Permitted output and audit event | [Gateway tests](../5-implementation/tests/integration/test_gateway.py), [judge showcase](../5-implementation/demo/judge_showcase.py) |
| Prompt injection | Authority override or secret-exfiltration instructions | `BLOCK` before upstream dispatch | [Gateway tests](../5-implementation/tests/integration/test_gateway.py), [adversarial corpus](../5-implementation/tests/adversarial/) |
| Reconstructed injection/secret | Encoded or split fragments form hostile instructions/credentials | Bounded reconstruction detects covered forms; privacy pre-pass withholds sensitive evidence | [Iteration 3 tests](../5-implementation/tests/unit/test_iteration3_detection.py), [final detection tests](../5-implementation/tests/unit/test_final_detection.py) |
| Direct secret | Synthetic credential in input/output | `BLOCK`; no permitted secret-bearing output | [Gateway tests](../5-implementation/tests/integration/test_gateway.py) |
| PII | Email/phone/account/identity values in input/output | Configured `REDACT` or stricter independent policy decision | [Gateway tests](../5-implementation/tests/integration/test_gateway.py), [controls tests](../5-implementation/tests/unit/test_controls.py) |
| Denied tool | `shell.exec` or repository deletion | `BLOCK`, including with an approval attempt | [Tool controls](../5-implementation/tests/integration/test_gateway.py), [profiles](../5-implementation/tests/integration/test_judge_showcase.py) |
| Mutation approval | `github.create_issue` with an execution ID | `REQUIRE_APPROVAL`; only exact approved operation may execute once | [Replay/binding tests](../5-implementation/tests/integration/test_phase3.py), [judge showcase](../5-implementation/tests/integration/test_judge_showcase.py) |
| Approval mismatch/replay | Changed arguments, identity, revision or reused token | Refusal with no second side effect | [Gateway tests](../5-implementation/tests/integration/test_gateway.py), [Phase 3 tests](../5-implementation/tests/integration/test_phase3.py) |
| Unknown model/resource | Unregistered model or tool | Default denial | [Gateway tests](../5-implementation/tests/integration/test_gateway.py) |
| SSRF | Private/loopback/link-local destination or unsafe redirect | Network restriction before protected fetch | [Adapter tests](../5-implementation/tests/unit/test_adapters.py), [controls tests](../5-implementation/tests/unit/test_controls.py) |
| Cross-tenant memory | Read another tenant's record | Refusal before returning content | [Memory scenarios](../5-implementation/tests/integration/test_gateway.py) |
| Poisoned memory | Authorized access to injection-bearing stored content | `QUARANTINE`; poisoned content withheld | [Memory scenarios](../5-implementation/tests/integration/test_gateway.py) |
| Protected-data egress | Confidential memory propagated to external tool/search/agent | Information-flow denial or configured approval without trust escalation | [Provenance tests](../5-implementation/tests/integration/test_phase2.py) |
| MCP manifest drift | Changed server/tool schema or metadata after pinning | `BLOCK` before dispatch | [MCP tests](../5-implementation/tests/integration/test_phase3.py) |
| Budget/rate/concurrency | More steps/calls/credits/tokens/time/depth than allowed | Denied admission or `TERMINATE`; no overspend from concurrent admission | [Budget tests](../5-implementation/tests/concurrency/test_budgets.py), [governance](../5-implementation/tests/integration/test_governance.py) |
| Live configuration | Valid revised policy/feed, then invalid replacement | Valid revision takes effect; invalid reload preserves active configuration | [Reload tests](../5-implementation/tests/integration/test_governance.py) |
| Dependency failure | OPA outage, storage failure or invalid semantic signal | OPA/storage fail closed; semantic failure follows explicit policy | [Chaos tests](../5-implementation/tests/integration/test_chaos_security.py), [gateway tests](../5-implementation/tests/integration/test_gateway.py) |
| Reporting privacy | Secret in resource/exception or arbitrary evidence | Audit/traces do not expose raw sensitive input | [Audit tests](../5-implementation/tests/integration/test_gateway.py), [export tests](../5-implementation/tests/integration/test_governance.py) |

Tests use upstream spies to assert that blocked requests never dispatch. Semantic fixtures isolate policy contracts; they do not measure real-model accuracy. SSRF/tool behavior is exercised within the controlled adapters rather than performing destructive actions against external systems.

## Detector-quality and performance checks

```text
python -m scripts.self_test --robustness
python scripts/robustness_eval.py --corpus v3 --output artifacts/submission-v3.json --name submission-v3
python scripts/paired_detection_performance.py
```

These require the installed real model and can take minutes. The saved iteration 3 reports record passing implementation checks alongside failed detection-quality gates. Gate failures must remain visible; a fixture showcase is not a substitute for the real-model evaluations. [Architecture measurements](../2-architecture/README.md) distinguish latency, classification quality and service capacity.

For manual inspection, launch `python scripts/final_demo.py`, open `http://127.0.0.1:8012/dashboard` and use its example requests. The detection lab is inspect-only; use the judge showcase for end-to-end dispatch/approval evidence. [Judge guide](../5-implementation/docs/JUDGE-GUIDE.md) documents operator workflows and scoped budget inspection.
