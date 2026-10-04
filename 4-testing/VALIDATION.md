# Repository reorganization validation

Validated locally on **2026-10-04**, after moving the runnable project to `5-implementation`.

| Check | Result |
|---|---|
| Real OPA policy tests | 27/27 passed |
| Ruff | Passed |
| Python implementation suite | 439 passed; 0 failures/errors/skips; 155.97 seconds |
| Isolated gateway/OPA fixture showcase | 8/8 scenarios passed |
| Submission-document links | All 113 local links resolved |
| Prometheus metric documentation | All 27 defined metric names covered |
| Architecture diagram | Embedded Mermaid matches standalone source |
| Docker Compose configuration | `docker compose config --quiet` completed successfully |
| Existing tracked files | All 281 tracked paths accounted for at their retained or relocated paths |
| Ignore rules | Relocated model weights, OPA tools, generated artifacts, credentials and local secrets remain ignored |

Commands were run from `5-implementation`, reusing the existing root Python environment after refreshing its editable install:

```powershell
..\.venv\Scripts\python.exe scripts\judge_check.py
..\.venv\Scripts\python.exe scripts\judge_demo.py --semantic fixture --output artifacts/repository-reorganization-showcase.json
docker compose config --quiet
```

The implementation-suite JUnit report is generated at `5-implementation/artifacts/judge-check.xml`. The full local showcase output is `5-implementation/artifacts/repository-reorganization-showcase.json`; its portable scenario summary is [showcase-results.json](showcase-results.json).

The showcase uses the actual OPA executable and original gateway/upstream HTTP handlers, with semantic fixtures and inert tools. It asserts attack blocking before dispatch, exact-operation approval/replay behavior, policy-profile effects, budget exhaustion and invalid-reload rollback. It is not a new real-model accuracy, latency, browser or production-deployment measurement. The architecture/reporting sections identify preserved historical evidence separately.
