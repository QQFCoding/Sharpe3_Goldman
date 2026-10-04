# Implementation guide

This directory is the runnable project root. Run its commands from here so relative policy, Docker, test, model and artifact paths resolve correctly. The original detailed [project README](README.md) and [historical reports](docs/) remain available.

## Code map

| Path | Responsibility |
|---|---|
| `app/main.py`, `app/api/` | FastAPI gateway and authenticated operation/operator endpoints |
| `app/core/` | Common transactions, authorization pipeline, identity, labels, workflows, execution/replay state and delegation |
| `app/controls/` | Deterministic scanning, privacy, reconstruction, network and tool checks |
| `app/semantic/` | Optional real classifiers and task-alignment integrations |
| `app/policy/`, `opa/` | Validated configuration snapshots, OPA client and Rego authorization |
| `app/adapters/` | Buffered model, MCP, network, tool and registered resource boundaries |
| `app/budget/`, `app/memory/`, `app/audit/` | Accounting, provenance-aware memory and audit storage |
| `app/telemetry/`, `observability/` | Prometheus/OpenTelemetry and provisioned Grafana/Tempo/PostgreSQL configuration |
| `app/client.py` | Async gateway client and explicit handling of denied/approval-required responses |
| `app/dashboard.*`, `cloud/` | Native dashboard and Streamlit presentation/runtime |
| `demo/` | Inert upstreams, scripted agent and reproducible showcase |
| `config/` | Policy, profiles, schemas, tool manifests, threat feeds, model locks and evaluation seeds |
| `scripts/` | Setup, launchers, tests, benchmarks, detector evaluation and validation |
| `tests/` | Unit, integration, concurrency, adversarial, evaluation and performance suites |
| `docs/` | Preserved phase/iteration reports, measured JSON, screenshots and license evidence |
| `Dockerfile`, `docker-compose.yml` | Container image and loopback demonstration stack |

## Fresh local setup

Python 3.12+ is required. From the repository root:

```powershell
cd 5-implementation
python scripts/bootstrap.py
.\.venv\Scripts\python.exe scripts\serve.py
```

Bootstrap creates `5-implementation/.venv`, installs the project and test dependencies, and downloads checksum-verified OPA 1.4.2 if absent. The default launcher needs no classifier weights or paid model API. Open `http://127.0.0.1:8000/dashboard` or the API reference at `http://127.0.0.1:8000/docs`.

In another terminal, from this directory:

```powershell
.\.venv\Scripts\python.exe scripts\judge_check.py
.\.venv\Scripts\python.exe scripts\judge_demo.py --semantic fixture
```

On Linux/macOS use `.venv/bin/python`. To run the real classifier demo:

```powershell
python scripts/bootstrap.py --semantic
.\.venv\Scripts\python.exe scripts\download_models.py --model deberta
.\.venv\Scripts\python.exe scripts\final_demo.py
```

The reviewed model is pinned/hash-verified; startup does not silently substitute fixtures. See [deployment and ecosystem integration](DEPLOYMENT.md) for persistent stores, authentication, Docker and adapter boundaries.

## Existing local environment after reorganization

An existing root `.venv` was preserved because virtual environments contain installation paths. You can reuse it from here by refreshing the editable install:

```powershell
..\.venv\Scripts\python.exe -m pip install --no-deps --no-build-isolation -e .
..\.venv\Scripts\python.exe scripts\judge_check.py
```

If the existing environment was created by uv and has no pip, use `uv pip install --offline --no-deps --no-build-isolation --python ../.venv/Scripts/python.exe -e .` to refresh the editable install instead. A fresh bootstrap-created environment includes pip.

Ignored local models, OPA tools, generated artifacts and caches were moved with the project; committed historical evidence was preserved. Existing environment variables, external startup commands and hosting entrypoints that named root-level source paths must use the new `5-implementation` paths. The repository-root Streamlit theme remains available for hosting; its copy here supports local launches.
