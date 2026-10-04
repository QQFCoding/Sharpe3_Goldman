# AI Control Layer

An enforcement gateway for agent model calls, tools, MCP, APIs, agent messages and memory. Deterministic controls and optional real classifiers supply security facts; OPA/Rego authorizes each protected operation.

This repository follows the five-section submission structure:

For a single detailed reading guide covering all five sections, open [PROJECT-OVERVIEW.md](PROJECT-OVERVIEW.md).

| Section | Contents |
|---|---|
| [1-solution](1-solution/README.md) | Approach, implemented controls and enforceable policy configuration |
| [2-architecture](2-architecture/README.md) | Architecture diagram and separately reported rule/model performance |
| [3-reporting](3-reporting/README.md) | Dashboard screenshots and the implemented metric inventory |
| [4-testing](4-testing/README.md) | Showcase cases, expected decisions and executable test/evaluation commands |
| [5-implementation](5-implementation/IMPLEMENTATION.md) | Runnable code, setup, implementation considerations and deployment into existing agent ecosystems |

```text
1-solution/
  README.md
2-architecture/
  README.md
  architecture.mmd
3-reporting/
  README.md
  METRICS.md
  screenshots/
4-testing/
  README.md
5-implementation/
  IMPLEMENTATION.md
  DEPLOYMENT.md
  README.md
  app/  config/  opa/  demo/  cloud/
  tests/  scripts/  observability/  docs/
  pyproject.toml  requirements.lock
  Dockerfile  docker-compose.yml  Makefile
```

All setup, launcher, test and Docker commands run from **`5-implementation`**. The original detailed README and historical reports are preserved there. Saved performance and screenshot evidence retains its original measurement scope; reorganizing the repository does not constitute a new detector benchmark.

## Run locally

Python 3.12+:

```powershell
cd 5-implementation
python scripts/bootstrap.py
.\.venv\Scripts\python.exe scripts\serve.py
```

Open http://127.0.0.1:8000/dashboard. In another terminal, from `5-implementation`:

```powershell
.\.venv\Scripts\python.exe scripts\judge_check.py
.\.venv\Scripts\python.exe scripts\judge_demo.py --semantic fixture
```

The default demo uses inert upstreams and requires no paid API or model download. The fixture showcase exercises real OPA enforcement without claiming real-model accuracy. For the pinned DeBERTa showcase, follow the [implementation guide](5-implementation/IMPLEMENTATION.md).

Existing checkouts can retain their root `.venv`; refresh its editable install after moving the code, as described in the implementation guide. Docker Compose now lives in `5-implementation`. The repository-relative Streamlit entrypoint is `5-implementation/cloud/streamlit_app.py`.

[Deployment and ecosystem integration](5-implementation/DEPLOYMENT.md) describes supported protocol subsets, persistent storage, authentication, approvals and remaining deployment work.
