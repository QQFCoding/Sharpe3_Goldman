PYTHON ?= python
.PHONY: bootstrap dev test demo up down
bootstrap:
	$(PYTHON) scripts/bootstrap.py
dev:
	$(PYTHON) scripts/serve.py
test:
	$(PYTHON) scripts/test.py
demo:
	$(PYTHON) demo/agent.py --isolated
	$(PYTHON) scripts/phase2_demo.py
	$(PYTHON) scripts/phase3_demo.py
up:
	$(PYTHON) scripts/mcp_demo_credentials.py
	docker compose up --build -d
	docker compose restart opa
down:
	docker compose down

semantic-eval:
	$(PYTHON) scripts/semantic_eval.py
task-alignment-eval:
	$(PYTHON) scripts/task_alignment_eval.py
download-model:
	$(PYTHON) scripts/download_models.py --model deberta
redteam:
	$(PYTHON) scripts/redteam.py
redteam-semantic:
	$(PYTHON) scripts/redteam.py --semantic
security-scan:
	$(PYTHON) scripts/security_scan.py
update-threat-feed:
	$(PYTHON) scripts/update_advisories.py --package fastapi --package httpx
benchmark-fast:
	$(PYTHON) scripts/benchmark_suite.py --mode fast
benchmark-semantic:
	$(PYTHON) scripts/benchmark_suite.py --mode semantic
benchmark-concurrency:
	$(PYTHON) scripts/benchmark_suite.py --mode concurrency
benchmark-agent-security:
	$(PYTHON) scripts/agent_security_benchmark.py
chaos-security:
	$(PYTHON) scripts/chaos_security.py
verify-policy:
	$(PYTHON) scripts/verify_policy.py
semantic-profile:
	$(PYTHON) scripts/semantic_profile.py
