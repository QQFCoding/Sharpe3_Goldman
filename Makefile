PYTHON ?= python
.PHONY: bootstrap dev test demo up down
bootstrap:
	$(PYTHON) scripts/bootstrap.py
dev:
	$(PYTHON) scripts/serve.py
test:
	$(PYTHON) scripts/test.py
demo:
	$(PYTHON) demo/agent.py
up:
	docker compose up --build -d
down:
	docker compose down
