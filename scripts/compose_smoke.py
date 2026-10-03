"""Read and exercise the running Compose stack; creates only safe demo data."""

import json
import subprocess
import sys
import time
from pathlib import Path
from uuid import uuid4

import httpx

ROOT = Path(__file__).resolve().parents[1]


def compose(*args):
    return subprocess.run(
        ["docker", "compose", *args], cwd=ROOT, check=True, capture_output=True, text=True, timeout=30
    ).stdout.strip()


def eventually(check, seconds=45):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            value = check()
            if value:
                return value
        except (httpx.HTTPError, KeyError):
            pass
        time.sleep(0.5)
    raise AssertionError("Compose service did not become ready")


def main():
    with httpx.Client(
        base_url="http://127.0.0.1:8000", timeout=5, headers={"Authorization": "Bearer demo-user-token"}
    ) as client:
        eventually(lambda: client.get("/ready").status_code == 200)
        subprocess.run([sys.executable, "demo/agent.py"], cwd=ROOT, check=True, timeout=60)
        marker = "Safe Compose persistence note " + str(uuid4())
        response = client.post(
            "/v1/transactions",
            json={
                "operation": "memory_write",
                "payload": {"content": marker, "source": "application", "ttl_seconds": 120},
            },
        )
        assert response.status_code == 200, response.text
        memory_id = response.json()["output"]["memory_id"]
        read = client.post(
            "/v1/transactions", json={"operation": "memory_read", "payload": {"memory_id": memory_id}}
        )
        assert read.json()["output"]["content"] == marker, read.text

        # Exercise real Redis Lua concurrently using many distinct workflows for the same user.
        async def burst():
            import asyncio

            async with httpx.AsyncClient(
                base_url="http://127.0.0.1:8000",
                timeout=15,
                headers={"Authorization": "Bearer demo-other-token"},
            ) as async_client:
                results = await asyncio.gather(
                    *(
                        async_client.post(
                            "/v1/chat/completions",
                            json={"messages": [{"role": "user", "content": "Concurrent Redis demo"}]},
                        )
                        for _ in range(6)
                    )
                )
                assert any(r.status_code == 200 for r in results), [r.text for r in results]
                for result in results:
                    if result.status_code != 200:
                        assert (
                            result.status_code == 403
                            and "CONCURRENCY_LIMIT_EXCEEDED" in result.json()["security"]["reason_codes"]
                        ), result.text

        import asyncio

        asyncio.run(burst())
        audit_count = int(
            compose(
                "exec",
                "-T",
                "postgres",
                "psql",
                "-U",
                "aicl",
                "-d",
                "aicl",
                "-Atc",
                "SELECT count(*) FROM aicl_audit",
            )
        )
        memory_count = int(
            compose(
                "exec",
                "-T",
                "postgres",
                "psql",
                "-U",
                "aicl",
                "-d",
                "aicl",
                "-Atc",
                "SELECT count(*) FROM aicl_memory",
            )
        )
        assert audit_count > 0 and memory_count > 0
        keys = compose("exec", "-T", "redis", "redis-cli", "--scan", "--pattern", "aicl:budget:*")
        assert "aicl:budget:" in keys
        headers = {"Authorization": "Bearer demo-admin-token"}
        audit = client.get("/admin/audit", headers=headers).json()["events"]
        assert marker not in json.dumps(audit)
        metrics = client.get("/metrics", headers=headers)
        assert metrics.status_code == 200 and "aicl_budget_used_total" in metrics.text
    with httpx.Client(base_url="http://127.0.0.1:9090", timeout=5) as prom:
        eventually(
            lambda: any(
                t["health"] == "up" for t in prom.get("/api/v1/targets").json()["data"]["activeTargets"]
            )
        )

        def scraped_requests():
            value = prom.get("/api/v1/query", params={"query": "sum(aicl_requests_total)"}).json()["data"][
                "result"
            ]
            return value and float(value[0]["value"][1]) > 0

        eventually(scraped_requests)
    with httpx.Client(
        base_url="http://127.0.0.1:3000", auth=("admin", "local-demo-password"), timeout=5
    ) as grafana:
        dashboard = eventually(
            lambda: grafana.get("/api/dashboards/uid/aicl-security").json().get("dashboard")
        )
        assert len(dashboard["panels"]) == 18
        assert {s["uid"] for s in grafana.get("/api/datasources").json()} == {"prometheus", "tempo"}
        trace_id = next(event["trace_id"] for event in audit if event["phase"] == "final")
        eventually(
            lambda: (
                grafana.get(
                    f"/api/datasources/proxy/uid/tempo/api/traces/{trace_id}",
                    headers={"Accept": "application/json"},
                ).status_code
                == 200
            )
        )
    print(
        f"Compose smoke passed: PostgreSQL {audit_count} audit events/{memory_count} memories, Redis Lua, Prometheus, 18 Grafana panels."
    )


if __name__ == "__main__":
    main()
