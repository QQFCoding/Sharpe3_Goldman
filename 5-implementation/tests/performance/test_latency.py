import json
import statistics
import time

import pytest

from tests.conftest import chat_body


@pytest.mark.performance
async def test_fast_path_performance_report(running, tmp_path):
    client, runtime = running
    latencies = []
    for _ in range(10):
        started = time.perf_counter()
        response = await client.post("/v1/chat/completions", json=chat_body("Benchmark request"))
        assert response.status_code == 200
        latencies.append((time.perf_counter() - started) * 1000)
    report = {
        "backend": "real OPA CLI; fake upstream; deterministic fast path",
        "samples": len(latencies),
        "p50_ms": statistics.median(latencies),
        "p95_ms": sorted(latencies)[-1],
        "max_ms": max(latencies),
    }
    (tmp_path / "latency.json").write_text(json.dumps(report, indent=2))
    print(json.dumps(report))
    assert not runtime.pipeline.semantic.calls
    assert max(latencies) < 10000  # Catch deadlocks/timeouts, not machine-specific microbenchmarks.
