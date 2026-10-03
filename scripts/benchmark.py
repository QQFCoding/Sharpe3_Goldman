import argparse
import json
import math
import statistics
import time
from pathlib import Path

import httpx


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1:8000")
    parser.add_argument("--samples", type=int, default=10)
    parser.add_argument("--output", default="artifacts/benchmark.json")
    args = parser.parse_args()
    durations = []
    with httpx.Client(
        base_url=args.url, headers={"Authorization": "Bearer demo-other-token"}, timeout=30
    ) as client:
        for _ in range(args.samples):
            started = time.perf_counter()
            response = client.post(
                "/v1/chat/completions", json={"messages": [{"role": "user", "content": "Benchmark"}]}
            )
            response.raise_for_status()
            durations.append((time.perf_counter() - started) * 1000)
    ordered = sorted(durations)

    def percentile(q):
        return ordered[max(0, math.ceil(q * len(ordered)) - 1)]

    report = {
        "samples": args.samples,
        "path": "HTTP gateway + OPA HTTP + safe mock LLM; deterministic fast path",
        "p50_ms": statistics.median(durations),
        "p95_ms": percentile(0.95),
        "p99_ms": percentile(0.99),
    }
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))


if __name__ == "__main__":
    main()
