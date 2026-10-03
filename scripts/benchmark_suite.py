"""Isolated ASGI gateway + real OPA HTTP benchmark; production stores via explicit --redis-url."""
import argparse
import asyncio
import json
import os
import socket
import subprocess
import tempfile
import time
from pathlib import Path

import httpx
import yaml

from app.evaluation.fixtures import SafeAdapter
from app.evaluation.statistics import latency
from app.main import create_app
from app.semantic.deberta import DebertaProvider
from app.settings import ROOT, Settings


async def run(args):
    redis_container = None
    if args.mode == "concurrency" and not args.redis_url:
        import uuid
        redis_container = "aicl-benchmark-" + uuid.uuid4().hex[:12]
        subprocess.run(["docker", "run", "--rm", "-d", "--name", redis_container,
            "-p", "127.0.0.1::6379", "redis:7.4-alpine"], check=True, capture_output=True)
        endpoint = subprocess.check_output(["docker", "port", redis_container, "6379"], text=True).strip()
        args.redis_url = "redis://" + endpoint + "/0"
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    opa = subprocess.Popen([str(ROOT / ".tools" / ("opa.exe" if os.name == "nt" else "opa")),
        "run", "--server", f"--addr=127.0.0.1:{port}", "--disable-telemetry", "--log-level=error", str(ROOT / "opa")],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        async with httpx.AsyncClient(timeout=2) as ready:
            for _ in range(100):
                try:
                    response = await ready.get(f"http://127.0.0.1:{port}/health")
                    if response.status_code == 200:
                        break
                except httpx.HTTPError:
                    pass
                await asyncio.sleep(.05)
            else:
                raise RuntimeError("Owned OPA failed readiness")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            policy = yaml.safe_load((ROOT / "config/policy.yaml").read_text())
            policy["budgets"]["per_user"]["requests_per_minute"] = 100000
            policy["budgets"]["per_agent"]["concurrent_requests"] = args.concurrency
            (path / "policy.yaml").write_text(yaml.safe_dump(policy))
            (path / "threat-feed.yaml").write_bytes((ROOT / "config/threat-feed.yaml").read_bytes())
            settings = Settings(_env_file=None, policy_path=path / "policy.yaml", opa_url=f"http://127.0.0.1:{port}",
                redis_url=args.redis_url)
            app = create_app(settings)
            async with app.router.lifespan_context(app):
                runtime = app.state.runtime
                runtime.pipeline.adapters.update(mock=SafeAdapter(), mcp=SafeAdapter(tool=True))
                if args.mode == "semantic":
                    import torch
                    torch.set_num_threads(2)
                    runtime.pipeline.semantic = DebertaProvider(str(ROOT / "models/deberta"))
                    runtime.pipeline.semantic_timeout = 60
                    await asyncio.to_thread(runtime.pipeline.semantic._load)
                    # Single inference admission intentionally rejects simultaneous classifier jobs.
                durations, codes = [], []
                slots = asyncio.Semaphore(args.concurrency)
                async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://benchmark",
                        headers={"Authorization": "Bearer demo-other-token"}) as client:
                    async def request(index):
                        async with slots:
                            start = time.perf_counter()
                            response = await client.post("/v1/chat/completions", json={"messages": [
                                {"role": "tool" if args.mode == "semantic" else "user", "content": "Public summary request"}],
                                "workflow": {"workflow_id": "benchmark-" + str(index)}})
                            durations.append((time.perf_counter() - start) * 1000)
                            codes.append(response.status_code)
                    start = time.perf_counter()
                    await asyncio.gather(*(request(i) for i in range(args.samples)))
                    report = latency(durations, time.perf_counter() - start) | {
                        "mode": args.mode, "concurrency": args.concurrency,
                        "error_rate": sum(c >= 500 for c in codes) / len(codes),
                        "security_denial_rate": sum(400 <= c < 500 for c in codes) / len(codes),
                        "non_success_rate": sum(c != 200 for c in codes) / len(codes),
                        "budget_backend": "Redis Lua" if args.redis_url else "in-memory lock",
                        "boundary": "ASGI gateway + real OPA HTTP + inert upstream. No external HTTP transport or PostgreSQL. "
                            "Supply --redis-url for actual Redis contention. Policy is isolated; no running policy is changed."}
        output = Path(args.output or "artifacts/benchmark-" + args.mode + ".json")
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
    finally:
        opa.terminate()
        try:
            opa.wait(timeout=5)
        except subprocess.TimeoutExpired:
            opa.kill()
            opa.wait(timeout=5)
        if redis_container:
            subprocess.run(["docker", "stop", redis_container], check=True, capture_output=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["fast", "semantic", "concurrency"], default="fast")
    parser.add_argument("--samples", type=int, default=200)
    parser.add_argument("--concurrency", type=int)
    parser.add_argument("--redis-url")
    parser.add_argument("--output")
    args = parser.parse_args()
    args.concurrency = args.concurrency or (8 if args.mode == "concurrency" else 1)
    if not 1 <= args.samples <= 10000 or not 1 <= args.concurrency <= 64:
        parser.error("Bound samples to 1..10000 and concurrency to 1..64")
    asyncio.run(run(args))
