"""Start owned local services, exercise their real HTTP paths, then shut them down."""

import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
from bootstrap import install_opa

ROOT = Path(__file__).resolve().parents[1]


def main():
    ports = [8000, 8081, 8082, 8181]
    for port in ports:
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", port))
    flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    env = {
        **os.environ,
        "AICL_OPA_URL": "http://127.0.0.1:8181",
        "AICL_DEMO_MODE": "true",
        "AICL_LLM_URL": "http://127.0.0.1:8081",
        "AICL_MCP_URL": "http://127.0.0.1:8082",
        "AICL_SEMANTIC_PROVIDER": "none",
    }
    env.pop("AICL_OPA_BINARY", None)
    env.pop("AICL_REDIS_URL", None)
    env.pop("AICL_DATABASE_URL", None)
    commands = [
        [
            str(install_opa()),
            "run",
            "--server",
            "--addr=127.0.0.1:8181",
            "--log-level=error",
            "--disable-telemetry",
            str(ROOT / "opa"),
        ]
    ]
    commands += [
        [
            sys.executable,
            "-m",
            "uvicorn",
            module,
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--no-access-log",
        ]
        for module, port in [("demo.mock_llm:app", 8081), ("demo.mock_mcp:app", 8082), ("app.main:app", 8000)]
    ]
    processes = []
    artifacts = ROOT / "artifacts"
    artifacts.mkdir(exist_ok=True)
    with (artifacts / "smoke-services.log").open("w") as log:
        try:
            for command in commands:
                processes.append(
                    subprocess.Popen(command, cwd=ROOT, env=env, stdout=log, stderr=log, creationflags=flags)
                )
            with httpx.Client(base_url="http://127.0.0.1:8000", timeout=1) as client:
                for _ in range(100):
                    if any(p.poll() is not None for p in processes):
                        raise RuntimeError("A service exited; inspect artifacts/smoke-services.log")
                    try:
                        if client.get("/ready").status_code == 200:
                            break
                    except httpx.HTTPError:
                        pass
                    time.sleep(0.1)
                else:
                    raise RuntimeError("Gateway readiness timeout")
            for script in ["demo/agent.py", "scripts/benchmark.py"]:
                subprocess.run([sys.executable, script], cwd=ROOT, env=env, check=True)
            print("Live HTTP smoke test passed; all owned services will stop.")
        finally:
            for p in reversed(processes):
                if p.poll() is None:
                    p.terminate()
            for p in processes:
                try:
                    p.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    p.kill()


if __name__ == "__main__":
    main()
