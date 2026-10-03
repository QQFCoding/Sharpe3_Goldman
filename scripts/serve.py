"""Launch OPA, safe mock services, and the gateway on loopback; Ctrl+C stops the group."""

import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

from bootstrap import install_opa

ROOT = Path(__file__).resolve().parents[1]


def main():
    opa = install_opa()
    env = os.environ.copy()
    env.setdefault("AICL_OPA_URL", "http://127.0.0.1:8181")
    flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    commands = [
        [
            str(opa),
            "run",
            "--server",
            "--addr=127.0.0.1:8181",
            "--log-level=error",
            "--disable-telemetry",
            str(ROOT / "opa"),
        ]
    ]
    for module, port in [("demo.mock_llm:app", 8081), ("demo.mock_mcp:app", 8082), ("app.main:app", 8000)]:
        commands.append(
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
        )
    processes = []
    try:
        for command in commands:
            processes.append(subprocess.Popen(command, cwd=ROOT, env=env, creationflags=flags))
        for _ in range(100):
            if any(p.poll() is not None for p in processes):
                raise RuntimeError("A service exited. Check ports 8000, 8081, 8082, and 8181.")
            try:
                urllib.request.urlopen("http://127.0.0.1:8000/ready", timeout=1).close()
                break
            except OSError:
                time.sleep(0.1)
        else:
            raise RuntimeError("Gateway did not become ready")
        print("Gateway http://127.0.0.1:8000/docs | run: python demo/agent.py", flush=True)
        while all(p.poll() is None for p in processes):
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
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
