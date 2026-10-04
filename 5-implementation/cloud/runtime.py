"""Opt-in loopback-only real detector runtime for a hosted Streamlit demonstration.

Starts owned processes only; no remote backend, model fallback or external tool
side effects. The model remains pinned and hash-verified. State is ephemeral.
"""
import argparse
import atexit
import hashlib
import json
import os
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
MODEL_SHA256 = "6521cb8d0ac08148c81464899c424e6148fcc62befa371089fa4061d8b6e0424"


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def stop_owned_process(child):
    if child.poll() is not None:
        return
    if os.name == "nt":
        subprocess.run(["taskkill", "/PID", str(child.pid), "/T", "/F"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW)
    else:
        # Every process started here owns its own session. Never target a user's group.
        try:
            os.killpg(child.pid, signal.SIGTERM)
        except ProcessLookupError:
            return
    try:
        child.wait(timeout=5)
    except subprocess.TimeoutExpired:
        if os.name != "nt":
            os.killpg(child.pid, signal.SIGKILL)
        else:
            child.kill()
        child.wait(timeout=5)


@dataclass
class CloudRuntime:
    url: str
    admin_token: str = field(repr=False)
    children: list = field(repr=False)
    temporary: object = field(repr=False)
    log_handle: object = field(repr=False)
    model_sha256: str = MODEL_SHA256
    mode: str = "hosted-demo; in-memory state; inert upstreams"

    @property
    def token(self):
        return self.admin_token

    def health(self) -> dict:
        states = [child.poll() is None for child in self.children]
        ready = False
        if all(states):
            try:
                with urllib.request.urlopen(self.url + "/ready", timeout=2) as response:
                    body = json.load(response)
                    ready = response.status == 200 and body.get("semantic_provider") == "deberta" and body.get("semantic_state") == "ready"
            except (OSError, urllib.error.URLError):
                pass
        return {"ready": ready, "owned_processes_running": sum(states), "process_count": len(states),
                "semantic_provider": "deberta", "model_sha256": self.model_sha256, "mode": self.mode}

    def stop(self):
        for child in reversed(self.children):
            stop_owned_process(child)
        self.log_handle.close()
        self.temporary.cleanup()

    close = stop


def ensure_model(log_handle, download=True):
    weights = ROOT / "models/deberta/model.safetensors"
    required = ["config.json", "tokenizer_config.json", "spm.model"]
    valid = False
    if weights.is_file():
        with weights.open("rb") as handle:
            valid = hashlib.file_digest(handle, "sha256").hexdigest() == MODEL_SHA256
    if not valid or any(not (weights.parent / name).is_file() for name in required):
        if not download:
            raise RuntimeError("Pinned model unavailable or corrupt; run python scripts/download_models.py --model deberta")
        # Explicit hosted-mode opt-in permits the existing pinned downloader.
        subprocess.run([sys.executable, str(ROOT / "scripts/download_models.py"), "--model", "deberta"],
            cwd=ROOT, stdout=log_handle, stderr=log_handle, timeout=1800, check=True)
    with weights.open("rb") as handle:
        if hashlib.file_digest(handle, "sha256").hexdigest() != MODEL_SHA256:
            raise RuntimeError("Pinned detector checksum verification failed; no fallback is permitted")


def start_cloud_runtime() -> CloudRuntime:
    if os.environ.get("AICL_CLOUD_STANDALONE", "").lower() != "true":
        raise RuntimeError("Hosted runtime requires explicit AICL_CLOUD_STANDALONE=true")
    return start_demo()


def start_demo(*, gateway_port=None, opa_port=None, llm_port=None, mcp_port=None,
               token=None, download=True) -> CloudRuntime:
    from scripts.bootstrap import install_opa

    ports = []
    for configured in (gateway_port, opa_port, llm_port, mcp_port):
        port = configured if configured is not None else free_port()
        while configured is None and port in ports:
            port = free_port()
        if not 1024 <= port <= 65535 or port in ports:
            raise ValueError("Each demo service needs a distinct unprivileged port")
        with socket.socket() as probe:
            try:
                probe.bind(("127.0.0.1", port))
            except OSError as error:
                raise RuntimeError(f"Port {port} is occupied; existing services are never stopped") from error
        ports.append(port)
    gateway_port, opa_port, llm_port, mcp_port = ports

    directory = ROOT / ".tools/cloud"
    directory.mkdir(parents=True, exist_ok=True)
    log_handle = (directory / "runtime.log").open("a", encoding="utf-8")
    temporary = tempfile.TemporaryDirectory(prefix="runtime-", dir=directory)
    children = []
    runtime = None
    try:
        ensure_model(log_handle, download=download)
        opa = install_opa()
        policy = Path(temporary.name) / "policy.yaml"
        shutil.copyfile(ROOT / "config/profiles/balanced.yaml", policy)
        shutil.copyfile(ROOT / "config/threat-feed.yaml", policy.parent / "threat-feed.yaml")
        config = yaml.safe_load(policy.read_text(encoding="utf-8"))
        config["threat_intelligence"]["source"] = str(policy.parent / "threat-feed.yaml")
        policy.write_text(yaml.safe_dump(config, sort_keys=False), encoding="utf-8")
        token = token or secrets.token_urlsafe(32)
        env = {k: v for k, v in os.environ.items() if not k.startswith("AICL_")}
        env.update(AICL_CLOUD_ADMIN_TOKEN=token, AICL_CLOUD_POLICY_PATH=str(policy),
                   AICL_CLOUD_LLM_URL=f"http://127.0.0.1:{llm_port}",
                   AICL_CLOUD_MCP_URL=f"http://127.0.0.1:{mcp_port}", PYTHONIOENCODING="utf-8")
        commands = [
            [str(opa), "run", "--server", f"--addr=127.0.0.1:{opa_port}", "--log-level=error",
             "--disable-telemetry", str(ROOT / "opa")],
            [sys.executable, "-m", "uvicorn", "demo.showcase_services:llm_app", "--host", "127.0.0.1",
             "--port", str(llm_port), "--no-access-log"],
            [sys.executable, "-m", "uvicorn", "demo.showcase_services:mcp_app", "--host", "127.0.0.1",
             "--port", str(mcp_port), "--no-access-log"],
            [sys.executable, "-m", "cloud.runtime", "--gateway-child", "--port", str(gateway_port),
             "--opa-port", str(opa_port)],
        ]
        for command in commands:
            options = {"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {"start_new_session": True}
            children.append(subprocess.Popen(command, cwd=ROOT, env=env, stdout=log_handle,
                stderr=log_handle, **options))
        runtime = CloudRuntime(f"http://127.0.0.1:{gateway_port}", token, children, temporary, log_handle)
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            if any(child.poll() is not None for child in children):
                raise RuntimeError("Hosted detector process exited; inspect .tools/cloud/runtime.log")
            if runtime.health()["ready"]:
                atexit.register(runtime.stop)
                return runtime
            time.sleep(0.25)
        raise RuntimeError("Real detector startup timed out; hosted demo is unavailable")
    except Exception:
        if runtime is not None:
            runtime.stop()
        else:
            for child in reversed(children):
                stop_owned_process(child)
            log_handle.close()
            temporary.cleanup()
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gateway-child", action="store_true")
    parser.add_argument("--port", type=int)
    parser.add_argument("--opa-port", type=int)
    args = parser.parse_args()
    if not args.gateway_child:
        parser.error("Use start_cloud_runtime() from the Streamlit server")
    import uvicorn

    from app.main import create_app
    from app.settings import Settings
    settings = Settings(_env_file=None, demo_mode=True, policy_path=Path(os.environ["AICL_CLOUD_POLICY_PATH"]),
        admin_token=os.environ["AICL_CLOUD_ADMIN_TOKEN"], semantic_provider="deberta", semantic_preload=True,
        semantic_cpu_threads=2, opa_url=f"http://127.0.0.1:{args.opa_port}", redis_url=None, database_url=None,
        auth_file=None, mcp_servers_path=None, jwt_jwks_path=None, alignment_provider="none", otlp_endpoint=None,
        llm_url=os.environ["AICL_CLOUD_LLM_URL"], mcp_url=os.environ["AICL_CLOUD_MCP_URL"])
    uvicorn.run(create_app(settings), host="127.0.0.1", port=args.port, access_log=False)


if __name__ == "__main__":
    main()
