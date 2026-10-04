"""Owned real-model gateway, inert issue tracker, native UI and optional Streamlit.

All services bind loopback. Existing services are never stopped or reused.
"""
import argparse
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8012)
    parser.add_argument("--opa-port", type=int, default=8188)
    parser.add_argument("--llm-port", type=int, default=8091)
    parser.add_argument("--mcp-port", type=int, default=8092)
    parser.add_argument("--streamlit", action="store_true")
    parser.add_argument("--streamlit-port", type=int, default=8502)
    args = parser.parse_args()
    ports = [args.port, args.opa_port, args.llm_port, args.mcp_port]
    if args.streamlit:
        ports.append(args.streamlit_port)
    if len(set(ports)) != len(ports) or any(not 1024 <= p <= 65535 for p in ports):
        parser.error("Use distinct ports between 1024 and 65535")
    for port in ports:
        with socket.socket() as check:
            try:
                check.bind(("127.0.0.1", port))
            except OSError:
                parser.error(f"Port {port} is occupied; choose another. Existing services are never stopped.")
    from cloud.runtime import start_demo
    demo = start_demo(gateway_port=args.port, opa_port=args.opa_port, llm_port=args.llm_port,
        mcp_port=args.mcp_port, token="demo-admin-token", download=False)
    streamlit = None
    try:
        if args.streamlit:
            env = {k: v for k, v in os.environ.items() if not k.startswith("AICL_")}
            env.update(AICL_GATEWAY_URL=demo.url, AICL_SHOWCASE_ENABLED="true", PYTHONIOENCODING="utf-8")
            streamlit = subprocess.Popen([sys.executable, "-m", "streamlit", "run", "cloud/streamlit_app.py",
                "--server.address=127.0.0.1", f"--server.port={args.streamlit_port}", "--server.headless=true"],
                cwd=ROOT, env=env, creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        state = ROOT / ".tools/final/live-demo.json"
        state.parent.mkdir(parents=True, exist_ok=True)
        state.write_text(json.dumps({"parent_pid": os.getpid(),
            "child_pids": [p.pid for p in demo.children] + ([streamlit.pid] if streamlit else []),
            "gateway_url": demo.url, "native_url": demo.url + "/dashboard",
            "streamlit_url": f"http://127.0.0.1:{args.streamlit_port}" if streamlit else None}, indent=2) + "\n")
        print(f"Native dashboard: {demo.url}/dashboard\nOperator token: demo-admin-token\n"
            "Useful agent: python -m demo.useful_agent --url " + demo.url, flush=True)
        if streamlit:
            print(f"Streamlit: http://127.0.0.1:{args.streamlit_port}", flush=True)
        while all(p.poll() is None for p in demo.children) and (streamlit is None or streamlit.poll() is None):
            time.sleep(.5)
    except KeyboardInterrupt:
        pass
    finally:
        if streamlit and streamlit.poll() is None:
            if os.name == "nt":
                subprocess.run(["taskkill", "/PID", str(streamlit.pid), "/T", "/F"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW)
            else:
                streamlit.terminate()
        demo.close()


if __name__ == "__main__":
    main()
