"""Run an isolated, real-model Threat Observatory with an owned OPA process.

No mock tool/LLM services are started. The lab's inspect-only API does not execute
upstreams. Ctrl+C terminates only children started by this command.
"""
import argparse
import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from bootstrap import install_opa

ROOT=Path(__file__).resolve().parents[1]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port",type=int,default=8010)
    parser.add_argument("--opa-port",type=int,default=8186)
    parser.add_argument("--gateway-child",action="store_true",help=argparse.SUPPRESS)
    args=parser.parse_args()
    if args.gateway_child:
        import uvicorn

        from app.main import create_app
        from app.settings import Settings
        settings=Settings(_env_file=None,demo_mode=True,semantic_provider="deberta",semantic_preload=True,
            semantic_cpu_threads=2,opa_url=f"http://127.0.0.1:{args.opa_port}",admin_token="demo-admin-token",
            redis_url=None,database_url=None,auth_file=None,mcp_servers_path=None,jwt_jwks_path=None,
            alignment_provider="none",otlp_endpoint=None,llm_url="http://127.0.0.1:1",mcp_url="http://127.0.0.1:1")
        uvicorn.run(create_app(settings),host="127.0.0.1",port=args.port,access_log=False)
        return
    for port in (args.port,args.opa_port):
        if not 1024<=port<=65535:
            parser.error("Use unprivileged ports between 1024 and 65535")
        with socket.socket() as check:
            try:
                check.bind(("127.0.0.1",port))
            except OSError:
                parser.error(f"Port {port} is occupied; choose another port. Existing services are never stopped.")
    if args.port==args.opa_port:
        parser.error("Gateway and OPA need different ports")
    if not (ROOT/"models/deberta/model.safetensors").is_file():
        parser.error("Install the pinned detector first: python scripts/download_models.py --model deberta")
    opa=install_opa()
    env={k:v for k,v in os.environ.items() if not k.startswith("AICL_")}
    env.update(AICL_DEMO_MODE="true",AICL_SEMANTIC_PROVIDER="deberta",AICL_SEMANTIC_PRELOAD="true",
        AICL_OPA_URL=f"http://127.0.0.1:{args.opa_port}",AICL_ADMIN_TOKEN="demo-admin-token",
        AICL_LLM_URL="http://127.0.0.1:1",AICL_MCP_URL="http://127.0.0.1:1",PYTHONIOENCODING="utf-8")
    for name in ("AICL_REDIS_URL","AICL_DATABASE_URL","AICL_AUTH_FILE","AICL_MCP_SERVERS_PATH","AICL_OPA_BINARY"):
        env.pop(name,None)
    # Explicit blank optional stores also defeat inherited .env connections.
    env.update(AICL_REDIS_URL="",AICL_DATABASE_URL="")
    commands=[
        [str(opa),"run","--server",f"--addr=127.0.0.1:{args.opa_port}","--log-level=error","--disable-telemetry",str(ROOT/"opa")],
        [sys.executable,str(ROOT/"scripts/live_demo.py"),"--gateway-child","--port",str(args.port),"--opa-port",str(args.opa_port)],
    ]
    children=[]
    try:
        for command in commands:
            children.append(subprocess.Popen(command,cwd=ROOT,env=env,creationflags=subprocess.CREATE_NO_WINDOW if os.name=="nt" else 0))
        deadline=time.monotonic()+120
        while time.monotonic()<deadline:
            if any(c.poll() is not None for c in children):
                raise RuntimeError("A demo process exited during startup")
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{args.port}/ready",timeout=1) as response:
                    if response.status==200:
                        break
            except (OSError,urllib.error.URLError):
                time.sleep(.2)
        else:
            raise RuntimeError("Demo did not become ready")
        state=ROOT/".tools/iteration3/live-demo.json"
        state.parent.mkdir(parents=True,exist_ok=True)
        state.write_text(json.dumps({"parent_pid":os.getpid(),"child_pids":[c.pid for c in children],"url":f"http://127.0.0.1:{args.port}/dashboard"},indent=2)+"\n")
        print(f"Live demo: http://127.0.0.1:{args.port}/dashboard\nOperator token: demo-admin-token\nSelect Run guided demo after connecting. Ctrl+C stops this demo.",flush=True)
        while all(c.poll() is None for c in children):
            time.sleep(.5)
    except KeyboardInterrupt:
        pass
    finally:
        for child in reversed(children):
            if child.poll() is None:
                if os.name=="nt":
                    # The venv executable can be a redirector with a Python child.
                    # Terminate this owned tree, not just its launcher process.
                    subprocess.run(["taskkill","/PID",str(child.pid),"/T","/F"],
                        stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,creationflags=subprocess.CREATE_NO_WINDOW)
                else:
                    child.terminate()
        for child in children:
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()


if __name__=="__main__":
    main()
