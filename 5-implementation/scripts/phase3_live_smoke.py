import json
import subprocess
import sys

import httpx

from app.settings import ROOT


def main():
    subprocess.run([sys.executable, str(ROOT / "scripts/mcp_demo_credentials.py")], check=True)
    # Gateway intentionally loads credentials once; refresh through its owned container restart first.
    subprocess.run(["docker", "compose", "restart", "gateway"], cwd=ROOT, check=True, capture_output=True)
    import time
    with httpx.Client(base_url="http://127.0.0.1:8000", timeout=10, headers={"Authorization": "Bearer demo-user-token"}) as client:
        for _ in range(40):
            try:
                if client.get("/ready").status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            time.sleep(.25)
        response = client.post("/v1/transactions", json={"operation": "mcp_tool_call",
            "resource": {"name": "trusted-internal::filesystem.read"}, "payload": {"path": "public.txt"}})
        assert response.status_code == 200, response.text
        registry = client.get("/admin/mcp/registry", headers={"Authorization": "Bearer demo-admin-token"})
        assert registry.status_code == 200
    result = subprocess.run(["docker", "compose", "exec", "-T", "gateway", "python", "-m", "app.evaluation.live_mcp"],
        cwd=ROOT, capture_output=True, text=True, check=True)
    lines = [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]
    report = lines[0] | lines[1]
    container = subprocess.check_output(["docker", "compose", "ps", "-q", "untrusted-external"], cwd=ROOT, text=True).strip()
    inspection = json.loads(subprocess.check_output(["docker", "inspect", container], text=True))[0]
    host = inspection["HostConfig"]
    assert host["ReadonlyRootfs"] and "ALL" in host["CapDrop"]
    assert "no-new-privileges:true" in host["SecurityOpt"] and inspection["Config"]["User"] == "65532:65532"
    assert host["Memory"] == 256*1024*1024 and host["PidsLimit"] == 64
    networks = list(inspection["NetworkSettings"]["Networks"])
    network = json.loads(subprocess.check_output(["docker", "network", "inspect", networks[0]], text=True))[0]
    assert network["Internal"]
    report["sandbox"] = {"read_only": True, "uid": 65532, "capabilities": "ALL dropped", "no_new_privileges": True,
        "memory_bytes": host["Memory"], "pids": host["PidsLimit"], "cpu_nanos": host["NanoCpus"], "internal_network": True}
    report["gateway_internal_read"] = "passed"
    report["registry_findings"] = registry.json()["findings"]
    (ROOT / "artifacts/phase3-live-smoke.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
