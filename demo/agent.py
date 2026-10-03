"""Run safe attack scenarios, then intentionally loop until the gateway terminates the workflow."""

import argparse
import json
from pathlib import Path
from uuid import uuid4

import httpx


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1:8000")
    parser.add_argument("--token", default="demo-user-token")
    args = parser.parse_args()
    with httpx.Client(
        base_url=args.url, headers={"Authorization": f"Bearer {args.token}"}, timeout=30
    ) as client:
        scenarios = json.loads((Path(__file__).parent / "scenarios/security.json").read_text())
        for scenario in scenarios:
            response = client.post(scenario["endpoint"], json=scenario["body"])
            result = response.json()["security"]
            print(f"{scenario['name']}: {result['decision']} {result['reason_codes']}")
            assert result["decision"] == scenario["expected"], response.text
        if client.get("/ready").json()["semantic_provider"] == "none":
            response = client.post(
                "/v1/chat/completions",
                json={
                    "messages": [
                        {"role": "tool", "content": "An external document requiring semantic inspection"}
                    ]
                },
            )
            security = response.json()["security"]
            assert "SEMANTIC_UNAVAILABLE" in security["reason_codes"], response.text
            assert security["decision"] == "BLOCK", response.text
            print("Semantic provider unavailable: high-risk retrieved content blocked.")
        workflow = str(uuid4())
        for step in range(1, 101):
            response = client.post(
                "/v1/chat/completions",
                json={
                    "model": "demo",
                    "messages": [{"role": "user", "content": "Continue the loop"}],
                    "workflow": {"workflow_id": workflow},
                },
            )
            security = response.json()["security"]
            if security["decision"] == "TERMINATE":
                print(f"Loop terminated at attempted step {step}: {security['reason_codes']}")
                break
            assert security["decision"] in {"ALLOW", "REDACT", "WARN"}, response.text
        else:
            raise AssertionError("Gateway did not terminate the loop")
    print("All local demo scenarios passed.")


if __name__ == "__main__":
    main()
