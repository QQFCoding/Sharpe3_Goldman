"""Optional explicit OSV queries; output is separate from runtime attack signatures."""
import argparse
import importlib.metadata
import json
from pathlib import Path

import httpx


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--package", action="append", required=True, help="Installed package to query; repeatable, max 20")
    parser.add_argument("--output", default="artifacts/osv-advisories.json")
    args = parser.parse_args()
    if len(args.package) > 20:
        parser.error("At most 20 explicit packages per update")
    results = []
    with httpx.Client(timeout=20) as client:
        for name in args.package:
            version = importlib.metadata.version(name)
            response = client.post("https://api.osv.dev/v1/query", json={"package": {"name": name, "ecosystem": "PyPI"}, "version": version})
            response.raise_for_status()
            results.append({"package": name, "version": version, "advisories": response.json().get("vulns", [])})
    path = Path(args.output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(results, indent=2) + "\n")


if __name__ == "__main__":
    main()
