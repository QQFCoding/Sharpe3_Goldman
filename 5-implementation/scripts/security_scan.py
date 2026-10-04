"""Offline dependency inventory and a distinct, explicitly sample advisory feed."""
import argparse
import importlib.metadata
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="artifacts/dependency-inventory.json")
    args = parser.parse_args()
    components = sorted([{"name": d.metadata["Name"], "version": d.version,
        "purl": f"pkg:pypi/{d.metadata['Name'].lower()}@{d.version}"}
        for d in importlib.metadata.distributions() if d.metadata.get("Name")], key=lambda x: x["name"].lower())
    advisories = json.loads((ROOT / "config/advisories.sample.json").read_text())
    findings = [advisory for advisory in advisories["advisories"] if any(
        c["name"].lower() == advisory["package"].lower() and c["version"] in advisory["affected_versions"]
        for c in components)]
    report = {"format": "aicl/dependency-inventory/v1", "scope": "active Python environment",
        "advisory_revision": advisories["revision"], "sample_feed": True,
        "components": components, "findings": findings,
        "boundary": "Exact-version sample matching is not a comprehensive vulnerability scan or an all-clear."}
    path = Path(args.output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + "\n")
    print(f"Inventoried {len(components)} dependencies; {len(findings)} sample advisory matches. {path}")


if __name__ == "__main__":
    main()
