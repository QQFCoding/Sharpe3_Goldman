"""Regenerate the Pydantic policy schema and provisioned Grafana dashboard."""

import json
from pathlib import Path

from app.adapters.manifests import manifest
from app.adapters.tools import TOOLS
from app.policy.loader import Policy

ROOT = Path(__file__).resolve().parents[1]


def main():
    (ROOT / "config/tool-manifests.json").write_text(
        json.dumps({name: manifest(tool) for name, tool in TOOLS.items()}, indent=2) + "\n")
    (ROOT / "config/policy.schema.json").write_text(json.dumps(Policy.model_json_schema(), indent=2) + "\n")
    from dashboard_v2 import write
    write()


if __name__ == "__main__":
    main()
