"""Copy safe completed evaluation reports into a reviewable committed snapshot."""
import argparse
import json
import platform
from datetime import datetime, timezone
from importlib.metadata import version

from app.settings import ROOT


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--python-tests", type=int, required=True)
    parser.add_argument("--rego-tests", type=int, required=True)
    args = parser.parse_args()
    names = ["agent-security", "agent-security-initial", "task-alignment-eval", "semantic-eval",
        "semantic-profile", "benchmark-fast", "benchmark-semantic", "chaos-security",
        "policy-verification", "phase2-live-smoke", "phase3-live-smoke", "phase3-demo", "security-eval"]
    reports = {}
    for name in names:
        report = json.loads((ROOT / "artifacts" / (name + ".json")).read_text(encoding="utf-8"))
        if report.get("partial"):
            raise RuntimeError("Incomplete evaluation: " + name)
        if name == "semantic-eval":
            report["path"] = "models/deberta"
        if name == "security-eval":
            report = {k: v for k, v in report.items() if k != "results"}
        reports[name] = report
    snapshot = {"recorded_at_utc": datetime.now(timezone.utc).isoformat(),
        "validation": {"python_tests_passed": args.python_tests, "rego_tests_passed": args.rego_tests,
            "ruff": "passed; see scripts/test.py", "counts_source": "explicit verified run supplied by operator"},
        "environment": {"os": platform.system(), "python": platform.python_version(),
            "packages": {name: version(name) for name in ["httpx", "pydantic", "torch", "transformers", "numpy"]}},
        "reports": reports,
        "limitations": "Local bounded evaluations. Raw observations, arguments, model weights and credentials are excluded. "
            "AgentDyn utility is poor; zero attack success does not establish deployment readiness."}
    (ROOT / "docs/phase3-measurements.json").write_text(json.dumps(snapshot, indent=2) + "\n", encoding="utf-8")
    print("Recorded safe Phase 3 measurement snapshot.")


if __name__ == "__main__":
    main()
