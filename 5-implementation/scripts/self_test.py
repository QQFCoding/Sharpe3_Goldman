"""One command: real Rego, lint, all Python layers, real AI/rule/hybrid evaluation and gates."""
import argparse
import json
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from datetime import UTC, datetime

from app.evaluation.evidence import source_fingerprint
from app.settings import ROOT


def gates(report, robustness=False):
    config = json.loads((ROOT / "config" / ("robustness-gates.json" if robustness else "detection-gates.json")).read_text())
    failures = []
    for detector, metrics in report["splits"]["test"]["metrics"].items():
        for metric, bound, direction in (("f1", "minimum_f1", "min"),
                ("false_positive_rate", "maximum_fpr", "max"), ("false_negative_rate", "maximum_fnr", "max")):
            limit = config[bound][detector]
            if (metrics[metric] < limit if direction == "min" else metrics[metric] > limit):
                failures.append(f"{detector}.{metric}={metrics[metric]:.4f} violates {limit}")
        if report["performance"][detector]["p95_ms"] > config["maximum_p95_ms"][detector]:
            failures.append(f"{detector} latency gate exceeded")
    if report.get("evidence_stable") is not True or report.get("source_fingerprint") != source_fingerprint():
        failures.append("Evaluation evidence changed during/after measurement")
    if robustness:
        if report.get("model_failures") != 0:
            failures.append("Robustness benchmark has unavailable model results")
        if report.get("evaluated_samples", 0) < config["minimum_samples"]:
            failures.append("Robustness benchmark is incomplete")
        if report["splits"]["test"]["overlap"].get("ai_only_correct", 0) < 1:
            failures.append("AI has no correct complementary held-out discoveries")
        if report.get("quality", {}).get("family_leakage") or report.get("quality", {}).get("duplicate_payloads"):
            failures.append("Dataset leakage/duplicates detected")
    return failures


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checks-only", action="store_true", help="Skip real model evaluation; result is explicitly partial")
    parser.add_argument("--robustness", action="store_true", help="Also evaluate all 2,688 v2 cases and frozen robustness gates (CPU run takes minutes)")
    args = parser.parse_args()
    if args.robustness and args.checks_only:
        parser.error("--robustness requires real-model evaluation")
    (ROOT / "artifacts").mkdir(exist_ok=True)
    path = ROOT / "artifacts/self-test.json"
    started = time.perf_counter()
    binding = source_fingerprint()
    report = {"status": "running", "timestamp": datetime.now(UTC).isoformat(), "source_fingerprint": binding,
        "layers": [], "real_model_required": not args.checks_only}
    path.write_text(json.dumps(report, indent=2))
    (ROOT / "artifacts/pytest.xml").unlink(missing_ok=True)
    commands = [("contracts_and_security", [sys.executable, "scripts/test.py", "--junitxml=artifacts/pytest.xml"])]
    if not args.checks_only:
        commands.append(("real_detectors", [sys.executable, "scripts/hybrid_eval.py", "--output", "artifacts/hybrid-current.json"]))
        if args.robustness:
            commands.append(("robustness", [sys.executable, "scripts/robustness_eval.py"]))
    for layer, command in commands:
        result = subprocess.run(command, cwd=ROOT)
        report["layers"].append({"layer": layer, "exit_code": result.returncode})
        if result.returncode:
            break
    junit = ROOT / "artifacts/pytest.xml"
    if junit.is_file():
        suites = ET.parse(junit).getroot().iter("testsuite")
        counts = [s.attrib for s in suites]
        report.update({key: sum(int(s.get(field, 0)) for s in counts) for key, field in
            (("python_tests", "tests"), ("failures", "failures"), ("errors", "errors"), ("skipped", "skipped"))})
    failures = []
    if not args.checks_only and all(r["exit_code"] == 0 for r in report["layers"]) and len(report["layers"]) >= 2:
        measured = json.loads((ROOT / "artifacts/hybrid-current.json").read_text())
        failures = gates(measured)
        report["metrics"] = measured["splits"]["test"]["metrics"]
        report["overlap"] = measured["splits"]["test"]["overlap"]
        report["performance"] = measured["performance"]
        if args.robustness:
            robustness = json.loads((ROOT / "artifacts/iteration3/current-v2.json").read_text(encoding="utf-8"))
            failures.extend("v2: " + f for f in gates(robustness, robustness=True))
            report["robustness"] = {key: robustness[key] for key in ("protocol", "dataset_sha256", "evaluated_samples", "quality", "performance")}
            report["robustness"]["test"] = robustness["splits"]["test"]
    report["gate_failures"] = failures
    report["duration_seconds"] = time.perf_counter() - started
    report["status"] = "failed" if failures or any(r["exit_code"] for r in report["layers"]) else "partial" if args.checks_only else "passed"
    if binding != source_fingerprint():
        report["status"] = "failed"
        report["gate_failures"].append("Source changed while self-test was running")
    path.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 1 if report["status"] == "failed" else 0


if __name__ == "__main__":
    raise SystemExit(main())
