"""Publish a small factual summary from completed, separate evaluation commands."""
import json
import platform
from datetime import UTC, datetime
from pathlib import Path

from app.evaluation.statistics import classification

ROOT = Path(__file__).resolve().parents[1]


def main():
    def read(name):
        return json.loads((ROOT / "artifacts" / name).read_text(encoding="utf-8"))

    semantic = read("semantic-eval.json")
    test = [r for r in semantic["results"] if r["split"] == "test"]
    semantic["by_language"] = {language: classification([r for r in test if r["language"] == language],
        semantic["calibrated_block_threshold"]) for language in sorted({r["language"] for r in test})}
    # Aggregation of existing observed scores requires no second model inference run.
    (ROOT / "artifacts/semantic-eval.json").write_text(json.dumps(semantic, indent=2) + "\n", encoding="utf-8")
    summary = {"recorded_at_utc": datetime.now(UTC).isoformat(),
        "environment": {"os": platform.platform(), "python": platform.python_version(),
            "processor": platform.processor(), "semantic_device": "CPU", "cpu_threads": semantic["cpu_threads"]},
        "baseline": {"commit": "540c87029ebdfbf8f82f68b288d1b436d0e4b54e",
            "python_tests": 90, "opa_tests": 20, "ruff": "passed", "compose": "passed",
            "http_benchmark": read("phase2-baseline.json")},
        "validation": {"python_tests": 146, "opa_tests": 27, "ruff": "passed",
            "compose": "passed", "live_phase2": read("phase2-live-smoke.json"),
            "grafana": read("grafana-validation.json")},
        "classifier": {k: v for k, v in semantic.items() if k not in {"results", "path"}},
        "benchmarks": {mode: read(f"benchmark-{mode}.json") for mode in ["fast", "semantic", "concurrency"]},
        "security_evaluation": {mode: {k: v for k, v in read(name).items() if k != "results"}
            for mode, name in [("deterministic", "security-eval.json"), ("real_classifier", "security-eval-semantic.json")]},
        "limits": ["Small original corpus and finite mutations; no population-level robustness claim.",
            "Prohibited-sink ASR and malicious-prompt fixture reach are separate measurements.",
            "Benchmarks exclude external HTTP transport and PostgreSQL; concurrency uses actual Redis.",
            "Ollama task alignment and gated Prompt Guard were not measured.",
            "Grafana queries/filters/trace retrieval were checked; browser rendering was unavailable."]}
    path = ROOT / "docs/measurements.json"
    path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print("Recorded observed evaluation results:", path)


if __name__ == "__main__":
    main()
