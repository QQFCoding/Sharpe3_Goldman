"""Offline rule-only evaluation; no model packages, weights or network required."""
import argparse
import hashlib
import json
import time
from datetime import UTC, datetime
from pathlib import Path

from app.controls.prompt_patterns import VERSION, inspect
from app.core.transaction import Principal, SecurityTransaction
from app.evaluation.evidence import source_fingerprint
from app.evaluation.hybrid_corpus import corpus
from app.evaluation.statistics import classification, latency


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="artifacts/deterministic-eval.json")
    args = parser.parse_args()
    cases, rows = corpus(), []
    started = time.perf_counter()
    for case in cases:
        before = time.perf_counter()
        tx = SecurityTransaction(principal=Principal(subject="evaluation", tenant_id="offline"),
            operation="llm_request", payload={"messages": [{"role": "user", "content": case["text"]}]})
        findings = inspect(tx)
        rows.append({k: v for k, v in case.items() if k != "text"} | {
            "score": max((f.confidence for f in findings), default=0),
            "latency_ms": (time.perf_counter() - before) * 1000, "rules": [f.rule_id for f in findings]})
    duration = time.perf_counter() - started
    report = {"timestamp": datetime.now(UTC).isoformat(), "detector": "deterministic", "version": VERSION,
        "source_fingerprint": source_fingerprint(),
        "dataset_sha256": hashlib.sha256(json.dumps(cases, sort_keys=True, ensure_ascii=False).encode()).hexdigest(),
        "metrics": {split: classification([r for r in rows if r["split"] == split], .9) for split in ("calibration", "development", "test")},
        "performance": latency([r["latency_ms"] for r in rows], duration), "results": rows}
    path = Path(args.output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({k: v for k, v in report.items() if k != "results"}, indent=2))


if __name__ == "__main__":
    main()
