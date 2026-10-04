"""Run v4 real-model evidence; test predictions require an explicit code freeze.

Independent of application admission: these are detector classification metrics,
not a claim that every classified attack executes an authorized upstream action.
"""
import argparse
import asyncio
import hashlib
import json
import time
from collections import Counter
from datetime import UTC, datetime

import yaml

from app.controls import prompt_patterns
from app.core.transaction import Principal, SecurityTransaction
from app.evaluation.corpus_v4 import VERSION, corpus, quality
from app.evaluation.evidence import source_fingerprint
from app.evaluation.statistics import latency
from app.semantic.deberta import DebertaProvider
from app.settings import ROOT
from scripts.robustness_eval import summarize


def detector_fingerprint():
    digest = hashlib.sha256()
    for directory in (ROOT / "app/controls", ROOT / "app/semantic"):
        for path in sorted(directory.glob("*.py")):
            digest.update(path.relative_to(ROOT).as_posix().encode())
            digest.update(path.read_bytes())
    for path in (ROOT / "config/deberta.lock.json", ROOT / "config/policy.yaml"):
        digest.update(path.relative_to(ROOT).as_posix().encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()


def manifest():
    cases = corpus()
    return {"timestamp": datetime.now(UTC).isoformat(), "source_fingerprint": source_fingerprint(),
        "detector_fingerprint": detector_fingerprint(),
        "dataset_sha256": hashlib.sha256(json.dumps(cases, sort_keys=True, ensure_ascii=False).encode()).hexdigest(),
        "quality": quality(cases), "selection": "No test predictions opened before this detector freeze"}


async def evaluate(args):
    binding = manifest()
    if "test" in args.splits.split(","):
        if not args.freeze:
            raise ValueError("V4 test predictions require --freeze <manifest>, created after detector selection")
        frozen = json.loads((ROOT / args.freeze).read_text(encoding="utf-8"))
        for field in ("detector_fingerprint", "dataset_sha256"):
            if frozen.get(field) != binding[field]:
                raise ValueError(f"V4 test freeze does not match {field}")
    cases = [c for c in corpus() if c["split"] in args.splits.split(",")]
    provider = DebertaProvider(str(ROOT / "models/deberta"))
    deterministic, snapshot = prompt_patterns.inspect, None
    if args.previous:
        from app.evaluation.previous_v2 import detectors
        deterministic, previous_provider, _, snapshot = detectors(args.snapshot)
        provider = previous_provider(str(ROOT / "models/deberta"))
    threshold = yaml.safe_load((ROOT / "config/policy.yaml").read_text(encoding="utf-8"))["controls"]["prompt_injection"]["semantic"]["provider_thresholds"]["deberta"]["block_threshold"]
    principal = Principal(subject="offline-v4", tenant_id="offline")
    def transaction(case):
        tx = SecurityTransaction(principal=principal, operation="llm_request", payload=case["payload"])
        if case.get("source") == "retrieved":
            tx.context.source_trust = "untrusted"
            tx.context.source = "retrieved"
        return tx
    start = time.perf_counter()
    await asyncio.to_thread(provider._load)
    load_seconds = time.perf_counter() - start
    print(f"Loaded actual {provider.provider_id}; measuring {len(cases)} v4 {args.splits} cases", flush=True)
    results = []
    started = time.perf_counter()
    for index, case in enumerate(cases):
        tx = transaction(case)
        before = time.perf_counter()
        findings = deterministic(tx)
        rule_ms = (time.perf_counter() - before) * 1000
        rule_score = max((f.confidence for f in findings if f.action == "BLOCK"), default=0)
        ai_tx = transaction(case)
        before = time.perf_counter()
        try:
            score, status = (await provider.analyze(ai_tx)).prompt_injection, "ok"
        except Exception as exc:
            score, status = 0, type(exc).__name__
        ai_ms = (time.perf_counter() - before) * 1000
        ai, rules = score >= threshold, rule_score >= .9
        results.append({k: v for k, v in case.items() if k != "payload"} | {
            "ai_score": score, "ai_status": status, "deterministic_score": rule_score,
            "hybrid_score": max(score, threshold if rules else 0),
            "rules": [f.rule_id for f in findings], "rule_actions": [f.action for f in findings],
            "agreement": "both_malicious" if ai and rules else "ai_only" if ai else "rule_only" if rules else "both_benign",
            "ai_ms": ai_ms, "deterministic_ms": rule_ms, "total_ms": ai_ms + rule_ms,
            "ai_details": ai_tx.metadata.get("semantic_details", {}),
        })
        if (index + 1) % 50 == 0:
            print(f"Measured {index+1}/{len(cases)} in {time.perf_counter()-started:.1f}s", flush=True)
    report = {**binding, "timestamp": datetime.now(UTC).isoformat(), "protocol": VERSION,
        "implementation": "iteration3-frozen" if args.previous else "final-v4",
        "provider": provider.provider_id, "model_revision": provider.model_revision,
        "real_model": True, "ai_threshold": threshold, "threshold_source": "deployed_policy",
        "previous_snapshot_sha256": snapshot, "selection": {"splits": args.splits, "limit": None},
        "evidence_stable": binding["source_fingerprint"] == source_fingerprint(),
        "detector_stable": binding["detector_fingerprint"] == detector_fingerprint(),
        "load_seconds": load_seconds, "duration_seconds": time.perf_counter() - started,
        "evaluated_samples": len(results), "model_failures": dict(Counter(r["ai_status"] for r in results if r["ai_status"] != "ok")),
        "performance": {name: latency([r[field] for r in results], sum(r[field] for r in results)/1000)
            for name, field in (("ai", "ai_ms"), ("deterministic", "deterministic_ms"), ("hybrid", "total_ms"))},
        "splits": {split: summarize([r for r in results if r["split"] == split], threshold) for split in args.splits.split(",")},
        "results": results,
    }
    output = ROOT / args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    for suffix, selected in (
        ("false-negatives", [r for r in results if r["malicious"] and r["hybrid_score"] < threshold]),
        ("false-positives", [r for r in results if not r["malicious"] and r["hybrid_score"] >= threshold]),
        ("disagreements", [r for r in results if r["agreement"] in {"ai_only", "rule_only"}]),
    ):
        output.with_name(output.stem + "-" + suffix + ".json").write_text(json.dumps(selected, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"output": str(output.relative_to(ROOT)), "model_failures": report["model_failures"],
        "splits": {split: row["metrics"] for split, row in report["splits"].items()}}, indent=2), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--splits", default="calibration,development")
    parser.add_argument("--output", default="artifacts/final/v4-development.json")
    parser.add_argument("--freeze")
    parser.add_argument("--write-freeze")
    parser.add_argument("--previous", action="store_true")
    parser.add_argument("--snapshot", default="docs/final/iteration3-source.zip")
    args = parser.parse_args()
    if args.write_freeze:
        path = ROOT / args.write_freeze
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(manifest(), ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"Wrote freeze manifest {path.relative_to(ROOT)}")
    else:
        asyncio.run(evaluate(args))


if __name__ == "__main__":
    main()
