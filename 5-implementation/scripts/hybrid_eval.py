"""Separate real AI, deterministic and hybrid measurements with frozen evidence."""
import argparse
import asyncio
import hashlib
import json
import time
from datetime import UTC, datetime
from pathlib import Path

from app.controls import prompt_patterns
from app.core.transaction import Operation, Principal, SecurityTransaction
from app.evaluation.evidence import source_fingerprint
from app.evaluation.hybrid_corpus import SEED, VERSION, corpus
from app.evaluation.statistics import calibrate, classification, latency
from app.semantic.deberta import DebertaProvider
from app.settings import ROOT


async def evaluate(args):
    import psutil
    import torch
    import yaml

    torch.set_num_threads(2)
    binding = source_fingerprint()
    cases = corpus()
    dataset_hash = hashlib.sha256(json.dumps(cases, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
    provider = DebertaProvider(str(ROOT / "models/deberta"))
    deterministic = prompt_patterns.inspect
    if args.baseline:
        from app.evaluation.baseline import detectors
        deterministic, legacy_provider = detectors()
        provider = legacy_provider(str(ROOT / "models/deberta"))
    started = time.perf_counter()
    await asyncio.to_thread(provider._load)
    load_seconds = time.perf_counter() - started
    threshold = yaml.safe_load((ROOT / "config/policy.yaml").read_text())["controls"]["prompt_injection"]["semantic"]["provider_thresholds"]["deberta"]["block_threshold"]
    results = []
    principal = Principal(subject="offline-evaluation", tenant_id="offline")
    def transaction(text):
        return SecurityTransaction(principal=principal, operation=Operation.LLM_REQUEST,
            payload={"messages": [{"role": "user", "content": text}]})
    await provider.analyze(transaction("Warm up with a public summary."))
    started = time.perf_counter()
    # Calibration is measured before opening the final split. Baseline uses deployed threshold.
    for split in ("calibration", "development", "test"):
        for case in (c for c in cases if c["split"] == split):
            tx = transaction(case["text"])
            before = time.perf_counter()
            findings = deterministic(tx)
            deterministic_ms = (time.perf_counter() - before) * 1000
            before = time.perf_counter()
            risk = await provider.analyze(transaction(case["text"]))
            ai_ms = (time.perf_counter() - before) * 1000
            results.append({k: v for k, v in case.items() if k != "text"} | {
                "ai_score": risk.prompt_injection,
                "deterministic_score": max((getattr(f, "confidence", .95) for f in findings), default=0),
                "rules": [f.rule_id or f.code for f in findings],
                "ai_ms": ai_ms, "deterministic_ms": deterministic_ms, "total_ms": ai_ms + deterministic_ms})
        if split == "calibration" and args.calibrate:
            threshold = calibrate([{**r, "score": r["ai_score"]} for r in results], minimum_threshold=.5)
    duration = time.perf_counter() - started
    summary = {}
    for split in ("calibration", "development", "test"):
        rows = [r for r in results if r["split"] == split]
        for r in rows:
            r["ai_positive"] = r["ai_score"] >= threshold
            r["deterministic_positive"] = r["deterministic_score"] >= .90
            r["hybrid_score"] = max(r["ai_score"], threshold if r["deterministic_positive"] else 0)
        metrics = {name: classification([{**r, "score": r[field]} for r in rows], cutoff)
            for name, field, cutoff in (("ai", "ai_score", threshold),
                ("deterministic", "deterministic_score", .90), ("hybrid", "hybrid_score", threshold))}
        overlap = {"ai_only": sum(r["ai_positive"] and not r["deterministic_positive"] for r in rows),
            "deterministic_only": sum(r["deterministic_positive"] and not r["ai_positive"] for r in rows),
            "both": sum(r["ai_positive"] and r["deterministic_positive"] for r in rows),
            "disagreements": sum(r["ai_positive"] != r["deterministic_positive"] for r in rows)}
        overlap["disagreement_rate"] = overlap["disagreements"] / len(rows)
        for name in ("ai_only", "deterministic_only", "both"):
            overlap[name + "_percentage"] = 100 * overlap[name] / len(rows)
        overlap["rule_corrects_ai"] = sum(r["malicious"] and r["deterministic_positive"] and not r["ai_positive"] for r in rows)
        overlap["ai_corrects_rule"] = sum(r["malicious"] and r["ai_positive"] and not r["deterministic_positive"] for r in rows)
        overlap["hybrid_worse_than_ai"] = sum(not r["malicious"] and r["deterministic_positive"] and not r["ai_positive"] for r in rows)
        overlap["hybrid_worse_than_rule"] = sum(not r["malicious"] and r["ai_positive"] and not r["deterministic_positive"] for r in rows)
        summary[split] = {"metrics": metrics, "overlap": overlap,
            "by_category": {category: {name: classification([{**r, "score": r[field]} for r in rows if r["category"] == category], cutoff)
                for name, field, cutoff in (("ai", "ai_score", threshold), ("deterministic", "deterministic_score", .90), ("hybrid", "hybrid_score", threshold))}
                for category in sorted({r["category"] for r in rows})}}
    report = {"timestamp": datetime.now(UTC).isoformat(), "real_model": True, "provider": "deberta",
        "implementation": "baseline-v1" if args.baseline else "current",
        "protocol": VERSION, "seed": SEED, "dataset_sha256": dataset_hash,
        "source_fingerprint": binding, "evidence_stable": binding == source_fingerprint(), "ai_threshold": threshold,
        "threshold_source": "calibration_only" if args.calibrate else "deployed_policy",
        "model_revision": "e6535ca4ce3ba852083e75ec585d7c8aeb4be4c5",
        "load_seconds": load_seconds, "rss_bytes": psutil.Process().memory_info().rss,
        "performance": {name: latency([r[field] for r in results], sum(r[field] for r in results) / 1000)
            for name, field in (("ai", "ai_ms"), ("deterministic", "deterministic_ms"), ("hybrid", "total_ms"))},
        "duration_seconds": duration, "splits": summary, "results": results,
        "limitations": "Synthetic families are correlated. Hybrid measures classification, not authorization or full gateway latency. Both detectors always run here for comparison."}
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    # Never display held-out case outcomes during development.
    print(json.dumps({"output": str(output), "threshold": threshold, "development": summary["development"]["metrics"], "performance": report["performance"]}, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="artifacts/hybrid-current.json")
    parser.add_argument("--calibrate", action="store_true")
    parser.add_argument("--baseline", action="store_true", help="Use archived detectors from the initial repository commit")
    parser.add_argument("--generate", action="store_true")
    args = parser.parse_args()
    if args.generate:
        path = Path(args.output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(json.dumps(c, ensure_ascii=False) for c in corpus()) + "\n", encoding="utf-8")
        print(f"Generated {len(corpus())} cases: {path}")
    else:
        asyncio.run(evaluate(args))
