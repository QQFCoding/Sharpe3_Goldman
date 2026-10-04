"""Real weights only; never substitutes mocked semantic signals for measurements."""
import argparse
import asyncio
import json
import time
from pathlib import Path

from app.core.transaction import Operation, Principal, SecurityTransaction
from app.evaluation.corpus import corpus
from app.evaluation.statistics import calibrate, classification, latency
from app.semantic.deberta import DebertaProvider
from app.semantic.prompt_guard import PromptGuardProvider

ROOT = Path(__file__).resolve().parents[1]


async def evaluate(args):
    import psutil
    import torch
    if not (Path(args.path) / "model.safetensors").is_file():
        if args.provider == "deberta":
            import subprocess
            import sys
            subprocess.run([sys.executable, str(ROOT / "scripts/download_models.py"), "--model", "deberta",
                "--destination", args.path], check=True)
        else:
            raise RuntimeError("Prompt Guard is optional/gated: install reviewed weights or use the public DeBERTa path")
    torch.set_num_threads(args.threads)
    provider = DebertaProvider(args.path) if args.provider == "deberta" else PromptGuardProvider(args.path)
    start = time.perf_counter()
    await asyncio.to_thread(provider._load)
    load_seconds = time.perf_counter() - start
    # A warm-up does not contaminate calibration/test observations.
    principal = Principal(subject="evaluation", tenant_id="offline")
    async def score(text):
        return await provider.analyze(SecurityTransaction(principal=principal, operation=Operation.LLM_REQUEST,
            payload={"text": text}))
    await score("Public evaluation warm-up.")
    results = []
    started = time.perf_counter()
    for case in corpus():
        before = time.perf_counter()
        risk = await score(case["text"])
        results.append({k: v for k, v in case.items() if k != "text"} | {
            "score": risk.prompt_injection, "latency_ms": (time.perf_counter() - before) * 1000})
    duration = time.perf_counter() - started
    calibration = [r for r in results if r["split"] == "calibration"]
    test = [r for r in results if r["split"] == "test"]
    threshold = calibrate(calibration)
    report = {"provider": args.provider, "real_model": True, "path": args.path,
        "revision": "e6535ca4ce3ba852083e75ec585d7c8aeb4be4c5" if args.provider == "deberta" else "operator-pinned",
        "load_seconds": load_seconds, "cpu_threads": args.threads, "rss_bytes": psutil.Process().memory_info().rss,
        "calibrated_block_threshold": threshold, "review_threshold": min(.3, threshold / 2),
        "rationale": "Choose highest calibration F1 with FPR <= 10%, then evaluate once on disjoint wording. "
            "Small original corpus; no claim of population-level robustness.",
        "calibration": classification(calibration, threshold), "held_out": classification(test, threshold),
        "performance": latency([r["latency_ms"] for r in results], duration),
        "by_category": {category: classification([r for r in test if r["category"] == category], threshold)
            for category in sorted({r["category"] for r in test})}, "results": results}
    report["by_language"] = {language: classification([r for r in test if r["language"] == language], threshold)
        for language in sorted({r["language"] for r in test})}
    path = Path(args.output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    path.with_suffix(".md").write_text("# Real semantic evaluation\n\n```json\n" +
        json.dumps({k: v for k, v in report.items() if k not in {"results", "by_category", "by_language"}}, indent=2) +
        "\n```\n\nCategory measurements and per-case scores are in the JSON report.\n", encoding="utf-8")
    print(json.dumps({k: v for k, v in report.items() if k not in {"results", "by_category", "by_language"}}, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--provider", choices=["deberta", "prompt_guard"], default="deberta")
    parser.add_argument("--path", default=str(ROOT / "models/deberta"))
    parser.add_argument("--threads", type=int, default=2)
    parser.add_argument("--output", default="artifacts/semantic-eval.json")
    asyncio.run(evaluate(parser.parse_args()))
