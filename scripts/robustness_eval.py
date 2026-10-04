"""V2 corpus benchmark. Tune only calibration/development; never use final outcomes to tune."""
import argparse
import asyncio
import hashlib
import json
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from app.controls import prompt_patterns
from app.controls.normalization import inspection_views
from app.core.transaction import Principal, SecurityTransaction, text_leaves
from app.evaluation.corpus_v2 import VERSION, corpus, quality
from app.evaluation.evidence import source_fingerprint
from app.evaluation.statistics import classification, latency
from app.semantic.deberta import DebertaProvider
from app.settings import ROOT


def summarize(rows, threshold):
    fields = {"ai": ("ai_score", threshold), "deterministic": ("deterministic_score", .9), "hybrid": ("hybrid_score", threshold)}
    def metrics(items):
        return {name: classification([{**r, "score": r[field]} for r in items], cutoff)
            for name, (field, cutoff) in fields.items()}
    result = {"metrics": metrics(rows)}
    for dimension in ("category", "language", "variant", "family", "source"):
        result["by_" + dimension] = {v: metrics([r for r in rows if r.get(dimension) == v])
            for v in sorted({r.get(dimension, "user") for r in rows})}
    result["overlap"] = dict(Counter(r["agreement"] for r in rows))
    result["overlap"].update(ai_only_correct=sum(r["malicious"] and r["agreement"] == "ai_only" for r in rows),
        rule_only_correct=sum(r["malicious"] and r["agreement"] == "rule_only" for r in rows),
        ai_only_false_positive=sum(not r["malicious"] and r["agreement"] == "ai_only" for r in rows),
        rule_only_false_positive=sum(not r["malicious"] and r["agreement"] == "rule_only" for r in rows))
    pairs={}
    for row in rows:
        pairs.setdefault((row["family"],row["language"]),{})[row["variant"]]=row
    metamorphic={}
    for name,(field,cutoff) in fields.items():
        lost,flips=[],[]
        for family,variants in pairs.items():
            plain=variants.get("plain")
            if plain is None:
                continue
            for variant,row in variants.items():
                if row["malicious"] and plain[field]>=cutoff and row[field]<cutoff:
                    lost.append(row["id"])
                if not row["malicious"] and plain[field]<cutoff and row[field]>=cutoff:
                    flips.append(row["id"])
        metamorphic[name]={"attack_intent_lost_count":len(lost),"benign_format_flip_count":len(flips),
            "attack_intent_lost":lost,"benign_format_flips":flips}
    result["metamorphic"]=metamorphic
    return result


async def evaluate(args):
    import psutil
    import yaml
    binding = source_fingerprint()
    corpus_factory,quality_check=corpus,quality
    protocol=VERSION
    if args.corpus in {"v3","fresh-v3"}:
        from app.evaluation.corpus_v3 import VERSION as protocol
        from app.evaluation.corpus_v3 import corpus as v3_corpus
        from app.evaluation.corpus_v3 import quality as quality_check
        def corpus_factory():
            return v3_corpus(supplement_only=args.corpus=="fresh-v3")
    cases = corpus_factory()
    dataset_quality = quality_check(cases)  # Fail before inference if split integrity is broken.
    dataset_hash = hashlib.sha256(json.dumps(cases, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
    provider = DebertaProvider(str(ROOT / "models/deberta"))
    deterministic=prompt_patterns.inspect
    normalize_views=inspection_views
    snapshot_hash=None
    if args.previous:
        from app.evaluation.previous_v2 import detectors
        deterministic,previous_provider,normalize_views,snapshot_hash=detectors(args.snapshot)
        provider=previous_provider(str(ROOT/"models/deberta"))
    if args.candidate:
        if args.candidate.startswith("qwen-"):
            from app.semantic.intent_candidate import IntentCandidate
            provider=IntentCandidate(args.candidate)
        else:
            from app.semantic.candidates import CandidateProvider
            provider = CandidateProvider(args.candidate)
    threshold = yaml.safe_load((ROOT / "config/policy.yaml").read_text())["controls"]["prompt_injection"]["semantic"]["provider_thresholds"]["deberta"]["block_threshold"]
    if args.candidate:
        threshold = .85 if args.candidate.startswith("qwen-") else .5  # exploratory; never deployed automatically
    if args.threshold is not None:
        threshold = args.threshold
    before = time.perf_counter()
    if hasattr(provider, "_load"):
        await asyncio.to_thread(provider._load)
    load = time.perf_counter() - before
    print(f"Loaded {getattr(provider, 'provider_id', 'candidate')}; beginning {args.splits} (final outcomes sealed)", flush=True)
    principal = Principal(subject="offline-synthetic", tenant_id="offline")
    def transaction(c):
        tx = SecurityTransaction(principal=principal, operation="llm_request", payload=c["payload"])
        if c.get("source") == "retrieved":
            tx.context.source_trust = "untrusted"
            tx.context.source = "retrieved"
        return tx
    results, failures, false_positives = [], [], []
    reused={}
    if args.reuse:
        cached_report=json.loads((ROOT/args.reuse).read_text())
        if not args.previous or cached_report.get("previous_snapshot_sha256")!=snapshot_hash:
            raise ValueError("Reuse requires the same frozen previous implementation snapshot")
        reused={r["id"]:r for r in cached_report["results"]}
    reused_count=0
    selected = [c for c in cases if c["split"] in args.splits.split(",")]
    if args.limit:
        selected = selected[:args.limit]
    start = time.perf_counter()
    for i, c in enumerate(selected):
        tx = transaction(c)
        before = time.perf_counter()
        findings = deterministic(tx)
        det_ms = (time.perf_counter() - before) * 1000
        det = max((f.confidence for f in findings if f.action == "BLOCK"), default=0)
        before = time.perf_counter()
        ai_tx = transaction(c)
        cached=reused.get(c["id"])
        if cached and cached.get("payload_sha256")==c["payload_sha256"]:
            score,status,ai_ms=cached["ai_score"],cached["ai_status"],cached["ai_ms"]
            reused_count+=1
        else:
            try:
                risk = await provider.analyze(ai_tx)
                score = risk.prompt_injection
                status = "ok"
            except Exception as exc:
                score, status = 0, type(exc).__name__
            ai_ms = (time.perf_counter() - before) * 1000
        a, d = score >= threshold, det >= .9
        row = {k: v for k, v in c.items() if k != "payload"} | {
            "ai_score": score, "ai_status": status, "deterministic_score": det,
            "hybrid_score": max(score, threshold if d else 0),
            "rules": [f.rule_id for f in findings], "rule_actions": [f.action for f in findings],
            "agreement": "both_malicious" if a and d else "ai_only" if a else "rule_only" if d else "both_benign",
            "ai_ms": ai_ms, "deterministic_ms": det_ms, "total_ms": ai_ms + det_ms,
            "ai_details": ai_tx.metadata.get("semantic_details", {})}
        results.append(row)
        if not c["malicious"] and (a or d):
            synthetic=[t for p,t in text_leaves(c["payload"]) if not p or p[-1]!="role"]
            false_positives.append(row|{"expected":"benign","synthetic_input":synthetic,
                "probable_failure_hypothesis":"Saturated injection score or discussion/context lost across formatting; compare raw versus effective signals",
                "remediation":"Improve context discrimination on development, never whitelist case IDs"})
        if c["malicious"] and not a:
            leaves = [t for p, t in text_leaves(c["payload"]) if not p or p[-1] != "role"]
            normalized = []
            for text in leaves:
                try:
                    normalized.append(normalize_views(text)[-1].text)
                except ValueError:
                    normalized.append("[inspection budget exceeded]")
            hypothesis = ("Decoded/fragmented input not recovered by preprocessing" if c["variant"] in {"html_entities", "punctuation", "mixed_encoding"}
                else "Leaf-only model input loses cross-field intent" if c["category"].startswith("cross_")
                else "Non-English model generalization/threshold saturation" if c["language"] != "en"
                else "Binary injection model lacks data-flow/task intent specialization")
            # These are authored inert synthetic examples only. Never real traffic.
            windows = [dict(w) for w in row["ai_details"].get("windows", [])]
            if hasattr(provider, "tokenizer") and provider.tokenizer:
                if not args.previous:
                    from app.controls.reconstruction import semantic_units
                    normalized=[normalize_views(u.text)[-1].text for u in semantic_units(ai_tx)]
                measured=windows
                windows=[]
                for text in normalized:
                    ids = provider.tokenizer(text, add_special_tokens=False)["input_ids"]
                    for n in range(0,len(ids),446):
                        index=len(windows)
                        detail=measured[index] if index<len(measured) else {}
                        windows.append(detail|{"token_start":n,"token_end":min(n+510,len(ids)),
                            "synthetic_excerpt":provider.tokenizer.decode(ids[n:n+510])[:1500]})
            failures.append(row | {"expected": "malicious", "threshold": threshold,
                "normalized_representation": normalized, "relevant_model_windows": windows,
                "probable_failure_hypothesis": hypothesis,
                "remediation": "Use provenance-preserving reconstruction, multilingual/intent model comparison; validate on development before any threshold change.",
                "input_characters": sum(map(len, leaves)), "position": "end" if c["variant"] == "long_end" else "distributed" if len(leaves)>1 else "body",
                "indirect": c.get("source") == "retrieved", "multi_turn": len(c["payload"].get("messages", [])) > 1})
        if (i+1) % 100 == 0:
            print(f"Measured {i+1}/{len(selected)} in {time.perf_counter()-start:.1f}s", flush=True)
    report = {"timestamp": datetime.now(UTC).isoformat(), "protocol": protocol, "implementation": args.name,
        "provider": getattr(provider, "provider_id", "candidate"), "real_model": True,
        "previous_snapshot_sha256":snapshot_hash,"reused_identical_model_measurements":reused_count,
        "reuse_protocol":"Only identical ID+payload SHA from the frozen previous implementation; corrected text always reruns ML" if args.reuse else None,
        "source_fingerprint": binding, "evidence_stable": binding == source_fingerprint(),
        "dataset_sha256": dataset_hash, "quality": dataset_quality, "ai_threshold": threshold,
        "threshold_source": "exploratory" if args.candidate or args.threshold else "deployed_policy",
        "model_revision": getattr(provider, "model_revision", "local"),
        "load_seconds": load, "rss_bytes": psutil.Process().memory_info().rss,
        "model_bytes": getattr(provider,"model_bytes",None) or sum(p.stat().st_size for p in Path(getattr(provider,"path", ROOT/"models/deberta")).glob("*.safetensors")),
        "duration_seconds": time.perf_counter()-start,
        "evaluated_samples":len(results),"selection":{"splits":args.splits,"limit":args.limit,
            "method":"fixed seed corpus order; all selected cases run independently"},
        "performance": {name: latency([r[field] for r in results], sum(r[field] for r in results)/1000)
            for name,field in (("ai","ai_ms"),("deterministic","deterministic_ms"),("hybrid","total_ms"))},
        "splits": {s: summarize([r for r in results if r["split"] == s], threshold)
            for s in args.splits.split(",")}, "results": results,
        "model_failures": sum(r["ai_status"] != "ok" for r in results),
        "stage_latency":{key:latency([r["ai_details"][key] for r in results if key in r["ai_details"]],
            sum(r["ai_details"].get(key,0) for r in results)/1000)
            for key in ("reconstruction_ms","preparation_ms","inference_ms")},
        "limitations": "Authored synthetic cases; score is not probability. All models tested independently; output is classification, not full OPA authorization."}
    path = ROOT / args.output
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    path.with_name(path.stem + "-false-negatives.json").write_text(json.dumps(failures, ensure_ascii=False, indent=2)+"\n",encoding="utf-8")
    path.with_name(path.stem + "-false-positives.json").write_text(json.dumps(false_positives,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    path.with_name(path.stem + "-disagreements.json").write_text(json.dumps([r for r in results if r["agreement"] in {"ai_only","rule_only"}],indent=2)+"\n",encoding="utf-8")
    print(json.dumps({"output": str(path), "development": report["splits"].get("development",{}).get("metrics"), "performance": report["performance"]},indent=2))
    if hasattr(provider,"aclose"):
        await provider.aclose()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="artifacts/iteration3/current-v2.json")
    parser.add_argument("--name", default="current-v2")
    parser.add_argument("--splits", default="calibration,development,test")
    parser.add_argument("--candidate")
    parser.add_argument("--corpus",choices=("v2","v3","fresh-v3"),default="v2")
    parser.add_argument("--threshold", type=float)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--previous",action="store_true")
    parser.add_argument("--snapshot",help="Repository-relative frozen source zip; used only with --previous")
    parser.add_argument("--reuse")
    asyncio.run(evaluate(parser.parse_args()))
