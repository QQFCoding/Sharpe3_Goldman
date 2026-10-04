"""Compare identical candidate cases; select exploratory thresholds on calibration only."""
import argparse
import json

from app.evaluation.statistics import classification
from app.settings import ROOT


def metrics(rows, threshold):
    return classification([{**r, "score": r["ai_score"]} for r in rows], threshold)


def study(args):
    names = ["deepset", "distilbert", "qwen-0.6b", "qwen-4b"]
    reports = {name: json.loads((ROOT / f"artifacts/iteration2/{name}-development.json").read_text()) for name in names}
    primary = json.loads((ROOT / args.primary).read_text())
    ids = {r["id"] for r in reports[names[0]]["results"]}
    for report in reports.values():
        if {r["id"] for r in report["results"]} != ids:
            raise ValueError("Candidates must measure identical cases")
        if report["model_failures"]:
            raise ValueError("Candidate has unavailable classifications")
    reports["deberta"] = {**primary, "results": [r for r in primary["results"] if r["id"] in ids]}
    output = {"scope": "360 fixed-seed calibration/development cases only; no held-out outcomes used for model selection",
        "limitations": "Small synthetic subset. Candidate Torch timings overlapped each other; Qwen uses the installed GPU-backed Ollama service. Client RSS excludes Ollama. No CPU-only Qwen latency claim. No automatic deployment/model or threshold change.",
        "calibration_fpr_budget": .10, "models": {}}
    for name, report in reports.items():
        calibration = [r for r in report["results"] if r["split"] == "calibration"]
        development = [r for r in report["results"] if r["split"] == "development"]
        options = sorted({.5, .85, .95, .99, .999, .9999, .99999, 1.000001, *[r["ai_score"] for r in calibration]})
        eligible = [(t, metrics(calibration, t)) for t in options if metrics(calibration, t)["false_positive_rate"] <= .10]
        chosen, cal = max(eligible, key=lambda item: (item[1]["f1"], item[1]["precision"], item[0]))
        active = report["ai_threshold"]
        derived = metrics(development, chosen)
        row = {"revision": report["model_revision"], "model_bytes": report["model_bytes"], "rss_bytes": report["rss_bytes"],
            "load_seconds": report["load_seconds"], "default_threshold": active, "default_development": metrics(development, active),
            "calibration_selected_threshold": chosen, "selected_calibration": cal, "selected_development": derived,
            "default_ai_only_correct": sum(r["malicious"] and r["ai_score"] >= active and r["deterministic_score"] < .9 for r in development),
            "selected_ai_only_correct": sum(r["malicious"] and r["ai_score"] >= chosen and r["deterministic_score"] < .9 for r in development),
            "by_language": {lang: metrics([r for r in development if r["language"] == lang], chosen) for lang in sorted({r["language"] for r in development})},
            "by_variant": {v: metrics([r for r in development if r["variant"] == v], chosen) for v in sorted({r["variant"] for r in development})},
            "by_category": {c: metrics([r for r in development if r["category"] == c], chosen) for c in sorted({r["category"] for r in development})}}
        # Primary latency here is the exact shared subset, not the full harder corpus.
        from app.evaluation.statistics import latency
        row["shared_subset_latency"] = latency([r["ai_ms"] for r in report["results"]], sum(r["ai_ms"] for r in report["results"])/1000)
        output["models"][name] = row
    output["decision"] = "Retain verified production DeBERTa and its frozen threshold. Candidate thresholds are exploratory; small development subsets, false-positive trade-offs, device placement and unverified deployment timeouts do not justify a production swap/ensemble."
    (ROOT / "artifacts/iteration2/model-study.json").write_text(json.dumps(output, indent=2)+"\n", encoding="utf-8")
    print(json.dumps({name: {k: row[k] for k in ("default_development", "calibration_selected_threshold", "selected_development", "selected_ai_only_correct")} for name, row in output["models"].items()}, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--primary", default="artifacts/iteration2/current-v2.json")
    study(parser.parse_args())
