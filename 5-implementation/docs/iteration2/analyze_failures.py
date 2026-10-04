"""Derive observations from final synthetic evidence; never change measured scores.

Run after scripts/self_test.py --robustness. Hypotheses are investigation aids,
not causal model explanations. This documentation helper does not run in gateway.
"""
import hashlib
import json
from collections import Counter
from pathlib import Path

from app.controls.normalization import inspection_views
from app.controls.reconstruction import semantic_units
from app.core.transaction import Principal, SecurityTransaction
from app.evaluation.corpus_v2 import corpus
from app.evaluation.statistics import classification

ROOT = Path(__file__).resolve().parents[2]


def main():
    folder = ROOT / "artifacts/iteration2"
    report = json.loads((folder / "current-v2.json").read_text(encoding="utf-8"))
    failures = json.loads((folder / "current-v2-false-negatives.json").read_text(encoding="utf-8"))
    cases = {c["id"]: c for c in corpus()}
    plain = {r["family"]: r for r in report["results"] if r["variant"] == "plain"}
    for row in failures:
        base = plain.get(row["family"])
        normalized = row["normalized_representation"]
        anchors = []
        if base:
            tx = SecurityTransaction(principal=Principal(subject="offline", tenant_id="offline"),
                operation="llm_request", payload=cases[base["id"]]["payload"])
            anchors = [inspection_views(u.text)[-1].text for u in semantic_units(tx)]
        restored = bool(anchors) and all(any(a in text for text in normalized) for a in anchors)
        details = row.get("ai_details", {})
        raw = details.get("raw_score", row["ai_score"])
        hashes = {hashlib.sha256(t.encode()).hexdigest() for t in normalized}
        observed = [w for w in details.get("windows", [])]
        if details.get("context_adjusted"):
            hypothesis = "Trusted discussion heuristic reduced the effective signal on an attack label; inspect execution intent and anaphoric follow-through."
            remedy = "Strengthen structural context discrimination using this normalized evidence, then validate on development; do not whitelist examples."
        elif not restored and row["variant"] in {"base64", "mixed_encoding", "html_entities", "unicode_escape", "punctuation", "leet", "url_twice"}:
            hypothesis = "Complete plain-case anchors are absent from the actual normalized representation; transformed or short encoded fragments may not have been recovered."
            remedy = "Inspect provenance and decoder minimum length/grouping; recover only explicitly encoded bounded fragments and test benign near-misses."
        elif row["category"] == "json_key":
            hypothesis = "Directive-bearing JSON keys are excluded from semantic input; the classifier sees values while the deterministic key scan is separate."
            remedy = "Consider bounded directive-key semantic units with explicit provenance; preserve protocol metadata and test legitimate schema keys."
        elif row["variant"] == "long_end" and base and base["ai_score"] >= row["threshold"]:
            hypothesis = "Plain attack passed the block threshold but padded input did not; window/context sensitivity is observed."
            remedy = "Review windows containing the tail instruction and compare padding placement; do not infer attention failure from score alone."
        elif raw >= .95:
            hypothesis = "The real model assigns a high injection score, but it remains below the frozen near-one blocking threshold."
            remedy = "Compare calibration FPR/FNR trade-offs or route uncertain actions for policy review; do not lower the threshold based on held-out misses."
        elif row["language"] != "en":
            hypothesis = "Non-English intent receives a subthreshold score despite normalized input; multilingual generalization remains limited."
            remedy = "Expand independent native development cases and compare multilingual/intent models with language-specific benign controls."
        elif row["category"].startswith("cross_"):
            hypothesis = "The normalized group/window evidence remains subthreshold; reconstruction alone does not supply tool authorization/data-flow semantics."
            remedy = "Check group provenance and relevant windows, then compare an explicit intent/data-flow classifier; preserve role separation."
        else:
            hypothesis = "Normalized input was inspected, but the binary injection classifier did not recognize sufficient attack intent at the deployed threshold."
            remedy = "Use task/data-flow context or a separately measured intent classifier; retain pre-execution hard invariants."
        row["initial_generic_hypothesis"] = row["probable_failure_hypothesis"]
        row["probable_failure_hypothesis"] = hypothesis
        row["remediation"] = remedy
        row["diagnostic_observations"] = {"plain_anchor_text_present": restored,
            "raw_score": raw, "effective_score": row["ai_score"], "threshold_margin": row["threshold"] - row["ai_score"],
            "measured_windows": len(observed), "window_hashes_match_normalized_inputs": all(w["view_sha256"] in hashes for w in observed) if observed else None,
            "hypothesis_is_causal_proof": False}
    destination = ROOT / "docs/iteration2/false-negative-analysis.json"
    destination.write_text(json.dumps(failures, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    groups = Counter(r["probable_failure_hypothesis"] for r in failures)
    dimensions = {}
    for split in ("calibration", "development", "test"):
        rows = [r for r in report["results"] if r["split"] == split]
        groups_to_check = {
            "benign_security_discussion": [r for r in rows if not r["malicious"] and r["category"] in {
                "security_documentation", "injection_research", "pentest_discussion", "regex_development", "security_rule_code",
                "policy_documentation", "ai_safety_paper", "education", "quoted_attack", "code_strings", "incident_response",
                "threat_intelligence", "multilingual_security"}],
            "quoted_attack": [r for r in rows if r["category"] == "quoted_attack"],
            "encoded_attack": [r for r in rows if r["malicious"] and r["variant"] in {
                "base64", "url_twice", "html_entities", "unicode_escape", "mixed_encoding"}],
            "cross_field_attack": [r for r in rows if r["malicious"] and r["category"] in {"cross_field", "cross_argument", "cross_message"}],
            "multi_turn_attack": [r for r in rows if r["malicious"] and r["category"] in {"multi_turn", "cross_message", "staged"}]}
        dimensions[split] = {group: {det: classification([{**r, "score": r[field]} for r in selected], cutoff)
            for det, field, cutoff in (("ai", "ai_score", report["ai_threshold"]), ("deterministic", "deterministic_score", .9),
                ("hybrid", "hybrid_score", report["ai_threshold"]))} for group, selected in groups_to_check.items()}
    summary = {"scope": "Derived from final measured scores and actual normalized/window metadata; no model rerun, tuning or causality claim",
        "source_fingerprint": report["source_fingerprint"], "dataset_sha256": report["dataset_sha256"],
        "failures_by_hypothesis": dict(groups), "failures_by_language": dict(Counter(r["language"] for r in failures)),
        "evaluation_dimensions": dimensions}
    (ROOT / "docs/iteration2/failure-summary.json").write_text(json.dumps(summary, indent=2)+"\n", encoding="utf-8")
    print(json.dumps({"analyzed_failures": len(failures), "hypotheses": dict(groups)}, indent=2))


if __name__ == "__main__":
    main()
