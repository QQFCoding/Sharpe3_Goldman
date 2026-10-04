"""Privacy-safe normalized detector reporting, shared by gateway and live console."""
import hashlib
from datetime import UTC, datetime


def safe_finding(finding):
    body = finding.model_dump(exclude={"replacement"})
    body["path"] = [p if isinstance(p, int) or p in {"messages", "content", "text", "path", "query"}
        else "sha256:" + hashlib.sha256(str(p).encode()).hexdigest()[:16] for p in finding.path]
    return body


def detection_report(tx, decision, findings=()):
    deterministic = tx.metadata.get("deterministic_detection", {"status": "not_run", "verdict": "not_run", "score": None})
    ai = tx.metadata.get("ai_detection", {"status": "not_required", "verdict": "not_run", "score": None})
    disagreement = None
    if deterministic.get("status") == "ok" and ai.get("status") == "ok":
        disagreement = (deterministic["verdict"] == "malicious") != (ai["verdict"] == "malicious")
    score = max(deterministic.get("score") or 0, ai.get("score") or 0,
        max((f.confidence for f in findings if f.action in {"BLOCK", "QUARANTINE"}), default=0))
    return {"schema_version": "security-report-v1", "request_id": tx.request_id,
        "timestamp": datetime.now(UTC).isoformat(), "phase": tx.context.phase,
        "normalization": tx.metadata.get("normalization", {}),
        "deterministic": deterministic, "ai": ai, "disagreement": disagreement,
        "disagreement_status": "measured" if disagreement is not None else "not_comparable",
        "agreement_class": "not_comparable" if disagreement is None else
            "both_malicious" if deterministic["verdict"]=="malicious" and ai["verdict"]=="malicious" else
            "rule_only" if deterministic["verdict"]=="malicious" else
            "ai_only" if ai["verdict"]=="malicious" else "both_benign",
        "disagreement_reason": "A detector did not run successfully" if disagreement is None else
            "High-confidence rule evidence takes precedence" if disagreement and deterministic["verdict"]=="malicious" else
            "Effective model score exceeds its configured threshold without a blocking rule" if disagreement else "Blocking verdicts agree",
        "aggregation": {"strategy": "hard invariants/high-confidence rules block; contextual/weak findings warn; effective AI thresholds feed OPA",
            "risk_score": score, "score_semantics": "risk signals, not calibrated probabilities",
            "tier_counts": {tier:sum(f.evidence.get("tier","hard_invariant" if f.control!="prompt-patterns" else "high_confidence")==tier for f in findings)
                for tier in ("hard_invariant","high_confidence","contextual_heuristic","weak_signal")},
            "deterministic_override": deterministic.get("verdict") == "malicious",
            "severity": "high" if score >= .9 else "medium" if score >= .3 else "low"},
        "final": {"decision": str(decision.decision), "reason_codes": decision.reason_codes,
            "controls": decision.controls, "policy_revision": decision.policy_revision,
            "feed_revision": decision.threat_feed_revision},
        "findings": [{"finding_id": f"{tx.request_id}:{index}", **safe_finding(f)}
            for index, f in enumerate(findings)][:64],
        "evidence_policy": "No raw payloads or matched secrets retained; hashes and rule descriptions only.",
        "latencies_ms": {k: v * 1000 for k, v in tx.metadata.get("stage_latencies", {}).items()}}
