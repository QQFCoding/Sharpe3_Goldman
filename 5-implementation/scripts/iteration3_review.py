"""Combine independently measured cohorts; never invent or reuse model scores."""
import hashlib
import json

from app.evaluation.corpus_v3 import corpus, quality
from app.evaluation.evidence import source_fingerprint
from app.evaluation.statistics import latency
from app.settings import ROOT
from scripts.robustness_eval import summarize


def read(name):
    return json.loads((ROOT/name).read_text(encoding="utf-8"))


def main():
    folder=ROOT/"artifacts/iteration3"
    regression=read("artifacts/iteration3/current-v2.json")
    fresh=read("artifacts/iteration3/current-fresh-v3.json")
    binding=source_fingerprint()
    for report in (regression,fresh):
        if not report["evidence_stable"] or report["source_fingerprint"]!=binding or report["model_failures"]:
            raise ValueError("Incomplete, stale or unavailable cohort measurements")
    if regression["ai_threshold"]!=fresh["ai_threshold"] or regression["model_revision"]!=fresh["model_revision"]:
        raise ValueError("Different model/threshold across cohorts")
    rows=[*regression["results"],*fresh["results"]]
    cases=corpus()
    actual={r["id"]:r["payload_sha256"] for r in rows}
    expected={r["id"]:r["payload_sha256"] for r in cases}
    if len(actual)!=len(rows) or actual!=expected:
        raise ValueError("Combined measurements do not match the complete v3 manifest")
    combined={**regression,"protocol":"adversarial-control-v3","implementation":"iteration3-combined-cohorts",
        "dataset_sha256":hashlib.sha256(json.dumps(cases,sort_keys=True,ensure_ascii=False).encode()).hexdigest(),
        "quality":quality(cases),"results":rows,"evaluated_samples":len(rows),
        "duration_seconds":regression["duration_seconds"]+fresh["duration_seconds"],
        "splits":{s:summarize([r for r in rows if r["split"]==s],regression["ai_threshold"]) for s in ("calibration","development","test")},
        "cohort_summaries":{"known_v2":regression["splits"],"fresh_v3":fresh["splits"]},
        "performance":{name:latency([r[field] for r in rows],sum(r[field] for r in rows)/1000)
            for name,field in (("ai","ai_ms"),("deterministic","deterministic_ms"),("hybrid","total_ms"))},
        "limitations":"All 4,102 cases actually measured in two sequential cohort runs at the same source fingerprint/model/threshold. V2 test is known regression; fresh v3 test was opened after freeze. Synthetic translations and transforms are correlated. No authorization/production-traffic estimate."}
    (folder/"current-v3.json").write_text(json.dumps(combined,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    for suffix in ("false-negatives","false-positives","disagreements"):
        values=read(f"artifacts/iteration3/current-v2-{suffix}.json")+read(f"artifacts/iteration3/current-fresh-v3-{suffix}.json")
        (folder/f"current-v3-{suffix}.json").write_text(json.dumps(values,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    output=ROOT/"docs/iteration3"
    output.mkdir(exist_ok=True)
    reports={"v2_regression":regression,"fresh_v3":fresh,"combined_v3":combined,
        "previous_fresh_v3":read("artifacts/iteration3/previous-fresh-v3.json"),
        "legacy":read("artifacts/hybrid-current.json")}
    summary={name:{k:v for k,v in report.items() if k!="results"} for name,report in reports.items()}
    summary["validation"]=read("artifacts/self-test.json")
    summary["candidate_final"]= {k:v for k,v in read("artifacts/iteration3/qwen-4b-final-v3.json").items() if k!="results"}
    (output/"measurements.json").write_text(json.dumps(summary,indent=2)+"\n",encoding="utf-8")
    print(json.dumps({name:report["splits"]["test"]["metrics"] for name,report in reports.items()},indent=2))


if __name__=="__main__":
    main()
