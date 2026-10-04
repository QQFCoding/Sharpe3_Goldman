"""Warm, alternating previous/current measurements with identical real model inputs."""
import asyncio
import json
import time

from app.controls.prompt_patterns import inspect
from app.core.transaction import Principal, SecurityTransaction
from app.evaluation.evidence import source_fingerprint
from app.evaluation.hybrid_corpus import corpus
from app.evaluation.previous_v2 import detectors
from app.evaluation.statistics import latency
from app.semantic.deberta import DebertaProvider
from app.settings import ROOT


async def main():
    binding=source_fingerprint()
    previous_rules,previous_provider,_,snapshot=detectors("docs/iteration3/previous-source.zip")
    providers={"previous":previous_provider(str(ROOT/"models/deberta")),"current":DebertaProvider(str(ROOT/"models/deberta"))}
    rules={"previous":previous_rules,"current":inspect}
    def tx(text):
        return SecurityTransaction(principal=Principal(subject="paired-synthetic",tenant_id="offline"),
            operation="llm_request",payload={"messages":[{"role":"user","content":text}]})
    for provider in providers.values():
        await asyncio.to_thread(provider._load)
        await provider.analyze(tx("Public model warm-up."))
    measurements={name:[] for name in providers}
    cases=[r for r in corpus() if r["split"]=="test"]
    for repeat in range(2):
        for index,case in enumerate(cases):
            order=("previous","current") if (index+repeat)%2==0 else ("current","previous")
            for name in order:
                before=time.perf_counter()
                findings=rules[name](tx(case["text"]))
                rule_ms=(time.perf_counter()-before)*1000
                before=time.perf_counter()
                risk=await providers[name].analyze(tx(case["text"]))
                measurements[name].append({"id":case["id"],"ai_ms":(time.perf_counter()-before)*1000,"rule_ms":rule_ms,
                    "ai_score":risk.prompt_injection,"blocking_rules":sum(f.action=="BLOCK" for f in findings)})
    report={"protocol":"warm alternating 72 legacy test cases, two passes, two CPU threads, trace disabled",
        "source_fingerprint":binding,"evidence_stable":binding==source_fingerprint(),"snapshot_sha256":snapshot,
        "measurements":{name:{key:latency([r[key] for r in rows],sum(r[key] for r in rows)/1000)
            for key in ("ai_ms","rule_ms")} for name,rows in measurements.items()},
        "score_differences":sum(abs(a["ai_score"]-b["ai_score"])>1e-6 for a,b in zip(measurements["previous"],measurements["current"],strict=True)),
        "limitations":"Warm sequential local CPU microbenchmark, not service load or larger-corpus latency. Installed user services may still consume resources."}
    (ROOT/"docs/iteration3/paired-performance.json").write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
    print(json.dumps(report,indent=2))


if __name__=="__main__":
    asyncio.run(main())
