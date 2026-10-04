"""Known v2 regression corpus plus new family-isolated multilingual scenarios.

Translations share a family and split. They increase language coverage, not the
number of independent scenarios. Supplement-only evaluation supports fresh tests.
"""
import hashlib
import json
import random
from collections import Counter

from app.evaluation.corpus_v2 import corpus as regression_corpus
from app.evaluation.corpus_v2 import quality as check_quality
from app.evaluation.transforms import ATTACK_TRANSFORMS, BENIGN_TRANSFORMS, transform
from app.settings import ROOT

VERSION="adversarial-control-v3"


def corpus(supplement_only=False):
    rows=[] if supplement_only else regression_corpus()
    seen={r["payload_sha256"]:(r["family"],r["language"]) for r in rows}
    seeds=json.loads((ROOT/"config/evaluation-seeds-v3.json").read_text(encoding="utf-8"))
    for seed in seeds:
        variants=ATTACK_TRANSFORMS if seed["malicious"] else BENIGN_TRANSFORMS
        for variant in variants:
            import copy
            def visit(value):
                if isinstance(value,dict):
                    return {k:v if k in {"role","name"} else visit(v) for k,v in value.items()}
                if isinstance(value,list):
                    return [visit(v) for v in value]
                return transform(value,variant) if isinstance(value,str) else value
            payload=visit(copy.deepcopy(seed["payload"])) if "payload" in seed else {"messages":[{"role":"user","content":transform(seed["text"],variant)}]}
            digest=hashlib.sha256(json.dumps(payload,sort_keys=True,ensure_ascii=False).encode()).hexdigest()
            if digest in seen:
                if seen[digest]!=(seed["family"],seed["language"]):
                    raise ValueError("Duplicate authored supplement: "+seed["family"])
                continue  # A transform that leaves this script unchanged is one case.
            seen[digest]=(seed["family"],seed["language"])
            rows.append({k:v for k,v in seed.items() if k not in {"text","payload"}}|{
                "id":f"{seed['family']}-{seed['language']}-{variant}","variant":variant,"payload":payload,
                "source":seed.get("source","user"),"payload_sha256":digest,"cohort":"fresh_v3"})
    random.Random(20261006).shuffle(rows)
    quality(rows)
    return rows


def quality(rows):
    result=check_quality(rows)
    result.update(protocol=VERSION,seed=20261006,cohorts=dict(Counter(r.get("cohort","known_v2") for r in rows)),
        generated_supplement_variants=1440,
        limitations="Authored synthetic, correlated transformations. Native translations share 12 scenario families; English supplement has 24 further scenario families. V2 test is known regression data. Fresh v3 test is evaluated after code freeze, not an external-adversary population estimate.")
    return result
