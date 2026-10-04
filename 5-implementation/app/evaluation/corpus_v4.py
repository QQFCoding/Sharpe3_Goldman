"""New v4-only scenarios. No v2/v3 family IDs or exact payloads are reused."""
import copy
import hashlib
import json
import random
from collections import Counter

from app.evaluation.corpus_v2 import quality as family_quality
from app.evaluation.transforms import transform
from app.settings import ROOT

VERSION = "final-native-authority-v4"


def corpus():
    seeds = json.loads((ROOT / "config/evaluation-seeds-v4.json").read_text(encoding="utf-8"))
    rows, seen = [], {}
    for seed in seeds:
        for variant in ("plain", "base64", "unicode_escape", "url_twice"):
            def visit(value):
                if isinstance(value, dict):
                    return {k: v if k in {"role", "name"} else visit(v) for k, v in value.items()}
                if isinstance(value, list):
                    return [visit(v) for v in value]
                return transform(value, variant) if isinstance(value, str) else value
            payload = visit(copy.deepcopy(seed["payload"])) if "payload" in seed else {
                "messages": [{"role": "user", "content": transform(seed["text"], variant)}]}
            digest = hashlib.sha256(json.dumps(payload, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
            if digest in seen:
                if seen[digest] != (seed["family"], seed["language"]):
                    raise ValueError("Duplicate authored scenario: " + seed["family"])
                continue
            seen[digest] = (seed["family"], seed["language"])
            rows.append({k: v for k, v in seed.items() if k not in {"text", "payload"}} | {
                "id": f"{seed['family']}-{seed['language']}-{variant}", "variant": variant,
                "payload": payload, "payload_sha256": digest, "cohort": "fresh_v4"})
    random.Random(20261007).shuffle(rows)
    quality(rows)
    return rows


def quality(rows):
    result = family_quality(rows)
    result.update(protocol=VERSION, seed=20261007, cohorts=dict(Counter(r["cohort"] for r in rows)),
        limitations="Authored synthetic native-language authority/disclosure supplement; 18 authoring families translated into ten languages, not 180 independent mechanisms. Four correlated transformations. V2/v3 outcomes are known regression evidence. V4 test predictions must only be opened after implementation freeze; authors know the test text. No external population estimate.")
    return result
