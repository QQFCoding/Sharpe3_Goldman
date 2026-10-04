"""Authoring families are split BEFORE transformations. No model training data imported.

Distinct scenarios are authoring families, not claims of independent attack mechanisms.
Translations/paraphrases of one scenario must share a family. Final cases are sealed
until the implementation and selection protocol are frozen.
"""
import hashlib
import json
import random
from collections import Counter

from app.evaluation.transforms import ATTACK_TRANSFORMS, BENIGN_TRANSFORMS, transform
from app.settings import ROOT

VERSION = "adversarial-control-v2"
SEED = 20261005


def corpus(seed=SEED):
    seeds = json.loads((ROOT / "config/evaluation-seeds-v2.json").read_text(encoding="utf-8"))
    rows, seen = [], set()
    for case in seeds:
        variants = ATTACK_TRANSFORMS if case["malicious"] else BENIGN_TRANSFORMS
        for variant in variants:
            payload = case.get("payload")
            if payload:
                # Structured cases preserve the boundary under test; transformations apply
                # independently to content, never role or provenance metadata.
                import copy
                payload = copy.deepcopy(payload)
                def visit(value):
                    if isinstance(value, dict):
                        return {k: v if k in {"role", "name"} else visit(v) for k, v in value.items()}
                    if isinstance(value, list):
                        return [visit(v) for v in value]
                    return transform(value, variant) if isinstance(value, str) else value
                payload = visit(payload)
            else:
                payload = {"messages": [{"role": "user", "content": transform(case["text"], variant)}]}
            digest = hashlib.sha256(json.dumps(payload, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
            if digest in seen:
                continue
            seen.add(digest)
            rows.append({k: v for k, v in case.items() if k not in {"text", "payload"}} | {
                "id": f"{case['family']}-{variant}", "variant": variant, "payload": payload,
                "source": case.get("source", "user"), "payload_sha256": digest})
    random.Random(seed).shuffle(rows)
    quality(rows)  # A leak is an error, never just a warning in a report.
    return rows


def quality(rows):
    families, contents = {}, {}
    for row in rows:
        family, split = row["family"], row["split"]
        if family in families and families[family] != split:
            raise ValueError("Family leakage: " + family)
        families[family] = split
        digest = row["payload_sha256"]
        if digest in contents:
            raise ValueError("Duplicate content: " + row["id"])
        contents[digest] = split
    return {"protocol": VERSION, "seed": SEED, "samples": len(rows),
        "base_authoring_families": len(families), "duplicate_payloads": 0, "family_leakage": 0,
        "split_separation_verified": True, "split_method": "scenario families assigned before any transformation; no imported training samples",
        "labels": dict(Counter("attack" if r["malicious"] else "benign" for r in rows)),
        "languages": dict(Counter(r["language"] for r in rows)),
        "variants_per_family": dict(Counter(Counter(r["family"] for r in rows).values())),
        "transforms": dict(Counter(r["variant"] for r in rows)),
        "attack_categories": dict(Counter(r["category"] for r in rows if r["malicious"])),
        "benign_categories": dict(Counter(r["category"] for r in rows if not r["malicious"])),
        "splits": {s: {"samples": sum(r["split"] == s for r in rows),
            "families": sum(v == s for v in families.values())} for s in ("calibration", "development", "test")},
        "limitations": "Synthetic and transformation-correlated. Mechanism categories overlap across splits; authoring scenarios do not. No external adversary/population estimate."}
