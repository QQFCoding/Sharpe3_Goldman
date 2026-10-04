import pytest

from app.evaluation.corpus_v3 import corpus, quality


def test_fresh_families_and_translations_stay_in_one_split():
    rows=corpus()
    q=quality(rows)
    assert q["samples"]==4102 and q["base_authoring_families"]==300
    assert q["cohorts"]=={"known_v2":2688,"fresh_v3":1414}
    assert q["family_leakage"]==0 and q["duplicate_payloads"]==0
    assert len({r["id"] for r in rows})==len(rows)
    for family in {r["family"] for r in rows if r.get("cohort")=="fresh_v3"}:
        members=[r for r in rows if r["family"]==family]
        assert len({r["split"] for r in members})==1
    altered=[dict(r) for r in corpus(supplement_only=True)]
    family=altered[0]["family"]
    altered.append(altered[0]|{"split":"test" if altered[0]["split"]!="test" else "development","payload_sha256":"new","id":"leak"})
    with pytest.raises(ValueError,match="Family leakage: "+family):
        quality(altered)
