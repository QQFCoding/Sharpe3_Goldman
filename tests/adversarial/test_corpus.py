import json

import pytest

from app.settings import ROOT
from tests.conftest import chat_body

CASES = [json.loads(line) for line in (ROOT / "tests/corpus/requests.jsonl").read_text().splitlines()]


@pytest.mark.parametrize("case", CASES, ids=[f"{i}-{c['decision']}" for i, c in enumerate(CASES)])
async def test_positive_and_negative_corpus(running, case):
    client, runtime = running
    response = await client.post("/v1/chat/completions", json=chat_body(case["text"]))
    assert response.json()["security"]["decision"] == case["decision"], response.text
    assert len(runtime.llm_spy.calls) == (0 if case["decision"] == "BLOCK" else 1)
