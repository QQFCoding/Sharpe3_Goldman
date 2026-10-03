import json
import os
import shutil
from pathlib import Path

import httpx
import pytest

from app.adapters.base import UpstreamResult
from app.core.transaction import OperationRequest
from app.main import create_app
from app.semantic.base import SemanticRisk
from app.settings import ROOT, Settings


class BenignSemantic:
    def __init__(self, risk=None):
        self.calls = []
        self.risk = risk or SemanticRisk(prompt_injection=0.01)

    async def analyze(self, tx):
        self.calls.append(tx.model_copy(deep=True))
        return self.risk


class SpyAdapter:
    def __init__(self, output=None, tool=False):
        self.calls = []
        self.output = output
        self.tool = tool

    async def execute(self, tx):
        self.calls.append(tx.model_copy(deep=True))
        output = self.output
        if output is None:
            output = (
                {"result": "Safe mock tool result"}
                if self.tool
                else {"content": "Echo: " + tx.payload["messages"][-1]["content"]}
            )
        return UpstreamResult(output=output, output_tokens=1 if not self.tool else 0)


@pytest.fixture
def opa_binary():
    binary = Path(
        os.environ.get("AICL_TEST_OPA", ROOT / ".tools" / ("opa.exe" if os.name == "nt" else "opa"))
    )
    if not binary.is_file():
        pytest.fail("Real OPA is required: run python scripts/bootstrap.py --opa-only or set AICL_TEST_OPA")
    return binary


@pytest.fixture
def config_dir(tmp_path):
    for name in ("policy.yaml", "threat-feed.yaml"):
        shutil.copyfile(ROOT / "config" / name, tmp_path / name)
    return tmp_path


@pytest.fixture
async def running(config_dir, opa_binary):
    settings = Settings(_env_file=None, policy_path=config_dir / "policy.yaml", opa_binary=opa_binary)
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        runtime = app.state.runtime
        runtime.pipeline.semantic = BenignSemantic()
        runtime.llm_spy = SpyAdapter()
        runtime.tool_spy = SpyAdapter(tool=True)
        runtime.pipeline.adapters.update(mock=runtime.llm_spy, mcp=runtime.tool_spy)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://test",
            headers={"Authorization": "Bearer demo-user-token"},
        ) as client:
            yield client, runtime


def chat_body(text="Hello", **changes):
    return {"model": "demo", "messages": [{"role": "user", "content": text}], **changes}


def tool_body(name="github.search", arguments=None, **changes):
    return {
        "operation": "mcp_tool_call",
        "resource": {"name": name},
        "payload": arguments if arguments is not None else {"query": "safe query"},
        **changes,
    }


def as_request(body):
    return OperationRequest.model_validate(json.loads(json.dumps(body)))
