import asyncio
import json
import subprocess
from typing import Protocol

import httpx
from pydantic import BaseModel, ConfigDict, Field

from app.core.decision import Decision, DecisionResult
from app.core.transaction import SecurityTransaction
from app.policy.loader import PolicySnapshot
from app.settings import ROOT


class PolicyDecisionPoint(Protocol):
    async def evaluate(
        self, tx: SecurityTransaction, snapshot: PolicySnapshot, facts: dict
    ) -> DecisionResult: ...


class OpaDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")
    decision: Decision
    reason_codes: list[str] = Field(max_length=256)
    controls: list[str] = Field(max_length=256)


class OpaEngine:
    def __init__(self, client: httpx.AsyncClient, url: str, binary=None):
        self.client, self.url, self.binary = client, url, binary
        self._slots = asyncio.Semaphore(8)

    def _cli(self, data: dict) -> dict:
        completed = subprocess.run(
            [
                str(self.binary),
                "eval",
                "--format=json",
                "--stdin-input",
                "--data",
                str(ROOT / "opa"),
                "data.aicl.decision",
            ],
            input=json.dumps(data),
            capture_output=True,
            text=True,
            timeout=5,
            check=True,
        )
        result = json.loads(completed.stdout)
        return result["result"][0]["expressions"][0]["value"]

    async def evaluate(
        self, tx: SecurityTransaction, snapshot: PolicySnapshot, facts: dict
    ) -> DecisionResult:
        data = {"transaction": tx.model_dump(mode="json"), "policy": snapshot.policy.model_dump(mode="json"), **facts}
        try:
            async with self._slots:
                if self.binary:
                    result = await asyncio.to_thread(self._cli, data)
                else:
                    response = await self.client.post(
                        f"{self.url}/v1/data/aicl/decision", json={"input": data}, timeout=3
                    )
                    response.raise_for_status()
                    result = response.json()["result"]
            verdict = OpaDecision.model_validate(result)
        except (httpx.HTTPError, ValueError, KeyError, IndexError, OSError, subprocess.SubprocessError):
            verdict = OpaDecision(
                decision=Decision.BLOCK, reason_codes=["POLICY_ENGINE_UNAVAILABLE"], controls=["opa"]
            )
        return DecisionResult(
            **verdict.model_dump(),
            request_id=tx.request_id,
            policy_revision=snapshot.policy.metadata.revision,
            threat_feed_revision=snapshot.feed.revision,
            risk=tx.risk,
        )
