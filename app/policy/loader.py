import asyncio
from pathlib import Path
from typing import Annotated, Literal

import yaml
from pydantic import Field, model_validator

from app.core.transaction import StrictModel
from app.threatintel.loader import ThreatFeed


class Metadata(StrictModel):
    revision: str = Field(min_length=1, max_length=128)


class Defaults(StrictModel):
    decision: Literal["deny"] = "deny"
    unknown_tool: Literal["deny"] = "deny"
    unknown_model: Literal["deny"] = "deny"
    semantic_failure: Literal["block_high_risk", "block_all", "warn"] = "block_high_risk"


class ScanControl(StrictModel):
    enabled: bool = True
    input_action: Literal["ALLOW", "REDACT", "BLOCK"]
    output_action: Literal["ALLOW", "REDACT", "BLOCK"]


class SemanticConfig(StrictModel):
    enabled: bool = True
    always_scan: bool = False
    review_threshold: float = Field(default=0.5, ge=0, le=1)
    block_threshold: float = Field(default=0.85, ge=0, le=1)

    @model_validator(mode="after")
    def thresholds(self):
        if self.review_threshold > self.block_threshold:
            raise ValueError("review_threshold must be <= block_threshold")
        return self


class InjectionConfig(StrictModel):
    enabled: bool = True
    deterministic_enabled: bool = True
    semantic: SemanticConfig = Field(default_factory=SemanticConfig)


class Controls(StrictModel):
    pii: ScanControl = Field(
        default_factory=lambda: ScanControl(input_action="REDACT", output_action="REDACT")
    )
    secrets: ScanControl = Field(
        default_factory=lambda: ScanControl(input_action="BLOCK", output_action="BLOCK")
    )
    prompt_injection: InjectionConfig = Field(default_factory=InjectionConfig)


class ModelEntry(StrictModel):
    provider: str
    model: str


class Models(StrictModel):
    allowed: list[ModelEntry]


class NamedResources(StrictModel):
    allowed: list[str] = Field(default_factory=list)


class Tools(StrictModel):
    default: Literal["deny"] = "deny"
    allow: list[str] = Field(default_factory=list)
    require_approval: list[str] = Field(default_factory=list)
    deny: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def disjoint(self):
        all_names = self.allow + self.require_approval + self.deny
        if len(set(all_names)) != len(all_names):
            raise ValueError("Tool policy lists must be disjoint")
        return self


class MemoryPolicy(StrictModel):
    enforce_tenant_boundary: Literal[True] = True
    scan_before_write: bool = True
    scan_after_read: bool = True
    quarantine_injection: bool = True
    max_ttl_seconds: int = Field(default=86400, ge=1, le=31536000)


class NetworkPolicy(StrictModel):
    block_loopback: bool = True
    block_private_ips: bool = True
    block_link_local: bool = True
    block_reserved: bool = True
    validate_redirects: Literal[True] = True
    resolve_dns: bool = True


class Limits(StrictModel):
    max_steps: int = Field(default=25, ge=1, le=100000)
    max_llm_calls: int = Field(default=20, ge=1, le=100000)
    max_tool_calls: int = Field(default=20, ge=1, le=100000)
    max_depth: int = Field(default=8, ge=0, le=100)
    max_wall_time_seconds: int = Field(default=120, ge=1, le=86400)
    token_limit: int = Field(default=100000, ge=1)
    credit_limit: float = Field(default=100, gt=0, allow_inf_nan=False)
    concurrent_requests: int = Field(default=4, ge=1, le=1000)
    reservation_ttl_seconds: int = Field(default=60, ge=1, le=600)


class UserLimits(StrictModel):
    requests_per_minute: int = Field(default=60, ge=1, le=100000)


class Budgets(StrictModel):
    per_agent: Limits = Field(default_factory=Limits)
    per_user: UserLimits = Field(default_factory=UserLimits)


class SizeLimits(StrictModel):
    request_bytes: int = Field(default=65536, ge=1, le=262144)
    response_bytes: int = Field(default=65536, ge=1, le=1048576)
    max_input_tokens: int = Field(default=16000, ge=1, le=1000000)
    max_output_tokens: int = Field(default=2048, ge=1, le=1000000)


class ThreatConfig(StrictModel):
    enabled: bool = True
    source: str = "threat-feed.yaml"


class AuditPolicy(StrictModel):
    store_raw_prompts: Literal[False] = False


class ModelCost(StrictModel):
    per_1000_input_tokens: float = Field(default=1, ge=0, allow_inf_nan=False)
    per_1000_output_tokens: float = Field(default=2, ge=0, allow_inf_nan=False)


class ResourceCosts(StrictModel):
    models: dict[str, ModelCost] = Field(default_factory=dict)
    tools: dict[str, Annotated[float, Field(ge=0, allow_inf_nan=False)]] = Field(default_factory=dict)
    default_tool: float = Field(default=1, ge=0, allow_inf_nan=False)


class Policy(StrictModel):
    apiVersion: Literal["aicl/v1"] = "aicl/v1"
    metadata: Metadata
    mode: Literal["enforce"] = "enforce"
    defaults: Defaults = Field(default_factory=Defaults)
    models: Models
    agents: NamedResources = Field(default_factory=NamedResources)
    apis: NamedResources = Field(default_factory=NamedResources)
    controls: Controls = Field(default_factory=Controls)
    tools: Tools
    memory: MemoryPolicy = Field(default_factory=MemoryPolicy)
    network: NetworkPolicy = Field(default_factory=NetworkPolicy)
    budgets: Budgets = Field(default_factory=Budgets)
    limits: SizeLimits = Field(default_factory=SizeLimits)
    threat_intelligence: ThreatConfig = Field(default_factory=ThreatConfig)
    audit: AuditPolicy = Field(default_factory=AuditPolicy)
    resource_costs: ResourceCosts = Field(default_factory=ResourceCosts)


class PolicySnapshot(StrictModel):
    policy: Policy
    feed: ThreatFeed


class PolicyStore:
    """Publish a fully validated policy/feed pair with one atomic reference swap."""

    def __init__(self, path: Path):
        self.path = path
        self._lock = asyncio.Lock()
        self.active = self._load()
        self.last_known_good = self.active

    def _load(self) -> PolicySnapshot:
        policy = Policy.model_validate(yaml.safe_load(self.path.read_text(encoding="utf-8")))
        feed_path = self.path.parent / policy.threat_intelligence.source
        feed = (
            ThreatFeed.load(feed_path)
            if policy.threat_intelligence.enabled
            else ThreatFeed(revision="disabled")
        )
        return PolicySnapshot(policy=policy, feed=feed)

    async def reload(self) -> PolicySnapshot:
        async with self._lock:
            candidate = await asyncio.to_thread(self._load)
            if (
                candidate.policy != self.active.policy
                and candidate.policy.metadata.revision == self.active.policy.metadata.revision
            ):
                raise ValueError("Policy semantics changed without a new revision")
            self.last_known_good = self.active
            self.active = candidate
            return candidate
