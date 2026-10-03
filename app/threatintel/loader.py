from pathlib import Path
from typing import Literal

import regex
import yaml
from pydantic import Field, field_validator, model_validator

from app.core.transaction import Finding, SecurityTransaction, StrictModel, text_leaves


class ThreatRule(StrictModel):
    id: str = Field(min_length=1, max_length=128)
    category: str
    severity: Literal["low", "medium", "high", "critical"] = "high"
    applies_to: list[str] = Field(default_factory=lambda: ["*"])
    regex: list[str] = Field(default_factory=list)
    tools: list[str] = Field(default_factory=list)
    packages: dict[str, list[str]] = Field(default_factory=dict)
    hashes: list[str] = Field(default_factory=list)
    mcp_servers: list[str] = Field(default_factory=list)
    action: Literal["BLOCK", "WARN", "QUARANTINE"] = "BLOCK"

    @model_validator(mode="after")
    def valid_regex(self):
        for pattern in self.regex:
            regex.compile(pattern)
        if not (self.regex or self.tools or self.packages or self.hashes or self.mcp_servers):
            raise ValueError("Threat rule requires an indicator")
        return self


class ThreatFeed(StrictModel):
    revision: str
    rules: list[ThreatRule] = Field(default_factory=list)

    @field_validator("revision", mode="before")
    @classmethod
    def normalize_revision(cls, value):
        return str(value) if type(value) is int else value

    @model_validator(mode="after")
    def unique_ids(self):
        if len({r.id for r in self.rules}) != len(self.rules):
            raise ValueError("Duplicate threat rule ids")
        return self

    @classmethod
    def load(cls, path: Path):
        return cls.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))

    def match(self, tx: SecurityTransaction) -> list[Finding]:
        kinds = {tx.operation.value, "model_output" if tx.context.phase == "output" else "prompt"}
        if tx.operation in {"tool_call", "mcp_tool_call", "api_call"}:
            kinds.add("tool_argument")
        findings = []
        for rule in self.rules:
            if "*" not in rule.applies_to and not kinds.intersection(rule.applies_to):
                continue
            name = tx.resource.name if tx.resource else ""
            matched = name in rule.tools
            matched |= bool(tx.resource and tx.resource.mcp_server in rule.mcp_servers)
            matched |= tx.metadata.get("artifact_hash") in rule.hashes
            matched |= any(
                tx.metadata.get("packages", {}).get(pkg) in versions
                for pkg, versions in rule.packages.items()
            )
            try:
                matched |= any(
                    regex.search(pattern, text, timeout=0.02)
                    for _, text in text_leaves(tx.payload)
                    for pattern in rule.regex
                )
            except TimeoutError:
                findings.append(Finding(code="THREAT_SCAN_TIMEOUT", control="threat-intel"))
                continue
            if matched:
                findings.append(
                    Finding(
                        code="THREAT_SIGNATURE_MATCH",
                        control="threat-intel",
                        action=rule.action,
                        rule_id=rule.id,
                    )
                )
        return findings
