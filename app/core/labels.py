"""Server-owned data labels. Neither delimiters nor model decisions confer trust."""
from typing import Literal

from pydantic import ConfigDict, Field

from app.core.transaction import StrictModel


class DataSecurityLabel(StrictModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    integrity: Literal["trusted", "derived", "untrusted"] = "trusted"
    confidentiality: frozenset[Literal["public", "internal", "private", "secret"]] = frozenset({"public"})
    source_type: Literal["user", "system", "tool", "mcp", "memory", "rag", "agent", "api"] = "user"
    source_id: str | None = None
    tenant_id: str | None = None
    owner_id: str | None = None
    provenance: tuple[str, ...] = Field(default=(), max_length=64)
    taints: frozenset[str] = frozenset()

    @classmethod
    def join(cls, *labels, derived=False):
        if not labels:
            return cls()
        ranks = {"trusted": 0, "derived": 1, "untrusted": 2}
        integrity = max((x.integrity for x in labels), key=ranks.get)
        taints = set().union(*(x.taints for x in labels))
        if integrity == "untrusted":
            taints.add("untrusted_origin")
        if derived:
            integrity = "derived"
        return cls(
            integrity=integrity,
            confidentiality=frozenset().union(*(x.confidentiality for x in labels)),
            source_type=labels[-1].source_type,
            tenant_id=labels[-1].tenant_id,
            owner_id=labels[-1].owner_id,
            provenance=tuple(sorted(set().union(*(set(x.provenance) for x in labels)))[:64]),
            taints=frozenset(taints),
        )


def source_label(tx, source_type="user", trust=None, classification=None):
    trust = trust or tx.context.source_trust
    classification = classification or (tx.resource.classification if tx.resource else "public")
    classification = "private" if classification == "restricted" else classification
    if classification not in {"public", "internal", "private", "secret"}:
        classification = "private"  # Unknown classification is never downgraded to public.
    return DataSecurityLabel(
        integrity="untrusted" if trust == "untrusted" else "trusted",
        confidentiality=frozenset({classification}), source_type=source_type,
        source_id=tx.request_id, tenant_id=tx.principal.tenant_id, owner_id=tx.principal.subject,
        provenance=(tx.request_id,),
        taints=frozenset({"untrusted_origin"}) if trust == "untrusted" else frozenset(),
    )
