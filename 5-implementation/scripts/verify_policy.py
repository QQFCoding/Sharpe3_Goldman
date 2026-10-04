"""Bounded offline properties against the actual Rego, with concrete synthetic counterexamples."""
import asyncio
import itertools
import json
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

from bootstrap import install_opa

from app.adapters.tools import TOOLS
from app.controls.information_flow import facts as flow_facts
from app.core.auth import DEMO_SCOPES
from app.core.delegation import DelegationRequest, DelegationStore
from app.core.labels import DataSecurityLabel
from app.core.pipeline import Pipeline
from app.core.transaction import Effect, Operation, Principal, Resource, SecurityTransaction
from app.core.workflows import WorkflowStore
from app.policy.engine import OpaEngine
from app.policy.loader import Declassification, PolicyStore
from app.settings import ROOT


def bounded_cases():
    policy = PolicyStore(ROOT / "config/policy.yaml").active.policy
    cases = []
    def add(category, tx, expected, label=None, scoped=False):
        local = policy.model_copy(deep=True)
        if scoped:
            local.information_flow.declassification = [Declassification(sinks=[tx.resource.name],
                classifications={"private", "secret"}, required_scope="data:declassify")]
        tx.metadata["data_flow"] = flow_facts(tx, label or DataSecurityLabel(), local)
        data = {"transaction": tx.model_dump(mode="json"), "policy": local.model_dump(mode="json"),
            **Pipeline.facts(SimpleNamespace(tools=TOOLS, semantic=None), tx, [])}
        cases.append({"id": len(cases), "category": category, "expected_permitted": expected, "input": data})
    def tx(name, operation=Operation.TOOL_CALL, approval=False, scopes=None):
        tool = TOOLS.get(name)
        value = SecurityTransaction(principal=Principal(subject="alice", tenant_id="a", scopes=scopes or DEMO_SCOPES),
            operation=operation, resource=Resource(name=name), effect=tool.effect if tool else Effect.READ, payload={})
        value.context.approval_verified = approval
        return value
    for classification, sink, approval, scoped, scope in itertools.product(["private", "secret"],
            ["github.search", "github.create_issue", "email.send", "filesystem.write", "network.fetch"], [False, True], [False, True], [False, True]):
        value = tx(sink, approval=approval, scopes=DEMO_SCOPES + (["data:declassify"] if scope else []))
        expected = scoped and scope and (approval or value.effect == Effect.READ)
        add("protected_sink", value, expected, DataSecurityLabel(confidentiality=frozenset({classification})), scoped)
    for name, approval in itertools.product(["missing", "shadowed.read", "shell.exec", "github.delete_repository"], [False, True]):
        add("unknown_or_destructive", tx(name, approval=approval), False)
    for tenant, owner, admin in itertools.product(["a", "b"], ["alice", "bob"], [False, True]):
        value = tx("memory", Operation.MEMORY_READ, scopes=DEMO_SCOPES + (["memory:admin"] if admin else []))
        value.resource.tenant_id, value.resource.owner = tenant, owner
        add("memory_boundary", value, tenant == "a" and (owner == "alice" or admin))
    for provider, model in itertools.product(["mock", "unknown"], ["demo", "unknown"]):
        value = tx(model, Operation.LLM_REQUEST)
        value.resource.provider, value.resource.model = provider, model
        add("model_allowlist", value, provider == "mock" and model == "demo")
    return cases


async def delegation_properties():
    store = DelegationStore(WorkflowStore())
    from app.policy.loader import DelegationPolicy
    parent = Principal(subject="alice", tenant_id="a", agent_id="root", scopes=["agents:delegate", "read"], capabilities=["read"])
    checked = 0
    for scopes, capabilities in itertools.product([[], ["read"], ["write"], ["read", "write"]], repeat=2):
        request = DelegationRequest(agent_id="demo-child", workflow_id="w", scopes=scopes, capabilities=capabilities)
        expected = set(scopes) <= set(parent.scopes) and set(capabilities) <= set(parent.capabilities)
        try:
            _, child = await store.issue(parent, request, DelegationPolicy())
            permitted = set(child.scopes) <= set(parent.scopes) and set(child.capabilities) <= set(parent.capabilities)
        except PermissionError:
            permitted = False
        if permitted != expected:
            raise AssertionError({"category": "child_subset", "request": request.model_dump(), "expected": expected})
        checked += 1
    return checked


def main():
    cases = bounded_cases()
    opa = install_opa()
    engine = OpaEngine(None, "offline", opa)
    # Evaluate exactly as the gateway does, including input-dependent complete rules.
    with ThreadPoolExecutor(max_workers=8) as workers:
        verdicts = list(workers.map(lambda case: engine._cli(case["input"]), cases))
    values = [{"id": case["id"], "verdict": verdict} for case, verdict in zip(cases, verdicts, strict=True)]
    assert len(values) == len(cases), f"OPA verdicts missing: {sorted(set(range(len(cases))) - {row['id'] for row in values})}"
    failures = [{"case": cases[row["id"]], "actual": row["verdict"]} for row in values
        if (row["verdict"]["decision"] in {"ALLOW", "WARN", "REDACT"}) != cases[row["id"]]["expected_permitted"]]
    count = asyncio.run(delegation_properties())
    report = {"rego_states": len(cases), "delegation_states": count, "failures": failures,
        "boundary": "Bounded properties; not a formal proof over all policies or application implementations."}
    (ROOT / "artifacts").mkdir(exist_ok=True)
    (ROOT / "artifacts/policy-verification.json").write_text(json.dumps(report, indent=2) + "\n")
    if failures:
        raise SystemExit("POLICY_COUNTEREXAMPLE: " + json.dumps(failures[0]))
    print(f"Verified {len(cases)} Rego states and {count} child-capability states.")


if __name__ == "__main__":
    main()
