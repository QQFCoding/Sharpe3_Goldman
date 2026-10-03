package aicl

import rego.v1

violations contains {"code": "OPERATION_NOT_ALLOWED", "control": "operation-authz", "action": "BLOCK"} if {
    not input.transaction.operation in {"llm_request", "llm_response", "mcp_tool_call", "tool_call",
                                       "memory_read", "memory_write", "agent_message", "api_call"}
}

violations contains {"code": "AGENT_NOT_ALLOWED", "control": "agent-authz", "action": "BLOCK"} if {
    input.transaction.operation == "agent_message"
    agents := object.get(input.policy, "agents", {"allowed": []})
    not input.transaction.resource.name in agents.allowed
}

violations contains {"code": "AGENT_SCOPE_MISSING", "control": "agent-authz", "action": "BLOCK"} if {
    input.transaction.operation == "agent_message"
    not "agents:message" in input.transaction.principal.scopes
}

violations contains {"code": "API_NOT_ALLOWED", "control": "tool-authz", "action": "BLOCK"} if {
    input.transaction.operation == "api_call"
    apis := object.get(input.policy, "apis", {"allowed": []})
    not input.transaction.resource.name in apis.allowed
}

# Findings are facts from protocol-independent scanners. No model authorizes anything.
violations contains {"code": f.code, "control": f.control, "action": f.action} if {
    some f in input.findings
    f.action != "ALLOW"
}

violations contains {"code": "UNAUTHENTICATED", "control": "authentication", "action": "BLOCK"} if {
    input.transaction.principal.authenticated != true
}

violations contains {"code": "CROSS_TENANT_ACCESS", "control": "tenant-boundary", "action": "BLOCK"} if {
    tenant := input.transaction.resource.tenant_id
    tenant != null
    tenant != input.transaction.principal.tenant_id
}

violations contains {"code": "UNAUTHORIZED_OWNER", "control": "memory-authz", "action": "BLOCK"} if {
    input.transaction.operation in {"memory_read", "memory_write"}
    owner := input.transaction.resource.owner
    owner != null
    owner != input.transaction.principal.subject
    not "memory:admin" in input.transaction.principal.scopes
}

violations contains {"code": "MODEL_NOT_ALLOWED", "control": "model-allowlist", "action": "BLOCK"} if {
    input.transaction.operation in {"llm_request", "llm_response"}
    not model_allowed
}

model_allowed if {
    some model in input.policy.models.allowed
    model.provider == input.transaction.resource.provider
    model.model == input.transaction.resource.model
}

violations contains {"code": "BUDGET_UNAVAILABLE", "control": "budget", "action": "BLOCK"} if {
    input.transaction.budget.available != true
    count(input.transaction.budget.violations) == 0
}

violations contains {"code": code, "control": "budget", "action": action} if {
    some code in input.transaction.budget.violations
    action := budget_action(code)
}

budget_action(code) := "TERMINATE" if {
    code in {"MAX_AGENT_STEPS_EXCEEDED", "MAX_LLM_CALLS_EXCEEDED", "MAX_TOOL_CALLS_EXCEEDED",
             "MAX_WORKFLOW_DEPTH_EXCEEDED", "MAX_WALL_TIME_EXCEEDED"}
} else := "BLOCK"

semantic_score := max([input.transaction.risk.prompt_injection,
                       input.transaction.risk.data_exfiltration, input.transaction.risk.tool_misuse])

violations contains {"code": "SEMANTIC_HIGH_RISK", "control": "semantic", "action": "BLOCK"} if {
    input.transaction.risk.semantic_status == "ok"
    semantic_score >= input.policy.controls.prompt_injection.semantic.block_threshold
}

violations contains {"code": "SEMANTIC_REVIEW_REQUIRED", "control": "semantic", "action": "REQUIRE_APPROVAL"} if {
    input.transaction.risk.semantic_status == "ok"
    semantic_score >= input.policy.controls.prompt_injection.semantic.review_threshold
    not input.transaction.context.approval_verified
}

violations contains {"code": "SEMANTIC_UNAVAILABLE", "control": "semantic", "action": "BLOCK"} if {
    input.transaction.risk.semantic_status == "unavailable"
    input.policy.defaults.semantic_failure == "block_all"
}

violations contains {"code": "SEMANTIC_UNAVAILABLE", "control": "semantic", "action": "BLOCK"} if {
    input.transaction.risk.semantic_status == "unavailable"
    input.policy.defaults.semantic_failure == "block_high_risk"
    input.high_risk
}

violations contains {"code": "SEMANTIC_UNAVAILABLE", "control": "semantic", "action": "WARN"} if {
    input.transaction.risk.semantic_status == "unavailable"
    input.policy.defaults.semantic_failure == "warn"
}

priorities := {"ALLOW": 0, "WARN": 10, "REDACT": 20, "REQUIRE_APPROVAL": 30,
               "QUARANTINE": 40, "BLOCK": 50, "TERMINATE": 60}
rank := max(array.concat([0], [priorities[v.action] | some v in violations]))
action := name if {
    some name, weight in priorities
    weight == rank
}

quarantine if {
    action == "BLOCK"
    input.transaction.operation in {"memory_read", "memory_write"}
    input.policy.memory.quarantine_injection
    not forbidden_memory_access
    some v in violations
    v.code in {"PROMPT_INJECTION_PATTERN", "SEMANTIC_HIGH_RISK", "THREAT_SIGNATURE_MATCH"}
}

forbidden_memory_access if {
    some v in violations
    v.code in {"UNAUTHENTICATED", "CROSS_TENANT_ACCESS", "UNAUTHORIZED_OWNER", "MEMORY_SCOPE_MISSING"}
}

forbidden_memory_access if input.transaction.budget.available != true

forbidden_memory_access if {
    some v in violations
    v.control in {"schema", "size", "budget", "availability", "secret-scanner", "output-schema"}
}

final_action := "QUARANTINE" if quarantine else := action

decision := {
    "decision": final_action,
    "reason_codes": sort({v.code | some v in violations}),
    "controls": sort({v.control | some v in violations}),
}
