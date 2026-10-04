package aicl_test

import rego.v1

base := {
    "transaction": {
        "principal": {"authenticated": true, "subject": "alice", "tenant_id": "a", "scopes": ["repo:read", "memory:read"]},
        "operation": "llm_request", "effect": "read",
        "resource": {"name": "demo", "tenant_id": "a", "owner": "alice", "provider": "mock", "model": "demo"},
        "context": {"approval_verified": false},
        "risk": {"prompt_injection": 0, "data_exfiltration": 0, "tool_misuse": 0, "semantic_status": "not_required"},
        "budget": {"available": true, "violations": []},
    },
    "policy": {
        "models": {"allowed": [{"provider": "mock", "model": "demo"}]},
        "tools": {"allow": ["github.search"], "require_approval": ["github.create_issue"], "deny": ["shell.exec"]},
        "memory": {"quarantine_injection": true},
        "defaults": {"semantic_failure": "block_high_risk"},
        "controls": {"prompt_injection": {"semantic": {"block_threshold": 0.85, "review_threshold": 0.5}}},
    },
    "tool": {"known": true, "required_scopes": []},
    "findings": [], "high_risk": false, "memory_quarantined": false,
}

with_tx(changes) := object.union(base, {"transaction": object.union(base.transaction, changes)})

test_benign_allow if {
    result := data.aicl.decision with input as base
    result.decision == "ALLOW"
}

test_authentication_block if {
    test_input := with_tx({"principal": object.union(base.transaction.principal, {"authenticated": false})})
    result := data.aicl.decision with input as test_input
    result.decision == "BLOCK"
    "UNAUTHENTICATED" in result.reason_codes
}

test_cross_tenant_block if {
    test_input := with_tx({"resource": object.union(base.transaction.resource, {"tenant_id": "other"})})
    result := data.aicl.decision with input as test_input
    result.decision == "BLOCK"
}

test_model_not_allowed if {
    test_input := with_tx({"resource": object.union(base.transaction.resource, {"model": "unknown"})})
    result := data.aicl.decision with input as test_input
    "MODEL_NOT_ALLOWED" in result.reason_codes
}

test_unknown_tool_block if {
    test_input := with_tx({"operation": "mcp_tool_call", "resource": {"name": "unknown"}})
    result := data.aicl.decision with input as test_input
    result.decision == "BLOCK"
}

test_mutation_requires_approval if {
    test_input := with_tx({"operation": "tool_call", "effect": "external_side_effect",
                          "resource": {"name": "github.create_issue"}})
    result := data.aicl.decision with input as test_input
    result.decision == "REQUIRE_APPROVAL"
}

test_approved_mutation_allow if {
    test_input := with_tx({"operation": "tool_call", "effect": "external_side_effect",
                          "resource": {"name": "github.create_issue"}, "context": {"approval_verified": true}})
    result := data.aicl.decision with input as test_input
    result.decision == "ALLOW"
}

test_destructive_block_even_approved if {
    test_input := with_tx({"operation": "tool_call", "effect": "destructive",
                          "resource": {"name": "github.create_issue"}, "context": {"approval_verified": true}})
    result := data.aicl.decision with input as test_input
    result.decision == "BLOCK"
}

test_missing_scope_block if {
    test_input := object.union(with_tx({"operation": "tool_call", "resource": {"name": "github.search"}}),
                               {"tool": {"known": true, "required_scopes": ["repo:admin"]}})
    result := data.aicl.decision with input as test_input
    "TOOL_SCOPE_MISSING" in result.reason_codes
}

test_semantic_high_risk_block if {
    test_input := with_tx({"risk": object.union(base.transaction.risk,
                         {"prompt_injection": 0.9, "semantic_status": "ok"})})
    result := data.aicl.decision with input as test_input
    result.decision == "BLOCK"
}

test_semantic_unavailable_high_risk_block if {
    test_input := object.union(with_tx({"risk": object.union(base.transaction.risk,
                                      {"semantic_status": "unavailable"})}), {"high_risk": true})
    result := data.aicl.decision with input as test_input
    result.decision == "BLOCK"
}

test_budget_failure_block if {
    test_input := with_tx({"budget": {"available": false, "violations": []}})
    result := data.aicl.decision with input as test_input
    result.decision == "BLOCK"
}

test_agent_limit_terminates if {
    test_input := with_tx({"budget": {"available": false, "violations": ["MAX_AGENT_STEPS_EXCEEDED"]}})
    result := data.aicl.decision with input as test_input
    result.decision == "TERMINATE"
}

test_memory_injection_quarantines if {
    test_input := object.union(with_tx({"operation": "memory_write",
                  "principal": object.union(base.transaction.principal, {"scopes": ["memory:write"]})}),
                  {"findings": [{"code": "PROMPT_INJECTION_PATTERN", "control": "prompt-patterns", "action": "BLOCK"}]})
    result := data.aicl.decision with input as test_input
    result.decision == "QUARANTINE"
}

test_cross_tenant_never_quarantines_foreign_record if {
    test_input := object.union(with_tx({"operation": "memory_read",
                  "resource": object.union(base.transaction.resource, {"tenant_id": "other"})}),
                  {"findings": [{"code": "PROMPT_INJECTION_PATTERN", "control": "prompt-patterns", "action": "BLOCK"}]})
    result := data.aicl.decision with input as test_input
    result.decision == "BLOCK"
}

test_pii_redaction if {
    test_input := object.union(base, {"findings": [{"code": "PII_DETECTED", "control": "pii-scanner", "action": "REDACT"}]})
    result := data.aicl.decision with input as test_input
    result.decision == "REDACT"
}

test_unknown_operation_defaults_deny if {
    result := data.aicl.decision with input as with_tx({"operation": "unknown_operation"})
    result.decision == "BLOCK"
    "OPERATION_NOT_ALLOWED" in result.reason_codes
}

test_unknown_agent_defaults_deny if {
    result := data.aicl.decision with input as with_tx({"operation": "agent_message"})
    "AGENT_NOT_ALLOWED" in result.reason_codes
}

test_semantic_review_requires_approval if {
    test_input := with_tx({"risk": object.union(base.transaction.risk,
                         {"prompt_injection": 0.65, "semantic_status": "ok"})})
    result := data.aicl.decision with input as test_input
    result.decision == "REQUIRE_APPROVAL"
}

test_quarantine_cannot_bypass_budget if {
    test_input := object.union(with_tx({"operation": "memory_write",
                  "principal": object.union(base.transaction.principal, {"scopes": ["memory:write"]}),
                  "budget": {"available": false, "violations": ["CREDIT_LIMIT_EXCEEDED"]}}),
                  {"findings": [{"code": "PROMPT_INJECTION_PATTERN", "control": "prompt-patterns", "action": "BLOCK"}]})
    result := data.aicl.decision with input as test_input
    result.decision == "BLOCK"
}
