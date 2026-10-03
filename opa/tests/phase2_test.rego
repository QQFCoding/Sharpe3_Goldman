package aicl_test
import rego.v1

flow_base := {"enabled": true, "untrusted": false, "confidentiality": ["private"],
              "external_sink": true, "declassified": []}

test_private_sink_block_even_approved if {
    tx := object.union(base.transaction, {"context": {"phase": "input", "approval_verified": true}})
    i := object.union(base, {"transaction": tx, "data_flow": flow_base})
    result := data.aicl.decision with input as i
    result.decision == "BLOCK"
    "CONFIDENTIAL_DATA_TO_EXTERNAL_SINK" in result.reason_codes
}

test_explicit_declassification if {
    tx := object.union(base.transaction, {"context": {"phase": "input", "approval_verified": true}})
    flow := object.union(flow_base, {"declassified": ["private"]})
    i := object.union(base, {"transaction": tx, "data_flow": flow})
    result := data.aicl.decision with input as i
    result.decision == "ALLOW"
}

test_untrusted_destructive_flow if {
    tx := object.union(base.transaction, {"effect": "destructive", "context": {"phase": "input", "approval_verified": true}})
    flow := object.union(flow_base, {"untrusted": true, "external_sink": false})
    i := object.union(base, {"transaction": tx, "data_flow": flow})
    result := data.aicl.decision with input as i
    "UNTRUSTED_DATA_CONTROLS_HIGH_IMPACT_ACTION" in result.reason_codes
    result.decision == "BLOCK"
}

test_immutable_intent_limits_effect if {
    tx := object.union(base.transaction, {"effect": "write", "context": {"phase": "input", "approval_verified": true}})
    i := object.union(base, {"transaction": tx, "trusted_intent": {"allowed_effects": ["read"], "allowed_resources": []}})
    result := data.aicl.decision with input as i
    result.decision == "BLOCK"
    "INTENT_EFFECT_NOT_PERMITTED" in result.reason_codes
}

test_uncertain_alignment_review if {
    tx := object.union(base.transaction, {"effect": "write", "context": {"phase": "input", "approval_verified": false},
        "risk": object.union(base.transaction.risk, {"alignment_status": "unavailable"})})
    i := object.union(base, {"transaction": tx})
    result := data.aicl.decision with input as i
    result.decision == "REQUIRE_APPROVAL"
    "TASK_ALIGNMENT_UNCERTAIN" in result.reason_codes
}

test_uncertain_injection_read_warn if {
    risk := object.union(base.transaction.risk, {"semantic_status": "ok", "prompt_injection": 0.7})
    tx := object.union(base.transaction, {"risk": risk})
    semantic := object.union(base.policy.controls.prompt_injection.semantic, {"uncertain_read": "WARN"})
    controls := object.union(base.policy.controls, {"prompt_injection": {"semantic": semantic}})
    policy := object.union(base.policy, {"controls": controls})
    result := data.aicl.decision with input as object.union(base, {"transaction": tx, "policy": policy})
    result.decision == "WARN"
}

test_uncertain_injection_read_allow if {
    risk := object.union(base.transaction.risk, {"semantic_status": "ok", "prompt_injection": 0.7})
    tx := object.union(base.transaction, {"risk": risk})
    semantic := object.union(base.policy.controls.prompt_injection.semantic, {"uncertain_read": "ALLOW"})
    controls := object.union(base.policy.controls, {"prompt_injection": {"semantic": semantic}})
    policy := object.union(base.policy, {"controls": controls})
    result := data.aicl.decision with input as object.union(base, {"transaction": tx, "policy": policy})
    result.decision == "ALLOW"
}
