package aicl
import rego.v1

flow := object.get(input, "data_flow", {"enabled": false})

violations contains {"code": "CONFIDENTIAL_DATA_TO_EXTERNAL_SINK", "control": "information-flow", "action": "BLOCK"} if {
    flow.enabled
    input.transaction.context.phase == "input"
    flow.external_sink
    some classification in flow.confidentiality
    classification in {"private", "secret"}
    not classification in flow.declassified
}

violations contains {"code": "UNTRUSTED_DATA_CONTROLS_HIGH_IMPACT_ACTION", "control": "information-flow", "action": "BLOCK"} if {
    flow.enabled
    input.transaction.context.phase == "input"
    flow.untrusted
    input.transaction.effect in {"destructive", "code_execution"}
}

violations contains {"code": "DATA_FLOW_POLICY_VIOLATION", "control": "information-flow", "action": action} if {
    flow.enabled
    input.transaction.context.phase == "input"
    flow.untrusted
    input.transaction.effect in {"write", "external_side_effect"}
    input.transaction.operation in {"mcp_tool_call", "tool_call", "api_call", "agent_message"}
    not input.transaction.context.approval_verified
    action := input.policy.information_flow.untrusted_to_mutating
}

violations contains {"code": "INTENT_EFFECT_NOT_PERMITTED", "control": "task-alignment", "action": "BLOCK"} if {
    intent := object.get(input, "trusted_intent", null)
    intent != null
    input.transaction.context.phase == "input"
    not input.transaction.effect in intent.allowed_effects
}

violations contains {"code": "INTENT_RESOURCE_NOT_PERMITTED", "control": "task-alignment", "action": "BLOCK"} if {
    intent := object.get(input, "trusted_intent", null)
    intent != null
    input.transaction.context.phase == "input"
    input.transaction.operation in {"tool_call", "mcp_tool_call", "api_call", "agent_message"}
    not input.transaction.resource.name in intent.allowed_resources
}

violations contains {"code": "TASK_GOAL_DEVIATION", "control": "task-alignment", "action": "BLOCK"} if {
    input.transaction.context.phase == "input"
    input.transaction.risk.alignment_status == "ok"
    input.transaction.risk.alignment_confidence >= input.policy.task_alignment.minimum_confidence
    input.transaction.risk.task_alignment < input.policy.task_alignment.block_below
}

alignment_uncertain if {
    input.transaction.risk.alignment_status == "unavailable"
}
alignment_uncertain if {
    input.transaction.risk.alignment_status == "ok"
    input.transaction.risk.task_alignment < input.policy.task_alignment.approve_below
}
alignment_uncertain if {
    input.transaction.risk.alignment_status == "ok"
    input.transaction.risk.alignment_confidence < input.policy.task_alignment.minimum_confidence
}

violations contains {"code": "TASK_ALIGNMENT_UNCERTAIN", "control": "task-alignment", "action": "REQUIRE_APPROVAL"} if {
    input.transaction.context.phase == "input"
    alignment_uncertain
    input.transaction.effect != "read"
    not input.transaction.context.approval_verified
}

violations contains {"code": "TASK_ALIGNMENT_UNCERTAIN", "control": "task-alignment", "action": action} if {
    input.transaction.context.phase == "input"
    alignment_uncertain
    input.transaction.effect == "read"
    action := input.policy.task_alignment.uncertain_read
    action != "ALLOW"
}

violations contains {"code": "TASK_EXFILTRATION_INTENT", "control": "task-alignment", "action": "BLOCK"} if {
    input.transaction.risk.alignment_status == "ok"
    input.transaction.risk.alignment_confidence >= input.policy.task_alignment.minimum_confidence
    input.transaction.risk.data_exfiltration_intent >= 0.85
}

violations contains {"code": "UNEXPECTED_SIDE_EFFECT", "control": "task-alignment", "action": "REQUIRE_APPROVAL"} if {
    input.transaction.context.phase == "input"
    input.transaction.risk.alignment_status == "ok"
    input.transaction.risk.unexpected_side_effect >= 0.5
    not input.transaction.context.approval_verified
}

violations contains {"code": "DELEGATION_WORKFLOW_BOUNDARY", "control": "delegation", "action": "BLOCK"} if {
    workflow := object.get(input.transaction.principal, "delegated_workflow", null)
    workflow != null
    workflow != input.transaction.context.workflow.workflow_id
}

violations contains {"code": "MAX_DELEGATION_DEPTH_EXCEEDED", "control": "delegation", "action": "BLOCK"} if {
    limits := object.get(input.policy, "delegation", {"max_depth": 4})
    object.get(input.transaction.principal, "delegation_depth", 0) > limits.max_depth
}

violations contains {"code": "DELEGATION_PEER_NOT_ALLOWED", "control": "delegation", "action": "BLOCK"} if {
    object.get(input.transaction.principal, "delegated_workflow", null) != null
    not input.transaction.principal.agent_id in input.policy.delegation.allowed_peers
}
