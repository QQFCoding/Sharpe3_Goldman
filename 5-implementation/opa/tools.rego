package aicl

import rego.v1

is_tool if input.transaction.operation in {"tool_call", "mcp_tool_call", "api_call"}

violations contains {"code": "UNAUTHORIZED_TOOL", "control": "tool-authz", "action": "BLOCK"} if {
    is_tool
    not input.tool.known
}

tool_listed if input.transaction.resource.name in input.policy.tools.allow
tool_listed if input.transaction.resource.name in input.policy.tools.require_approval

violations contains {"code": "UNAUTHORIZED_TOOL", "control": "tool-authz", "action": "BLOCK"} if {
    is_tool
    not tool_listed
}

violations contains {"code": "TOOL_SCOPE_MISSING", "control": "tool-authz", "action": "BLOCK"} if {
    is_tool
    some scope in input.tool.required_scopes
    not scope in input.transaction.principal.scopes
}

approval_needed if {
    is_tool
    input.transaction.resource.name in input.policy.tools.require_approval
}

approval_needed if {
    is_tool
    input.transaction.effect in {"write", "external_side_effect", "destructive", "code_execution"}
}

violations contains {"code": "APPROVAL_REQUIRED", "control": "tool-authz", "action": "REQUIRE_APPROVAL"} if {
    approval_needed
    not input.transaction.context.approval_verified
}

violations contains {"code": "DESTRUCTIVE_ACTION", "control": "tool-authz", "action": "BLOCK"} if {
    is_tool
    input.transaction.effect in {"destructive", "code_execution"}
}
