package aicl

import rego.v1

violations contains {"code": "MEMORY_SCOPE_MISSING", "control": "memory-authz", "action": "BLOCK"} if {
    input.transaction.operation == "memory_read"
    not "memory:read" in input.transaction.principal.scopes
}

violations contains {"code": "MEMORY_SCOPE_MISSING", "control": "memory-authz", "action": "BLOCK"} if {
    input.transaction.operation == "memory_write"
    not "memory:write" in input.transaction.principal.scopes
}

violations contains {"code": "MEMORY_QUARANTINED", "control": "memory-authz", "action": "BLOCK"} if {
    input.memory_quarantined
}
