import hashlib
import secrets

from app.core.transaction import Principal, StrictModel


class DelegationRequest(StrictModel):
    agent_id: str
    workflow_id: str
    scopes: list[str]
    capabilities: list[str]


class DelegationStore:
    def __init__(self, workflows):
        self.workflows = workflows
        self.ttl = 300

    async def issue(self, parent, request, policy):
        if "agents:delegate" not in parent.scopes:
            raise PermissionError("DELEGATION_SCOPE_MISSING")
        if parent.delegated_workflow and parent.delegated_workflow != request.workflow_id:
            raise PermissionError("DELEGATION_WORKFLOW_BOUNDARY")
        if request.agent_id not in policy.allowed_peers:
            raise PermissionError("DELEGATION_PEER_NOT_ALLOWED")
        if parent.delegation_depth + 1 > policy.max_depth:
            raise PermissionError("MAX_DELEGATION_DEPTH_EXCEEDED")
        if not set(request.scopes) <= set(parent.scopes):
            raise PermissionError("DELEGATION_CAPABILITY_ESCALATION")
        if not set(request.capabilities) <= set(parent.capabilities):
            raise PermissionError("DELEGATION_CAPABILITY_ESCALATION")
        child = Principal(subject=parent.subject, tenant_id=parent.tenant_id,
            agent_id=request.agent_id, scopes=request.scopes, capabilities=request.capabilities,
            roles=[], on_behalf_of=parent.subject, authentication_method="delegation",
            delegator=parent.agent_id or parent.subject, parent_agent=parent.agent_id,
            delegation_depth=parent.delegation_depth + 1, delegated_workflow=request.workflow_id)
        token = "dlg_" + secrets.token_urlsafe(32)
        key = "aicl:delegation:" + hashlib.sha256(token.encode()).hexdigest()
        await self.workflows.put_once(key, child.model_dump(mode="json"), ttl=self.ttl)
        return token, child

    async def authenticate(self, token):
        if not token or not token.startswith("dlg_"):
            return None
        value = await self.workflows.get("aicl:delegation:" + hashlib.sha256(token.encode()).hexdigest())
        return Principal.model_validate(value) if value else None
