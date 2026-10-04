"""Server-owned field receipts; a handle resolves a value, never relabels caller text."""
import hashlib
import secrets

from app.core.labels import DataSecurityLabel


class ValueStore:
    def __init__(self, workflows):
        self.workflows = workflows

    @staticmethod
    def key(handle):
        return "aicl:value:" + hashlib.sha256(handle.encode()).hexdigest()

    async def issue(self, principal, value, label):
        handle = secrets.token_urlsafe(24)
        await self.workflows.put_once(self.key(handle), {"tenant": principal.tenant_id,
            "owner": principal.subject, "value": value, "label": label.model_dump(mode="json")})
        return handle

    async def resolve(self, principal, handle):
        item = await self.workflows.get(self.key(handle))
        if not item or item["tenant"] != principal.tenant_id or item["owner"] != principal.subject:
            raise PermissionError("DATA_REFERENCE_NOT_ACCESSIBLE")
        return item["value"], DataSecurityLabel.model_validate(item["label"])
