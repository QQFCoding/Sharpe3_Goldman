import asyncio
import hashlib
import json
import secrets
import time
from pathlib import Path

from app.controls.base import encoded
from app.core.transaction import Principal, SecurityTransaction

DEMO_SCOPES = [
    "repo:read",
    "repo:write",
    "files:read",
    "files:write",
    "network:read",
    "email:send",
    "memory:read",
    "memory:write",
    "memory:trusted_write",
    "agents:message",
    "agents:delegate",
    "workflow:intent",
]


class Authenticator:
    def __init__(self, demo_mode: bool, auth_file: Path | None):
        self.records: dict[str, Principal] = {}
        if demo_mode:
            for token, tenant, subject in [
                ("demo-user-token", "tenant-a", "alice"),
                ("demo-other-token", "tenant-b", "bob"),
            ]:
                self.records[hashlib.sha256(token.encode()).hexdigest()] = Principal(
                    subject=subject, tenant_id=tenant, agent_id="demo-agent", scopes=DEMO_SCOPES,
                    capabilities=["github.search", "github.read_issue", "github.create_issue", "filesystem.read",
                                  "filesystem.write", "email.send", "network.fetch", "demo.echo", "demo-child"]
                )
        if auth_file:
            for record in json.loads(auth_file.read_text(encoding="utf-8")):
                digest = record["token_sha256"]
                if len(digest) != 64:
                    raise ValueError("Auth records require SHA-256 token digests")
                self.records[digest] = Principal.model_validate(record["principal"])
        if not self.records:
            raise ValueError("No configured identities")
        self.jwt = None

    def authenticate(self, token: str | None) -> Principal | None:
        if not token:
            return None
        identity = self.records.get(hashlib.sha256(token.encode()).hexdigest())
        return identity.model_copy(deep=True) if identity else (self.jwt.authenticate(token) if self.jwt else None)


def approval_digest(tx: SecurityTransaction, revision: str) -> str:
    p = tx.principal
    return hashlib.sha256(
        encoded(
            {
                "subject": p.subject,
                "tenant": p.tenant_id,
                "agent": p.agent_id,
                "operation": tx.operation,
                "effect": tx.effect,
                "resource": tx.resource.model_dump() if tx.resource else None,
                "payload": tx.payload,
                "workflow": tx.context.workflow.model_dump(),
                "revision": revision,
                "manifest_hash": tx.metadata.get("manifest_hash"),
            }
        )
    ).hexdigest()


class ApprovalStore:
    def __init__(self, redis=None):
        self.redis = redis
        self._lock = asyncio.Lock()
        self._tokens: dict[str, tuple[str, float]] = {}

    async def issue(self, digest: str, ttl: int = 300) -> str:
        token = secrets.token_urlsafe(32)
        key = "aicl:approval:" + hashlib.sha256(token.encode()).hexdigest()
        if self.redis:
            await self.redis.set(key, digest, ex=ttl)
        else:
            async with self._lock:
                self._tokens = {k: v for k, v in self._tokens.items() if v[1] > time.time()}
                self._tokens[key] = (digest, time.time() + ttl)
        return token

    async def check(self, token: str | None, digest: str, consume: bool = False) -> bool:
        if not token:
            return False
        key = "aicl:approval:" + hashlib.sha256(token.encode()).hexdigest()
        if self.redis:
            if consume:
                script = "if redis.call('GET', KEYS[1]) == ARGV[1] then redis.call('DEL', KEYS[1]); return 1 end; return 0"
                return bool(await self.redis.eval(script, 1, key, digest))
            value = await self.redis.get(key)
            if isinstance(value, bytes):
                value = value.decode()
            return value is not None and secrets.compare_digest(value, digest)
        async with self._lock:
            record = self._tokens.get(key)
            valid = bool(record and record[1] > time.time() and secrets.compare_digest(record[0], digest))
            if valid and consume:
                del self._tokens[key]
            return valid
