import secrets

from fastapi import HTTPException, Request

from app.core.decision import Decision


def bearer(request: Request) -> str | None:
    header = request.headers.get("authorization", "")
    scheme, _, value = header.partition(" ")
    return value if scheme.lower() == "bearer" and len(value) <= 8192 else None


async def principal(request: Request):
    runtime = request.app.state.runtime
    identity = runtime.auth.authenticate(bearer(request))
    if identity is None:
        identity = await runtime.delegations.authenticate(bearer(request))
    if identity is None:
        result = await runtime.reject("UNAUTHENTICATED", "authentication")
        raise HTTPException(status_code=401, detail=result.model_dump(mode="json"))
    return identity


async def admin(request: Request):
    if not secrets.compare_digest(bearer(request) or "", request.app.state.runtime.settings.admin_token):
        result = await request.app.state.runtime.reject("ADMIN_UNAUTHORIZED", "authentication")
        raise HTTPException(status_code=403, detail=result.model_dump(mode="json"))


def status_for(decision):
    return {
        Decision.REQUIRE_APPROVAL: 409,
        Decision.BLOCK: 403,
        Decision.QUARANTINE: 403,
        Decision.TERMINATE: 429,
    }.get(decision, 200)
