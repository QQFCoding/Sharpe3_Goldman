import json
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.api import admin, chat, health, metrics
from app.api.dependencies import bearer
from app.runtime import Runtime
from app.settings import Settings


class BodyLimitMiddleware:
    def __init__(self, app, runtime_app, limit):
        self.app, self.runtime_app, self.limit = app, runtime_app, limit

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["method"] not in {"POST", "PUT", "PATCH"}:
            return await self.app(scope, receive, send)
        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            body.extend(message.get("body", b""))
            if len(body) > self.limit:
                result = await self.runtime_app.state.runtime.reject("REQUEST_BODY_TOO_LARGE", "size")
                return await JSONResponse(result.model_dump(mode="json"), status_code=413)(
                    scope, receive, send
                )
            if not message.get("more_body", False):
                break
        delivered = False

        async def bounded_receive():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()

        # Reject non-finite JSON and duplicate keys, which otherwise admit ambiguous protocol interpretation.
        if body:
            try:

                def pairs(items):
                    result = {}
                    for key, value in items:
                        if key in result:
                            raise ValueError("duplicate key")
                        result[key] = value
                    return result

                def invalid_constant(_):
                    raise ValueError("non-finite number")

                json.loads(body, object_pairs_hook=pairs, parse_constant=invalid_constant)
            except (ValueError, RecursionError):
                result = await self.runtime_app.state.runtime.reject("JSON_INVALID", "schema")
                return await JSONResponse(result.model_dump(mode="json"), status_code=422)(
                    scope, receive, send
                )
        return await self.app(scope, bounded_receive, send)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()

    @asynccontextmanager
    async def lifespan(application):
        runtime = Runtime(settings)
        try:
            application.state.runtime = await runtime.open()
            yield
        finally:
            await runtime.close()

    application = FastAPI(title="AI Control Layer", version="0.1.0", lifespan=lifespan)
    application.add_middleware(BodyLimitMiddleware, runtime_app=application, limit=settings.max_body_bytes)
    for router in (health.router, chat.router, admin.router, metrics.router):
        application.include_router(router)

    @application.exception_handler(HTTPException)
    async def http_error(request, exc):
        return JSONResponse(
            exc.detail if isinstance(exc.detail, dict) else {"error": exc.detail}, status_code=exc.status_code
        )

    @application.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc):
        runtime = request.app.state.runtime
        identity = runtime.auth.authenticate(bearer(request))
        result = await runtime.reject("SCHEMA_INVALID", "schema", identity)
        return JSONResponse(result.model_dump(mode="json"), status_code=422)

    return application


app = create_app()
