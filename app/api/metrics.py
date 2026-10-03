from fastapi import APIRouter, Depends, Request
from fastapi.responses import Response

from app.api.dependencies import admin

router = APIRouter()


@router.get("/metrics", dependencies=[Depends(admin)])
async def metrics(request: Request):
    return Response(
        request.app.state.runtime.metrics.render(), media_type="text/plain; version=0.0.4; charset=utf-8"
    )
