"""Operator-only, rate-bounded inspection. No upstream/tool execution or approvals."""
import asyncio
import json
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import Field

from app.api.dependencies import admin
from app.core.transaction import StrictModel
from app.settings import ROOT

router = APIRouter()


@router.get("/favicon.svg")
async def favicon():
    from fastapi.responses import Response
    return Response('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect width="64" height="64" rx="12" fill="#141e2b"/><text x="8" y="42" fill="#64d8d1" font-size="28" font-family="sans-serif">AC</text></svg>',media_type="image/svg+xml")


class InspectionRequest(StrictModel):
    text: str = Field(default="", strict=True, max_length=16000)
    payload: dict | None = None
    debug: bool = False
    source: Literal["user", "retrieved"] = "user"
    compare: bool = False


@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard():
    return HTMLResponse((Path(__file__).resolve().parents[1] / "dashboard.html").read_text(encoding="utf-8"),
        headers={"Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
            "X-Content-Type-Options": "nosniff", "Cache-Control": "no-store"})


@router.get("/dashboard.js")
async def dashboard_script():
    from fastapi.responses import Response
    return Response((Path(__file__).resolve().parents[1] / "dashboard.js").read_text(encoding="utf-8"),
        media_type="application/javascript", headers={"X-Content-Type-Options": "nosniff"})


@router.get("/dashboard.css")
async def dashboard_style():
    from fastapi.responses import Response
    return Response((Path(__file__).resolve().parents[1] / "dashboard.css").read_text(encoding="utf-8"), media_type="text/css")


@router.post("/admin/detection/inspect", dependencies=[Depends(admin)])
async def inspect(body: InspectionRequest, request: Request):
    from app.detection.inspection import InspectionError, acquire, inspect_request, release
    runtime=request.app.state.runtime
    try:
        token=await acquire(runtime)
    except InspectionError as exc:
        return JSONResponse({"error":exc.code},status_code=exc.status)
    try:
        report,trace=await inspect_request(runtime,body)
        if body.debug:
            report={**report,"trace":trace.events}
        return JSONResponse(report,headers={"Cache-Control":"no-store"})
    except InspectionError as exc:
        return JSONResponse({"error":exc.code},status_code=exc.status)
    finally:
        await release(runtime,token)


@router.post("/admin/detection/stream", dependencies=[Depends(admin)])
async def stream(body: InspectionRequest,request: Request):
    from fastapi.responses import StreamingResponse

    from app.detection.inspection import InspectionError, acquire, inspect_request, release, sse
    from app.detection.trace import Trace
    runtime=request.app.state.runtime
    try:
        token=await acquire(runtime)
    except InspectionError as exc:
        return JSONResponse({"error":exc.code},status_code=exc.status)
    async def events():
        queue=asyncio.Queue(maxsize=256)
        loop=asyncio.get_running_loop()
        def deliver(event):
            if not queue.full():
                queue.put_nowait(event)
        trace=Trace(lambda event:loop.call_soon_threadsafe(deliver,event))
        task=asyncio.create_task(inspect_request(runtime,body,trace))
        try:
            while not task.done() or not queue.empty():
                if await request.is_disconnected():
                    break
                try:
                    event=await asyncio.wait_for(queue.get(),.25)
                    yield sse(event)
                except TimeoutError:
                    yield ": heartbeat\n\n"
            if task.done():
                try:
                    await task
                except InspectionError as exc:
                    yield "event: error\ndata: "+json.dumps({"error":exc.code,"status":exc.status})+"\n\n"
                except Exception:
                    yield "event: error\ndata: {\"error\":\"INSPECTION_UNAVAILABLE\"}\n\n"
        finally:
            # Do not release admission while a disconnected/Torch inspection still runs.
            # Its durable result completes; the next reconnect starts a new explicit request.
            async def cleanup():
                try:
                    await task
                except (Exception,asyncio.CancelledError):
                    pass
                finally:
                    await release(runtime,token)
            # ASGI cancels a generator when a browser disconnects. Keep cleanup
            # independently alive so cancellation cannot strand local/shared admission.
            pending=getattr(runtime,"inspection_cleanup_tasks",None)
            if pending is None:
                runtime.inspection_cleanup_tasks=pending=set()
            cleanup_task=asyncio.create_task(cleanup())
            pending.add(cleanup_task)
            cleanup_task.add_done_callback(pending.discard)
            try:
                await asyncio.shield(cleanup_task)
            except asyncio.CancelledError:
                pass
    return StreamingResponse(events(),media_type="text/event-stream",headers={"Cache-Control":"no-store","X-Accel-Buffering":"no"})


@router.get("/admin/detection/evaluation", dependencies=[Depends(admin)])
async def evaluation():
    from app.evaluation.evidence import source_fingerprint
    current = source_fingerprint()
    reports = {}
    for name in ("baseline", "current"):
        path = ROOT / "artifacts" / f"hybrid-{name}.json"
        if name == "baseline" and not path.is_file():
            path = ROOT / "docs/hybrid-baseline.json"
        if not path.is_file():
            reports[name] = {"status": "missing", "current": False}
            continue
        try:
            report = json.loads(path.read_text(encoding="utf-8"))
            reports[name] = {k: v for k, v in report.items() if k not in {"results", "path"}}
            reports[name]["current"] = report.get("source_fingerprint") == current
            reports[name]["status"] = "historical_baseline" if name == "baseline" else "measured"
        except (OSError, ValueError):
            reports[name] = {"status": "invalid", "current": False}
    path = ROOT / "artifacts/self-test.json"
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
        reports["self_test"] = {**report, "current": report.get("source_fingerprint") == current}
    except (OSError, ValueError):
        reports["self_test"] = {"status": "missing", "current": False}
    return JSONResponse(reports, headers={"Cache-Control": "no-store"})
