"""Real isolated browser QA. Uses installed Edge; never the user's browser profile.

Run against an owned local gateway configured with the real model. Negative states
use explicit HTTP fault injection and are identified separately in the evidence.
"""
import argparse
import asyncio
import json

from app.settings import ROOT


async def main(args):
    from playwright.async_api import async_playwright, expect
    output=ROOT/args.output
    output.mkdir(parents=True,exist_ok=True)
    checks,errors,console_errors=[],[],[]
    async with async_playwright() as p:
        browser=await p.chromium.launch(headless=True,executable_path=args.edge)
        context=await browser.new_context(viewport={"width":1440,"height":1000})
        page=await context.new_page()
        page.on("pageerror",lambda err:errors.append(str(err)))
        page.on("console",lambda msg:console_errors.append(msg.text) if msg.type=="error" else None)
        async def check(name,condition=True):
            if not condition:
                raise AssertionError(name)
            checks.append(name)
        await page.goto(args.url+"/dashboard")
        await check("navigation has no Evaluation & Tests",not await page.get_by_text("Evaluation & tests",exact=False).count())
        await page.locator("#token").fill("invalid-test-token")
        await page.locator("#connect").click()
        await page.get_by_text("Authentication failed",exact=True).wait_for()
        await check("authentication failure displayed")
        await page.locator("#token").fill("demo-admin-token")
        await page.locator("#connect").click()
        await page.get_by_text("Authenticated operator",exact=True).wait_for()
        await page.get_by_role("button",name="Live detection lab").click()
        await check("live lab navigation",await page.locator("#lab-view").is_visible())
        await check("seven visible pipeline stages",await page.locator("#pipeline-progress li").count()==7)
        async def inspect(text=None,scenario=None):
            if scenario is not None:
                await page.locator("#examples").select_option(str(scenario))
            if text is not None:
                await page.locator("#structured").uncheck()
                await page.locator("#payload").fill(text)
            await page.locator("#run").click()
            await expect(page.locator("#run")).to_be_enabled(timeout=60000)
            err=await page.locator("#error").inner_text()
            if err:
                raise AssertionError(err)
        await inspect(scenario=0)
        await check("real attack blocked",await page.locator("#decision").inner_text()=="BLOCK")
        await check("final stage marked current",await page.locator("#pipeline-progress .current").inner_text()=="Final action")
        await check("actual AI windows rendered",await page.locator("#timeline").get_by_text("ai window",exact=True).count()>=1)
        await check("final OPA event rendered",await page.locator("#timeline").get_by_text("opa",exact=True).count()==1)
        await page.locator("#findings details").first.locator("summary").click()
        await check("finding expands",await page.locator("#findings details").first.get_attribute("open") is not None)
        await inspect(scenario=24)
        await check("quoted benign security explanation allowed",await page.locator("#decision").inner_text()=="ALLOW")
        await inspect(scenario=11)
        await check("structured cross-message attack blocked",await page.locator("#decision").inner_text()=="BLOCK")
        await inspect(scenario=31)
        await check("encoded short-fragment demo blocked",await page.locator("#decision").inner_text()=="BLOCK")
        await page.locator("#payload").fill("A different public input")
        await check("edited input clears old verdict and export",await page.locator("#decision").inner_text()=="Ready to inspect" and await page.locator("#export").is_disabled())
        await inspect(scenario=23)
        await check("long prompt has multiple actual windows",await page.locator("#timeline").get_by_text("ai window",exact=True).count()>1)
        await page.locator("#advanced").check()
        await check("advanced stage data expands",await page.locator("#timeline details[open]").count()>5)
        await page.locator("#advanced").uncheck()
        await page.screenshot(path=str(output/"lab-desktop.png"),full_page=True)
        await page.locator("#stream-mode").select_option("burst")
        await page.locator("#start-stream").click()
        await page.locator(".stream-request").first.click()
        await expect(page.locator("#start-stream")).to_be_enabled(timeout=60000)
        await check("real stream shows eight selectable requests",await page.locator(".stream-request").count()==8)
        await check("burst capacity refusals visible","429" in await page.locator("#stream-rows").inner_text())
        await page.locator("#stream-mode").select_option("guided")
        await page.locator("#start-stream").click()
        await page.locator('.stream-request[data-decision="BLOCK"]').first.wait_for(timeout=60000)
        await page.locator("#stop-stream").click()
        await expect(page.locator("#start-stream")).to_be_enabled(timeout=60000)
        await check("guided stream has real allow and block decisions",await page.locator('.stream-request[data-decision="ALLOW"]').count()>0 and await page.locator('.stream-request[data-decision="BLOCK"]').count()>0)
        await check("guided stream shows expected labels",await page.locator(".stream-request .expected").count()>=2)
        await page.get_by_role("button",name="Security flags").click()
        await page.locator("#flag-list details").first.wait_for()
        await check("durable flags load")
        await check("alerts grouped by request",await page.locator("#alert-summary").get_by_text("MATCHING REQUESTS",exact=True).count()==1)
        await page.locator("#group-alerts").uncheck()
        await check("individual finding view remains available",await page.locator("#flag-list details").count()>0)
        await page.locator("#group-alerts").check()
        await page.locator("[name=category]").fill("not_present")
        await page.locator("#flag-filters button").click()
        await page.get_by_text("No flags in this filter and audit window.",exact=True).last.wait_for()
        await check("flag filter empty state")
        await page.locator("[name=category]").fill("")
        await page.locator("#flag-filters button").click()
        await page.locator("#flag-list details").first.wait_for()
        await page.locator("#flag-list > details").first.locator(":scope > summary").click()
        await check("flag details expand")
        await page.get_by_role("button",name="Model diagnostics").click()
        await check("diagnostics navigation",await page.locator("#diagnostics-view").is_visible())
        await page.get_by_role("button",name="Observatory",exact=False).click()
        await check("operational overview navigation",await page.locator("#overview-view").is_visible())
        await page.screenshot(path=str(output/"observatory-desktop.png"),full_page=True)
        await page.set_viewport_size({"width":390,"height":844})
        await page.get_by_role("button",name="Live detection lab").click()
        await page.screenshot(path=str(output/"lab-mobile.png"),full_page=True)
        await check("narrow layout has no horizontal document overflow",await page.evaluate("document.documentElement.scrollWidth<=innerWidth"))
        await check("mobile mode selector is readable",(await page.locator("#stream-mode").bounding_box())["width"]>250)
        await page.set_viewport_size({"width":1440,"height":1000})
        await inspect(text="")
        await check("empty input has real final state",await page.locator("#decision").inner_text() in {"ALLOW","BLOCK","REQUIRE_APPROVAL","WARN"})
        # Deliberate transport failures: no detector result is fabricated.
        async def disconnected(route):
            await route.fulfill(status=200,content_type="text/event-stream",body='event: stage\ndata: {"sequence":0,"stage":"received","elapsed_ms":0,"data":{}}\n\n')
        await page.route("**/admin/detection/stream",disconnected)
        await page.locator("#run").click()
        await page.locator("#reconnect").wait_for(state="visible")
        await check("disconnect explains missing final report and exposes reconnect")
        await page.unroute("**/admin/detection/stream",disconnected)
        await page.locator("#payload").fill("Summarize public museum hours.")
        await page.locator("#reconnect").click()
        await expect(page.locator("#run")).to_be_enabled(timeout=60000)
        await check("reconnect starts a successful new real inspection",await page.locator("#decision").inner_text()=="ALLOW")
        async def unavailable(route):
            await route.fulfill(status=503,content_type="application/json",body='{"error":"MODEL_UNAVAILABLE_TEST"}')
        await page.route("**/admin/detection/stream",unavailable)
        await page.locator("#run").click()
        await expect(page.locator("#run")).to_be_enabled()
        await check("unavailable error has no success verdict","503" in await page.locator("#error").inner_text())
        await page.unroute("**/admin/detection/stream",unavailable)
        await check("no uncaught browser errors",not errors)
        # Chromium logs HTTP failures for intentionally rejected auth/capacity/faults.
        unexpected=[s for s in console_errors if not any(v in s for v in ("403","429","503"))]
        print("Unexpected console errors:",unexpected,flush=True)
        await check("no unexpected browser console errors",not unexpected)
        await browser.close()
    report={"browser":"installed Microsoft Edge, isolated headless context","url":args.url,
        "checks":checks,"passed":len(checks),"page_errors":errors,"console_errors":console_errors,
        "negative_states":"Explicit route faults for disconnect/503; auth, capacity, detector verdicts and windows use real server",
        "screenshots":[str(p.relative_to(ROOT)) for p in output.glob("*.png")]}
    (output/"qa.json").write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps(report,indent=2))


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url",default="http://127.0.0.1:8010")
    parser.add_argument("--edge",default=r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe")
    parser.add_argument("--output",default="artifacts/iteration3/browser")
    asyncio.run(main(parser.parse_args()))
