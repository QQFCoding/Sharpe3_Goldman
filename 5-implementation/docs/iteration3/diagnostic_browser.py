import asyncio
import json
import math
from pathlib import Path

from playwright.async_api import async_playwright, expect

ROOT = Path(__file__).resolve().parents[2]


def percent(value):
    return f"{value * 100:.6f}%" if value > .9999 else f"{math.floor(value * 1000 + .5) / 10:.1f}%"


async def main():
    report = json.loads((ROOT / 'artifacts/iteration3/current-v3.json').read_text(encoding='utf-8'))
    checks, errors, console = [], [], []
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True, executable_path=r'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe')
        page = await browser.new_page(viewport={'width': 1440, 'height': 1000})
        page.on('pageerror', lambda e: errors.append(str(e)))
        page.on('console', lambda e: console.append(e.text) if e.type == 'error' else None)
        await page.goto('http://127.0.0.1:8010/dashboard')
        await page.locator('#token').fill('demo-admin-token')
        await page.locator('#connect').click()
        await page.get_by_text('Authenticated operator', exact=True).wait_for()
        async with page.expect_response(lambda r: '/admin/detection/diagnostics?' in r.url) as response:
            await page.get_by_role('button', name='Model diagnostics').click()
        data = await (await response.value).json()
        assert data['current'] and data['quality']['samples'] == 4102
        assert data['quality']['family_leakage'] == data['quality']['duplicate_payloads'] == 0
        await expect(page.locator('#diagnostic-summary table')).to_have_count(2)
        checks.append('complete 4102-case suite is current and leak/duplicate free')
        for cohort in ('all', 'known_v2', 'fresh_v3'):
            if cohort != 'all':
                async with page.expect_response(lambda r: '/admin/detection/diagnostics?' in r.url and f'cohort={cohort}' in r.url) as response:
                    await page.locator('#diagnostic-cohort').select_option(cohort)
                data = await (await response.value).json()
            expected = report['splits']['test'] if cohort == 'all' else report['cohort_summaries'][cohort]['test']
            assert data['splits']['test']['metrics'] == expected['metrics']
            for index, detector in enumerate(('ai', 'deterministic', 'hybrid'), 1):
                metric = expected['metrics'][detector]
                row = page.locator('#diagnostic-summary table').first.locator('tr').nth(index)
                await expect(row.locator('td').nth(3)).to_have_text(percent(metric['recall']))
                await expect(row.locator('td').nth(4)).to_have_text(f"{metric['fp']} / {metric['fn']}")
            coverage = page.locator('#diagnostic-summary table').nth(1)
            await expect(coverage.locator('tr')).to_have_count(11)
            for index, (language, metrics) in enumerate(expected['by_language'].items(), 1):
                row = coverage.locator('tr').nth(index)
                await expect(row.locator('td').first).to_have_text(language)
                await expect(row.locator('td').nth(1)).to_have_text(str(metrics['hybrid']['samples']))
                await expect(row.locator('td').nth(4)).to_have_text(percent(metrics['hybrid']['recall']))
            checks.append(f'{cohort}: real metric counts and ten-language coverage match measured report')
        await page.locator('#diagnostic-language').fill('en')
        async with page.expect_response(lambda r: '/admin/detection/diagnostics?' in r.url and 'kind=false_negative' in r.url) as response:
            await page.locator('#diagnostic-kind').select_option('false_negative')
        data = await (await response.value).json()
        assert data['cases'] and all(c['cohort'] == 'fresh_v3' and c['language'] == 'en' for c in data['cases'])
        assert all('ai_details' not in c and 'relevant_model_windows' not in c for c in data['cases'])
        await page.locator('#diagnostic-cases details').first.locator('summary').click()
        await expect(page.locator('#diagnostic-cases details').first).to_have_attribute('open', '')
        checks.append('fresh English false-negative filter and sanitized expandable evidence')
        await page.screenshot(path=str(ROOT / 'docs/iteration3/diagnostics-desktop.png'), full_page=True)
        await page.set_viewport_size({'width': 390, 'height': 844})
        assert await page.evaluate('document.documentElement.scrollWidth <= innerWidth + 1')
        checks.append('diagnostic tables remain contained on narrow layout')
        await page.set_viewport_size({'width': 1440, 'height': 1000})
        await page.get_by_role('button', name='Security flags').click()
        await page.locator('#flag-list > details').first.wait_for()
        assert await page.locator('#group-alerts').is_checked()
        await page.locator('#flag-list > details').first.locator(':scope > summary').click()
        await page.screenshot(path=str(ROOT / 'docs/iteration3/alerts-desktop.png'), full_page=True)
        checks.append('real grouped alerts and expanded evidence visible')
        assert not errors and not console, (errors, console)
        checks.append('no browser or console errors')
        await browser.close()
    output = {'browser': 'installed Edge, isolated headless context', 'source_fingerprint': report['source_fingerprint'],
        'checks': checks, 'passed': len(checks), 'page_errors': errors, 'console_errors': console,
        'scope': 'actual authenticated server/report data; no response mocking; p95 column is whole measured suite latency'}
    (ROOT / 'docs/iteration3/diagnostic-browser.json').write_text(json.dumps(output, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(output, indent=2))


asyncio.run(main())
