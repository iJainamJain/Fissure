"""Integration tests: run each active module against live VulnLab."""

from __future__ import annotations

from fissure.crawler import Crawler, Injectable
from fissure.http import Session
from fissure.modules.cmdi import CmdiScanner
from fissure.modules.cors import CorsScanner
from fissure.modules.discovery import DiscoveryScanner
from fissure.modules.headers import HeaderScanner
from fissure.modules.ssti import SstiScanner
from fissure.modules.traversal import TraversalScanner
from fissure.modules.redirect import RedirectScanner
from fissure.modules.sqli import SqliScanner
from fissure.modules.xss import XssScanner
from fissure.targets import normalize_target


def _inj(url, param, method="GET", params=None):
    return Injectable(method, url, param, tuple(params or [(param, "1")]))


async def test_crawler_finds_injectables(vulnlab_url):
    async with Session() as s:
        crawl = await Crawler(normalize_target(vulnlab_url), s, max_pages=10, max_depth=2).crawl()
    names = {i.param for i in crawl.injectables}
    assert {"q", "id", "next"} <= names


async def test_error_based_sqli(vulnlab_url):
    async with Session() as s:
        res = await SqliScanner(s, [_inj(f"{vulnlab_url}/search", "q")]).scan()
    assert any("error-based" in f.metadata.get("type", "") for f in res.findings)


async def test_time_based_sqli(vulnlab_url):
    async with Session(timeout=15) as s:
        res = await SqliScanner(s, [_inj(f"{vulnlab_url}/item", "id")]).scan()
    assert res.findings, "expected a SQLi finding on /item"


async def test_reflected_xss(vulnlab_url):
    async with Session() as s:
        res = await XssScanner(s, [_inj(f"{vulnlab_url}/search", "q")]).scan()
    assert res.findings and res.findings[0].title.startswith("Reflected")


async def test_no_xss_on_encoded_param(vulnlab_url):
    # /item HTML-escapes its id, so no reflected XSS should be reported there.
    async with Session() as s:
        res = await XssScanner(s, [_inj(f"{vulnlab_url}/item", "id")]).scan()
    assert not res.findings


async def test_command_injection_time_based(vulnlab_url):
    async with Session(timeout=15) as s:
        res = await CmdiScanner(s, [_inj(f"{vulnlab_url}/ping", "host")]).scan()
    assert res.findings and res.findings[0].cwe == "CWE-78"


async def test_no_cmdi_on_safe_param(vulnlab_url):
    # /search doesn't execute commands, so cmdi must not fire there.
    async with Session(timeout=15) as s:
        res = await CmdiScanner(s, [_inj(f"{vulnlab_url}/search", "q")]).scan()
    assert not res.findings


async def test_path_traversal(vulnlab_url):
    async with Session() as s:
        res = await TraversalScanner(s, [_inj(f"{vulnlab_url}/view", "file")]).scan()
    assert res.findings and res.findings[0].cwe == "CWE-22"


async def test_no_traversal_on_safe_param(vulnlab_url):
    async with Session() as s:
        res = await TraversalScanner(s, [_inj(f"{vulnlab_url}/search", "q")]).scan()
    assert not res.findings


async def test_ssti(vulnlab_url):
    async with Session() as s:
        res = await SstiScanner(s, [_inj(f"{vulnlab_url}/render", "name")]).scan()
    assert res.findings and res.findings[0].cwe == "CWE-1336"


async def test_no_ssti_on_reflecting_param(vulnlab_url):
    # /search reflects input but does not evaluate templates -> no SSTI.
    async with Session() as s:
        res = await SstiScanner(s, [_inj(f"{vulnlab_url}/search", "q")]).scan()
    assert not res.findings


async def test_cors_misconfig(vulnlab_url):
    async with Session() as s:
        crawl = await Crawler(normalize_target(vulnlab_url), s, max_pages=10, max_depth=1).crawl()
        res = await CorsScanner(s, crawl).scan()
    assert any(f.cwe == "CWE-942" and f.severity == "high" for f in res.findings)


async def test_open_redirect(vulnlab_url):
    async with Session() as s:
        res = await RedirectScanner(s, [_inj(f"{vulnlab_url}/go", "next")]).scan()
    assert res.findings and "redirect" in res.findings[0].title.lower()


async def test_headers_flags_missing_security_headers(vulnlab_url):
    # VulnLab sends no security headers, so the passive module must flag them.
    async with Session() as s:
        crawl = await Crawler(normalize_target(vulnlab_url), s, max_pages=10, max_depth=1).crawl()
        res = await HeaderScanner(crawl).scan()
    titles = {f.title for f in res.findings}
    assert any("content-security-policy" in t.lower() for t in titles)
    assert all(f.cwe for f in res.findings)  # every finding carries a CWE id


async def test_discovery_finds_env(vulnlab_url):
    async with Session() as s:
        res = await DiscoveryScanner(s, normalize_target(vulnlab_url)).scan()
    assert any(".env" in f.location for f in res.findings)
