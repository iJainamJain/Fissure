"""CORS misconfiguration detection.

For each crawled page, sends a request with a crafted `Origin` header and checks
the CORS response: reflecting an arbitrary origin into
`Access-Control-Allow-Origin` *with* `Access-Control-Allow-Credentials: true` is
high severity (any site can read authenticated responses); `*` without
credentials is informational. Per-URL, not per-parameter.
"""

from __future__ import annotations

from ..crawler import CrawlResult
from ..http import Session
from ..reporting import Finding, ModuleResult

EVIL_ORIGIN = "https://fissure-evil.example"


class CorsScanner:
    module = "cors"

    def __init__(self, session: Session, crawl: CrawlResult, *, max_urls: int = 15, concurrency: int = 8) -> None:
        self.session = session
        self.crawl = crawl
        self.max_urls = max_urls
        self.concurrency = concurrency

    async def scan(self) -> ModuleResult:
        from ..concurrency import map_bounded
        if not self.crawl.responses:
            return ModuleResult(module=self.module, status="unsupported",
                                summary="No crawled URLs to test for CORS.")
        findings: list[Finding] = []
        errors: list[str] = []
        seen: list[str] = []
        for resp_meta in self.crawl.responses:
            if resp_meta.url not in seen:
                seen.append(resp_meta.url)
        urls = seen[:self.max_urls]
        tested = len(urls)

        async def _safe(url):
            try:
                return (await self._test_url(url), None)
            except Exception as exc:
                return (None, f"{url}: {exc.__class__.__name__}: {exc}")

        for finding, err in await map_bounded(urls, _safe, self.concurrency):
            if err:
                errors.append(err)
            elif finding:
                findings.append(finding)

        status = "success" if not errors else "partial"
        summary = (f"CORS misconfiguration on {len(findings)} of {tested} URL(s)."
                   if findings else f"No CORS misconfiguration across {tested} URL(s).")
        return ModuleResult(module=self.module, status=status, summary=summary, findings=findings,
                            data={"urls_tested": tested}, errors=errors)

    async def _test_url(self, url: str) -> Finding | None:
        resp = await self.session.client.get(url, headers={"Origin": EVIL_ORIGIN}, follow_redirects=False)
        acao = resp.headers.get("access-control-allow-origin", "")
        acac = resp.headers.get("access-control-allow-credentials", "").lower() == "true"

        if acao == EVIL_ORIGIN and acac:
            return Finding(
                title="CORS misconfiguration (reflected origin with credentials)",
                severity="high",
                cwe="CWE-942",
                location=url,
                evidence=f"ACAO reflected attacker origin {EVIL_ORIGIN!r} with Access-Control-Allow-Credentials: true.",
                metadata={"acao": acao, "credentials": True},
            )
        if acao == EVIL_ORIGIN or acao == "*":
            return Finding(
                title="CORS allows arbitrary origin",
                severity="low" if acao == "*" else "medium",
                cwe="CWE-942",
                location=url,
                evidence=f"Access-Control-Allow-Origin is {acao!r} (no credentials).",
                confirmed=False,
                metadata={"acao": acao, "credentials": False},
            )
        return None
