"""Security-headers and cookie-flag analysis (passive).

Covers OWASP A05:2021 Security Misconfiguration. This module makes no extra
requests: it inspects the response metadata the crawler already captured. To
avoid drowning the report, each issue is reported ONCE with a representative URL
and a count of how many crawled responses were affected.
"""

from __future__ import annotations

from ..crawler import CrawlResult, PageResponse
from ..reporting import Finding, ModuleResult

# header -> (severity, description, cwe). HSTS/Secure are only meaningful on HTTPS.
HEADER_RULES: dict[str, tuple[str, str, str]] = {
    "content-security-policy": ("medium", "No Content-Security-Policy — weak defence against XSS/content injection.", "CWE-693"),
    "x-frame-options": ("low", "No X-Frame-Options — page may be framed (clickjacking).", "CWE-1021"),
    "x-content-type-options": ("low", "No X-Content-Type-Options: nosniff — MIME sniffing allowed.", "CWE-693"),
    "referrer-policy": ("low", "No Referrer-Policy — referrer may leak to third parties.", "CWE-200"),
    "permissions-policy": ("low", "No Permissions-Policy — browser features not restricted.", "CWE-693"),
}
HSTS = ("medium", "No Strict-Transport-Security on an HTTPS response — downgrade/MITM risk.", "CWE-319")


class HeaderScanner:
    module = "headers"

    def __init__(self, crawl: CrawlResult) -> None:
        self.crawl = crawl

    async def scan(self) -> ModuleResult:
        responses = self.crawl.responses
        if not responses:
            return ModuleResult(module=self.module, status="unsupported",
                                summary="No responses captured during crawl to analyse.")

        findings: list[Finding] = []
        findings.extend(self._header_findings(responses))
        findings.extend(self._cookie_findings(responses))

        summary = (f"{len(findings)} header/cookie issue(s) across {len(responses)} response(s)."
                   if findings else f"No header/cookie misconfigurations across {len(responses)} response(s).")
        return ModuleResult(module=self.module, status="success", summary=summary,
                            findings=findings, data={"responses_analysed": len(responses)})

    def _header_findings(self, responses: list[PageResponse]) -> list[Finding]:
        findings: list[Finding] = []
        rules = dict(HEADER_RULES)

        for header, (severity, desc, cwe) in rules.items():
            missing = [r for r in responses if header not in r.headers]
            if missing:
                findings.append(self._grouped(missing, len(responses),
                                               f"Missing security header: {header}", severity, desc, cwe))

        # HSTS only applies to HTTPS responses.
        https = [r for r in responses if r.url.lower().startswith("https://")]
        hsts_missing = [r for r in https if "strict-transport-security" not in r.headers]
        if hsts_missing:
            sev, desc, cwe = HSTS
            findings.append(self._grouped(hsts_missing, len(https),
                                          "Missing security header: strict-transport-security", sev, desc, cwe))

        # Server/X-Powered-By version disclosure (info/low).
        disclosing = [r for r in responses if r.headers.get("server") or r.headers.get("x-powered-by")]
        if disclosing:
            sample = disclosing[0]
            banner = sample.headers.get("server") or sample.headers.get("x-powered-by")
            findings.append(Finding(
                title="Software version disclosure", severity="low", location=sample.url,
                evidence=f"Response advertises software via Server/X-Powered-By: {banner!r} "
                         f"({len(disclosing)} response(s)).",
                confirmed=False, cwe="CWE-200"))
        return findings

    def _cookie_findings(self, responses: list[PageResponse]) -> list[Finding]:
        findings: list[Finding] = []
        for check, title, severity, cwe, https_only in (
            (lambda c: "httponly" not in c.lower(), "Cookie without HttpOnly", "medium", "CWE-1004", False),
            (lambda c: "samesite" not in c.lower(), "Cookie without SameSite", "low", "CWE-1275", False),
            (lambda c: "secure" not in c.lower(), "Cookie without Secure (HTTPS response)", "medium", "CWE-614", True),
        ):
            hits: list[tuple[str, str]] = []  # (url, cookie-name)
            for r in responses:
                if https_only and not r.url.lower().startswith("https://"):
                    continue
                for raw in r.set_cookie:
                    if check(raw):
                        hits.append((r.url, raw.split("=", 1)[0].strip()))
            if hits:
                url, name = hits[0]
                findings.append(Finding(
                    title=title, severity=severity, location=url,
                    evidence=f"Cookie '{name}' set without the flag ({len(hits)} cookie(s) affected).",
                    cwe=cwe))
        return findings

    @staticmethod
    def _grouped(affected: list[PageResponse], total: int, title: str, severity: str,
                 desc: str, cwe: str) -> Finding:
        return Finding(
            title=title, severity=severity, location=affected[0].url,
            evidence=f"{desc} Affects {len(affected)} of {total} response(s).",
            cwe=cwe)
