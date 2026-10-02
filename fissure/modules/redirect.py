"""Open-redirect detection.

Only parameters whose name suggests a navigation target are tested (to avoid
noise), by setting them to an external canary host and checking whether the
server sends the browser there via a ``Location`` header (3xx) or a
``<meta http-equiv=refresh>`` tag.
"""

from __future__ import annotations

import re

from ..crawler import Injectable
from ..http import Session
from ..reporting import Finding, ModuleResult
from ._probe import send

REDIRECT_PARAM_HINTS = ("next", "url", "redirect", "return", "returnurl", "dest", "destination", "continue", "goto", "target")
CANARY = "http://fissure-canary.example"
META_REFRESH_RE = re.compile(r'http-equiv=["\']?refresh["\']?[^>]*url=([^"\'>\s]+)', re.IGNORECASE)


class RedirectScanner:
    module = "redirect"

    def __init__(self, session: Session, injectables: list[Injectable]) -> None:
        self.session = session
        self.injectables = injectables

    async def scan(self) -> ModuleResult:
        findings: list[Finding] = []
        errors: list[str] = []
        candidates = [inj for inj in self.injectables if inj.param.lower() in REDIRECT_PARAM_HINTS]

        for inj in candidates:
            try:
                finding = await self._test_one(inj)
            except Exception as exc:
                errors.append(f"{inj.method} {inj.url} [{inj.param}]: {exc.__class__.__name__}: {exc}")
                continue
            if finding:
                findings.append(finding)

        status = "success" if not errors else "partial"
        summary = (
            f"Open redirect detected in {len(findings)} of {len(candidates)} candidate parameter(s)."
            if findings
            else f"No open redirect detected across {len(candidates)} candidate parameter(s)."
        )
        return ModuleResult(module=self.module, status=status, summary=summary, findings=findings,
                            data={"candidate_parameters": len(candidates)}, errors=errors)

    async def _test_one(self, inj: Injectable) -> Finding | None:
        loc = f"{inj.method} {inj.url} (param: {inj.param})"
        probe = await send(self.session, inj, CANARY, follow_redirects=False)

        location = probe.headers.get("location", "")
        if 300 <= probe.status < 400 and CANARY in location:
            return Finding(
                title="Open redirect (Location header)",
                severity="medium",
                cwe="CWE-601",
                location=loc,
                evidence=f"HTTP {probe.status} redirected to attacker-controlled {location!r}.",
                metadata={"via": "location-header", "location": location},
            )

        meta = META_REFRESH_RE.search(probe.text)
        if meta and CANARY in meta.group(1):
            return Finding(
                title="Open redirect (meta refresh)",
                severity="medium",
                cwe="CWE-601",
                location=loc,
                evidence=f"Page issued a meta-refresh to {meta.group(1)!r}.",
                confirmed=False,
                metadata={"via": "meta-refresh", "location": meta.group(1)},
            )
        return None
