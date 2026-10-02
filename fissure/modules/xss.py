"""Reflected cross-site scripting detection.

A unique marker is embedded inside several HTML contexts (raw, attribute,
script). If the marker comes back **unescaped** — the significant characters
``< > " '`` survive intact — the parameter reflects attacker input without
encoding, which is the core of reflected XSS. Markers that only appear
HTML-encoded are treated as safe.
"""

from __future__ import annotations

import secrets

from ..crawler import Injectable
from ..http import Session
from ..reporting import Finding, ModuleResult
from ._probe import send


def _marker() -> str:
    return "fz" + secrets.token_hex(4)


# Each payload pairs a probe string with the raw substring that must survive
# un-encoded for the injection to be exploitable in that context.
def _payloads(marker: str) -> list[tuple[str, str, str]]:
    return [
        (f"<{marker}>", f"<{marker}>", "raw HTML tag"),
        (f'"><svg onload={marker}>', f"<svg onload={marker}>", "attribute breakout"),
        (f"';{marker};//", f"';{marker};//", "inline script context"),
    ]


class XssScanner:
    module = "xss"

    def __init__(self, session: Session, injectables: list[Injectable]) -> None:
        self.session = session
        self.injectables = injectables

    async def scan(self) -> ModuleResult:
        findings: list[Finding] = []
        errors: list[str] = []
        tested = 0

        for inj in self.injectables:
            tested += 1
            try:
                finding = await self._test_one(inj)
            except Exception as exc:
                errors.append(f"{inj.method} {inj.url} [{inj.param}]: {exc.__class__.__name__}: {exc}")
                continue
            if finding:
                findings.append(finding)

        status = "success" if not errors else "partial"
        summary = (
            f"Reflected XSS detected in {len(findings)} of {tested} parameter(s)."
            if findings
            else f"No reflected XSS detected across {tested} parameter(s)."
        )
        return ModuleResult(module=self.module, status=status, summary=summary, findings=findings,
                            data={"parameters_tested": tested}, errors=errors)

    async def _test_one(self, inj: Injectable) -> Finding | None:
        loc = f"{inj.method} {inj.url} (param: {inj.param})"
        for payload, must_survive, context in _payloads(_marker()):
            probe = await send(self.session, inj, payload)
            if must_survive in probe.text:
                return Finding(
                    title="Reflected cross-site scripting (XSS)",
                    severity="high",
                    cwe="CWE-79",
                    location=loc,
                    evidence=f"Payload reflected unescaped in {context}: {must_survive!r}",
                    metadata={"context": context, "payload": payload},
                )
        return None
