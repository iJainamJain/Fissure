"""Path traversal / Local File Inclusion detection.

Injects `../` sequences (and common encodings/bypasses) to read files outside
the web root, and confirms a hit by matching the *file's content signature* in
the response — e.g. the `root:...:0:0:` line of /etc/passwd — never the echoed
payload string. Matching on content, not reflection, keeps false positives low.
"""

from __future__ import annotations

import re

from ..crawler import Injectable
from ..http import Session
from ..reporting import Finding, ModuleResult
from ._probe import send

PAYLOADS = [
    "../../../../../../etc/passwd",
    "....//....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
    "/etc/passwd",
    "../../../../../../windows/win.ini",
    "..%5c..%5c..%5c..%5c..%5cwindows%5cwin.ini",
]
# Content signatures proving a real file was read (not the payload reflected back).
SIGNATURES = [
    ("Unix /etc/passwd", re.compile(r"root:.*?:0:0:", re.MULTILINE)),
    ("Windows win.ini", re.compile(r"\[fonts\]|\[extensions\]|for 16-bit app support", re.IGNORECASE)),
]


class TraversalScanner:
    module = "traversal"

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
        summary = (f"Path traversal detected in {len(findings)} of {tested} parameter(s)."
                   if findings else f"No path traversal detected across {tested} parameter(s).")
        return ModuleResult(module=self.module, status=status, summary=summary, findings=findings,
                            data={"parameters_tested": tested}, errors=errors)

    async def _test_one(self, inj: Injectable) -> Finding | None:
        loc = f"{inj.method} {inj.url} (param: {inj.param})"
        for payload in PAYLOADS:
            probe = await send(self.session, inj, payload)
            for name, pattern in SIGNATURES:
                if pattern.search(probe.text):
                    return Finding(
                        title="Path traversal / Local File Inclusion",
                        severity="high",
                        cwe="CWE-22",
                        location=loc,
                        evidence=f"Response contained {name} contents for payload {payload!r}.",
                        metadata={"payload": payload, "signature": name},
                    )
        return None
