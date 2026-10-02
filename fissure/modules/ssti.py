"""Server-Side Template Injection detection.

Injects an arithmetic expression wrapped in several template-engine delimiters,
bound by a unique marker on both sides. If the response contains
`<marker><product><marker>` — i.e. the engine evaluated the expression — it is a
confirmed hit. Binding the result to a random marker and a distinctive product
avoids matching a stray number already on the page (the main SSTI false-positive
trap).
"""

from __future__ import annotations

import secrets

from ..crawler import Injectable
from ..http import Session
from ..reporting import Finding, ModuleResult
from ._probe import send


def _marker() -> str:
    return "fz" + secrets.token_hex(3)


def _payloads(marker: str, a: int, b: int) -> list[tuple[str, str]]:
    """(payload, engine) pairs for common template syntaxes."""
    expr = f"{a}*{b}"
    return [
        (f"{marker}{{{{{expr}}}}}{marker}", "Jinja2/Twig ({{ }})"),
        (f"{marker}${{{expr}}}{marker}", "Freemarker/JSP EL (${ })"),
        (f"{marker}<%={expr}%>{marker}", "ERB (<%= %>)"),
        (f"{marker}{{{expr}}}{marker}", "Smarty ({ })"),
    ]


class SstiScanner:
    module = "ssti"

    def __init__(self, session: Session, injectables: list[Injectable], *, concurrency: int = 8) -> None:
        self.session = session
        self.injectables = injectables
        self.concurrency = concurrency

    async def scan(self) -> ModuleResult:
        from ._runner import scan_injectables
        return await scan_injectables(self.module, self.injectables, self._test_one,
                                      self.concurrency, "Template injection")

    async def _test_one(self, inj: Injectable) -> Finding | None:
        loc = f"{inj.method} {inj.url} (param: {inj.param})"
        marker = _marker()
        a, b = secrets.randbelow(40) + 50, secrets.randbelow(40) + 50  # distinctive product
        expected = f"{marker}{a * b}{marker}"
        for payload, engine in _payloads(marker, a, b):
            probe = await send(self.session, inj, payload)
            if expected in probe.text:
                return Finding(
                    title="Server-side template injection (SSTI)",
                    severity="critical",
                    cwe="CWE-1336",
                    location=loc,
                    evidence=f"Engine evaluated {a}*{b}={a * b} ({engine}); found {expected!r} in the response.",
                    metadata={"engine": engine, "payload": payload},
                )
        return None
