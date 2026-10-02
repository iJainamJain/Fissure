"""Shared scan loop for injectable-scoped, non-timing modules.

Runs `test_one` over every injectable with bounded concurrency, collecting
findings and per-input errors into a ModuleResult.
"""

from __future__ import annotations

from typing import Awaitable, Callable

from ..concurrency import map_bounded
from ..crawler import Injectable
from ..reporting import Finding, ModuleResult


async def scan_injectables(module: str, injectables: list[Injectable],
                           test_one: Callable[[Injectable], Awaitable[Finding | None]],
                           concurrency: int, noun: str) -> ModuleResult:
    async def _safe(inj: Injectable):
        try:
            return (await test_one(inj), None)
        except Exception as exc:
            return (None, f"{inj.method} {inj.url} [{inj.param}]: {exc.__class__.__name__}: {exc}")

    results = await map_bounded(injectables, _safe, concurrency)
    findings = [f for f, e in results if f]
    errors = [e for f, e in results if e]
    status = "success" if not errors else "partial"
    n = len(injectables)
    summary = (f"{noun} detected in {len(findings)} of {n} parameter(s)."
               if findings else f"No {noun.lower()} detected across {n} parameter(s).")
    return ModuleResult(module=module, status=status, summary=summary, findings=findings,
                        data={"parameters_tested": n}, errors=errors)
