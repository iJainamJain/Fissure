"""OS command-injection detection (time-based blind).

Mirrors the SQLi module's most trustworthy signal: inject a shell command that
sleeps for N seconds and confirm the response is delayed by roughly N, re-tested
once to reject a one-off slow response. Time-based is used as the sole signal
because echo/output-based detection is prone to false positives when the app
merely reflects the payload string back. Payloads are non-destructive
(sleep/ping only) and cover both Unix and Windows shells.
"""

from __future__ import annotations

from ..crawler import Injectable
from ..http import Session
from ..reporting import Finding, ModuleResult
from ._probe import send

SLEEP_SECONDS = 6
# Separator-prefixed sleeps for POSIX shells, plus a Windows ping delay.
TIME_PAYLOADS = [
    f"; sleep {SLEEP_SECONDS}",
    f"| sleep {SLEEP_SECONDS}",
    f"|| sleep {SLEEP_SECONDS}",
    f"& sleep {SLEEP_SECONDS}",
    f"$(sleep {SLEEP_SECONDS})",
    f"`sleep {SLEEP_SECONDS}`",
    f"& ping -n {SLEEP_SECONDS + 1} 127.0.0.1",  # Windows: ~N seconds
]


class CmdiScanner:
    module = "cmdi"

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
        summary = (f"OS command injection detected in {len(findings)} of {tested} parameter(s)."
                   if findings else f"No command injection detected across {tested} parameter(s).")
        return ModuleResult(module=self.module, status=status, summary=summary, findings=findings,
                            data={"parameters_tested": tested}, errors=errors)

    async def _test_one(self, inj: Injectable) -> Finding | None:
        loc = f"{inj.method} {inj.url} (param: {inj.param})"
        baseline = await send(self.session, inj, "127.0.0.1")
        for payload in TIME_PAYLOADS:
            probe = await send(self.session, inj, "127.0.0.1" + payload)
            if probe.elapsed >= SLEEP_SECONDS - 0.5 and probe.elapsed > baseline.elapsed + SLEEP_SECONDS - 1:
                confirm = await send(self.session, inj, "127.0.0.1" + payload)
                if confirm.elapsed >= SLEEP_SECONDS - 0.5:
                    return Finding(
                        title="OS command injection (time-based blind)",
                        severity="critical",
                        cwe="CWE-78",
                        location=loc,
                        evidence=(f"Payload delayed response to {probe.elapsed:.1f}s / {confirm.elapsed:.1f}s "
                                  f"(baseline {baseline.elapsed:.1f}s) for a {SLEEP_SECONDS}s sleep."),
                        metadata={"type": "time-based", "payload": payload},
                    )
        return None
