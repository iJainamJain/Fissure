"""SQL-injection detection: error-based, boolean-based, and time-based.

Detection strategy, cheapest to most expensive, stopping at the first hit
per parameter:

1. **Error-based** — inject a syntax-breaking character and look for a known
   database error string in the response.
2. **Boolean-based** — send an always-true and an always-false condition; a
   large, consistent difference in response length implies the query reacts
   to injected logic.
3. **Time-based** — inject a database sleep and confirm the response is
   delayed by roughly the requested interval (re-tested once to reject noise).
"""

from __future__ import annotations

import re

from ..crawler import Injectable
from ..http import Session
from ..reporting import Finding, ModuleResult
from ._probe import send

# Signatures of raw DB errors leaking to the page (error-based).
DB_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"warning: mysqli?_",
    r"unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    r"pg_query\(\)|pg_exec\(\)|postgresql",
    r"sqlite3?::|sqlite_error|unrecognized token",
    r"ora-\d{5}",
    r"odbc sql server driver",
    r"supplied argument is not a valid mysql",
]
ERROR_RE = re.compile("|".join(DB_ERROR_PATTERNS), re.IGNORECASE)

ERROR_PAYLOADS = ["'", '"', "')", "';"]
TRUE_PAYLOAD = "1' OR '1'='1"
FALSE_PAYLOAD = "1' AND '1'='2"
SLEEP_SECONDS = 5
# One payload per common backend; the module tries each until one delays.
TIME_PAYLOADS = [
    f"1' AND SLEEP({SLEEP_SECONDS})-- -",          # MySQL
    f"1'; SELECT pg_sleep({SLEEP_SECONDS})-- -",    # PostgreSQL
    f"1' WAITFOR DELAY '0:0:{SLEEP_SECONDS}'-- -",  # MSSQL
]


class SqliScanner:
    module = "sqli"

    def __init__(self, session: Session, injectables: list[Injectable]) -> None:
        self.session = session
        self.injectables = injectables

    async def scan(self) -> ModuleResult:
        findings: list[Finding] = []
        tested = 0
        errors: list[str] = []

        for inj in self.injectables:
            tested += 1
            try:
                finding = await self._test_one(inj)
            except Exception as exc:  # keep scanning the rest
                errors.append(f"{inj.method} {inj.url} [{inj.param}]: {exc.__class__.__name__}: {exc}")
                continue
            if finding:
                findings.append(finding)

        status = "success" if not errors else "partial"
        summary = (
            f"SQL injection detected in {len(findings)} of {tested} parameter(s)."
            if findings
            else f"No SQL injection detected across {tested} parameter(s)."
        )
        return ModuleResult(module=self.module, status=status, summary=summary, findings=findings,
                            data={"parameters_tested": tested}, errors=errors)

    async def _test_one(self, inj: Injectable) -> Finding | None:
        loc = f"{inj.method} {inj.url} (param: {inj.param})"

        # 1. Error-based
        for payload in ERROR_PAYLOADS:
            probe = await send(self.session, inj, payload)
            match = ERROR_RE.search(probe.text)
            if match:
                return Finding(
                    title="SQL injection (error-based)",
                    severity="critical",
                    cwe="CWE-89",
                    location=loc,
                    evidence=f"Payload {payload!r} triggered DB error: {match.group(0)!r}",
                    metadata={"type": "error-based", "payload": payload},
                )

        # 2. Boolean-based
        true_probe = await send(self.session, inj, TRUE_PAYLOAD)
        false_probe = await send(self.session, inj, FALSE_PAYLOAD)
        diff = abs(len(true_probe.text) - len(false_probe.text))
        if true_probe.status == false_probe.status and diff > 40 and len(false_probe.text) > 0:
            return Finding(
                title="SQL injection (boolean-based)",
                severity="high",
                cwe="CWE-89",
                location=loc,
                evidence=(
                    f"TRUE vs FALSE condition changed response size by {diff} bytes "
                    f"({len(true_probe.text)} vs {len(false_probe.text)})."
                ),
                confirmed=False,  # heuristic; flag for manual confirmation
                metadata={"type": "boolean-based", "true_len": len(true_probe.text), "false_len": len(false_probe.text)},
            )

        # 3. Time-based
        baseline = await send(self.session, inj, "1")
        for payload in TIME_PAYLOADS:
            probe = await send(self.session, inj, payload)
            if probe.elapsed >= SLEEP_SECONDS - 0.5 and probe.elapsed > baseline.elapsed + SLEEP_SECONDS - 1:
                confirm = await send(self.session, inj, payload)  # re-test to reject a one-off slow response
                if confirm.elapsed >= SLEEP_SECONDS - 0.5:
                    return Finding(
                        title="SQL injection (time-based blind)",
                        severity="critical",
                        cwe="CWE-89",
                        location=loc,
                        evidence=(
                            f"Payload delayed response to {probe.elapsed:.1f}s / {confirm.elapsed:.1f}s "
                            f"(baseline {baseline.elapsed:.1f}s) for a {SLEEP_SECONDS}s sleep."
                        ),
                        metadata={"type": "time-based", "payload": payload},
                    )
        return None
