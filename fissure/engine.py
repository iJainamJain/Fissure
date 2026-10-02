"""Scan orchestrator: crawl once, then run the active modules over the findings."""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .crawler import Crawler
from .html_report import generate_html_report
from .http import Session
from .modules.cmdi import CmdiScanner
from .modules.discovery import DiscoveryScanner
from .modules.headers import HeaderScanner
from .modules.redirect import RedirectScanner
from .modules.sqli import SqliScanner
from .modules.traversal import TraversalScanner
from .modules.xss import XssScanner
from .reporting import ModuleResult, risk_label
from .targets import Target, normalize_target, validate_scope


class Engine:
    def __init__(
        self,
        target_input: str,
        *,
        output: str = "fissure_report.json",
        timeout: float = 10.0,
        allow_public: bool = False,
        cookies: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        crawl_pages: int = 25,
        crawl_depth: int = 2,
        crawl_delay: float = 0.0,
        html: bool = False,
        sarif: bool = False,
        login: dict | None = None,
        progress: "Callable[[str, str], None] | None" = None,
    ) -> None:
        self.target: Target = normalize_target(target_input)
        validate_scope(self.target, allow_public=allow_public)
        self.output = Path(output)
        self.timeout = timeout
        self.cookies = cookies or {}
        self.headers = headers or {}
        self.crawl_pages = crawl_pages
        self.crawl_depth = crawl_depth
        self.crawl_delay = crawl_delay
        self.html = html
        self.sarif = sarif
        self.login = login  # {"url":..., "data":{...}, "success_text":...}
        self._progress = progress

    def _emit(self, stage: str, detail: str = "") -> None:
        if self._progress:
            self._progress(stage, detail)

    async def run(self) -> dict[str, Any]:
        created_at = datetime.now(timezone.utc).isoformat()
        results: list[ModuleResult] = []

        async with Session(timeout=self.timeout, cookies=self.cookies, headers=self.headers) as session:
            if self.login:
                self._emit("login", self.login["url"])
                ok = await session.login(
                    self.login["url"], self.login["data"],
                    token_field=self.login.get("token_field"),
                    success_text=self.login.get("success_text"),
                )
                if not ok:
                    raise RuntimeError("Form login failed; check credentials/success_text.")

            self._emit("crawl", "Discovering endpoints and injectable inputs…")
            crawl = await Crawler(
                self.target, session,
                max_pages=self.crawl_pages, max_depth=self.crawl_depth, delay=self.crawl_delay,
            ).crawl()
            injectables = crawl.injectables
            self._emit("crawl_done", f"{len(crawl.pages)} pages, {len(injectables)} injectable inputs")

            # Passive first (no payloads), then the active injection modules.
            self._emit("module_start", "headers")
            headers_result = await self._timed(HeaderScanner(crawl).scan())
            results.append(headers_result)
            self._emit("module_done", f"headers:{len(headers_result.findings)}")

            scanners = [
                ("sqli", SqliScanner(session, injectables)),
                ("xss", XssScanner(session, injectables)),
                ("cmdi", CmdiScanner(session, injectables)),
                ("traversal", TraversalScanner(session, injectables)),
                ("redirect", RedirectScanner(session, injectables)),
                ("discovery", DiscoveryScanner(session, self.target)),
            ]
            for name, scanner in scanners:
                # Self-heal a dropped login between modules so later modules
                # don't silently produce false negatives on a logged-out session.
                if not await session.ensure_authenticated(self.target.start_url):
                    self._emit("auth_lost", name)
                self._emit("module_start", name)
                result = await self._timed(scanner.scan())
                results.append(result)
                self._emit("module_done", f"{name}:{len(result.findings)}")

        score = sum(r.risk_points() for r in results)
        report = {
            "schema_version": "1.0",
            "tool": {"name": "Fissure", "version": self._version()},
            "created_at": created_at,
            "target": self.target.to_dict(),
            "summary": {
                "score": score,
                "label": risk_label(score),
                "endpoints_crawled": len(crawl.pages),
                "injectables_found": len(injectables),
                "total_findings": sum(len(r.findings) for r in results),
            },
            "modules": {r.module: r.to_dict() for r in results},
            "outputs": {"json": str(self.output)},
        }

        self.output.parent.mkdir(parents=True, exist_ok=True)
        self.output.write_text(json.dumps(report, indent=2), encoding="utf-8")
        if self.html:
            report["outputs"]["html"] = generate_html_report(report, str(self.output.with_suffix(".html")))
        if self.sarif:
            from .sarif import generate_sarif
            report["outputs"]["sarif"] = generate_sarif(report, str(self.output.with_suffix(".sarif")))
        if self.html or self.sarif:
            self.output.write_text(json.dumps(report, indent=2), encoding="utf-8")
        return report

    async def _timed(self, coro) -> ModuleResult:
        started = datetime.now(timezone.utc).isoformat()
        start = time.perf_counter()
        result = await coro
        result.started_at = started
        result.duration_seconds = round(time.perf_counter() - start, 3)
        return result

    @staticmethod
    def _version() -> str:
        from . import __version__

        return __version__
