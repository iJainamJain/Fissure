"""ToolRegistry — exposes Fissure's crawler, modules, and HTTP as Claude tools.

Each tool validates via the gate, calls Step-1 code, and returns a compact JSON
envelope with short handles (inj_*, find_*) instead of re-sending payloads/URLs.
Tool outputs never carry raw response bodies into context.
"""

from __future__ import annotations

from typing import Any

from ..crawler import Crawler, CrawlResult, Injectable
from ..http import Session
from ..modules.cmdi import CmdiScanner
from ..modules.cors import CorsScanner
from ..modules.discovery import DiscoveryScanner
from ..modules.headers import HeaderScanner
from ..modules.redirect import RedirectScanner
from ..modules.sqli import SqliScanner
from ..modules.ssti import SstiScanner
from ..modules.traversal import TraversalScanner
from ..modules.xss import XssScanner
from ..reporting import ModuleResult
from ..targets import Target
from .gate import Gate
from .memory import FindingsStore
from .report import assemble_and_write

# Injectable-scoped active modules, by tool name.
_MODULES = {
    "run_sqli": SqliScanner, "run_xss": XssScanner, "run_cmdi": CmdiScanner,
    "run_traversal": TraversalScanner, "run_redirect": RedirectScanner,
}


def _finding_brief(f) -> dict[str, Any]:
    return {"title": f.title, "severity": f.severity, "confirmed": f.confirmed,
            "cwe": f.cwe, "evidence": f.evidence[:200]}


class ToolRegistry:
    def __init__(self, session: Session, target: Target, gate: Gate, store: FindingsStore,
                 output: str, *, html: bool = True, sarif: bool = False) -> None:
        self.session = session
        self.target = target
        self.gate = gate
        self.store = store
        self.output = output
        self.html = html
        self.sarif = sarif
        self.injectables: dict[str, Injectable] = {}
        self.crawl_result: CrawlResult | None = None
        self.report_paths: dict | None = None

    # ---- tool specs advertised to the model ----
    def specs(self) -> list:
        from .llm import ToolSpec
        inj = {"type": "object", "properties": {"injectable_id": {"type": "string"},
               "param": {"type": "string", "description": "alternative to injectable_id: match by param name"}}}
        return [
            ToolSpec("crawl", "Crawl the target to discover injectable inputs and pages.",
                     {"type": "object", "properties": {"max_pages": {"type": "integer"},
                      "max_depth": {"type": "integer"}}}),
            ToolSpec("get_injectables", "List discovered injectable inputs.",
                     {"type": "object", "properties": {"param": {"type": "string"}}}),
            ToolSpec("run_sqli", "Test one injectable for SQL injection.", inj),
            ToolSpec("run_xss", "Test one injectable for reflected XSS.", inj),
            ToolSpec("run_cmdi", "Test one injectable for OS command injection.", inj),
            ToolSpec("run_traversal", "Test one injectable for path traversal / LFI.", inj),
            ToolSpec("run_ssti", "Test one injectable for server-side template injection.", inj),
            ToolSpec("run_redirect", "Test one injectable for open redirect.", inj),
            ToolSpec("run_discovery", "Probe the site root for sensitive/default files.",
                     {"type": "object", "properties": {}}),
            ToolSpec("run_headers", "Passively audit security headers and cookie flags.",
                     {"type": "object", "properties": {}}),
            ToolSpec("run_cors", "Test crawled URLs for CORS misconfiguration.",
                     {"type": "object", "properties": {}}),
            ToolSpec("http_request", "Send one HTTP request (guarded). GET read-only probes only unless approved.",
                     {"type": "object", "properties": {
                        "method": {"type": "string", "enum": ["GET", "POST", "HEAD"]},
                        "url": {"type": "string"}, "params": {"type": "object"},
                        "data": {"type": "object"}, "intent": {"type": "string"}},
                      "required": ["method", "url"]}),
            ToolSpec("get_findings", "List findings gathered so far.",
                     {"type": "object", "properties": {"severity_min": {"type": "string"},
                      "confirmed_only": {"type": "boolean"}}}),
            ToolSpec("report", "Finalize and write the report. Ends the engagement.",
                     {"type": "object", "properties": {"executive_summary": {"type": "string"}},
                      "required": ["executive_summary"]}),
        ]

    # ---- dispatch ----
    async def dispatch(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
        try:
            handler = getattr(self, f"_t_{name}", None)
            if handler is None:
                return {"ok": False, "error": "unknown_tool", "detail": name}
            return await handler(args)
        except Exception as exc:  # surface as a tool error, never crash the loop
            return {"ok": False, "error": exc.__class__.__name__, "detail": str(exc)}

    def _resolve(self, args: dict[str, Any]) -> Injectable | None:
        if args.get("injectable_id") in self.injectables:
            return self.injectables[args["injectable_id"]]
        if args.get("param"):
            for inj in self.injectables.values():
                if inj.param == args["param"]:
                    return inj
        return None

    async def _t_crawl(self, args) -> dict:
        crawler = Crawler(self.target, self.session,
                          max_pages=int(args.get("max_pages", 25)),
                          max_depth=int(args.get("max_depth", 2)))
        self.crawl_result = await crawler.crawl()
        self.injectables = {}
        listed = []
        for i, inj in enumerate(self.crawl_result.injectables, 1):
            iid = f"inj_{i:03d}"
            self.injectables[iid] = inj
            listed.append({"id": iid, "method": inj.method, "url": inj.url, "param": inj.param})
        return {"ok": True, "data": {"pages_crawled": len(self.crawl_result.pages),
                "injectables": listed[:40], "truncated": len(listed) > 40}}

    async def _run_module(self, scanner_cls, args) -> dict:
        inj = self._resolve(args)
        if inj is None:
            return {"ok": False, "error": "no_injectable", "detail": "crawl first or pass a valid injectable_id/param"}
        result = await scanner_cls(self.session, [inj]).scan()
        ids = self.store.add_result(result)
        return {"ok": True, "data": {"module": result.module, "summary": result.summary,
                "findings": [{"id": fid, **_finding_brief(f)} for fid, f in zip(ids, result.findings)]}}

    async def _t_run_sqli(self, args): return await self._run_module(SqliScanner, args)
    async def _t_run_xss(self, args): return await self._run_module(XssScanner, args)
    async def _t_run_cmdi(self, args): return await self._run_module(CmdiScanner, args)
    async def _t_run_traversal(self, args): return await self._run_module(TraversalScanner, args)
    async def _t_run_ssti(self, args): return await self._run_module(SstiScanner, args)
    async def _t_run_redirect(self, args): return await self._run_module(RedirectScanner, args)

    async def _t_run_cors(self, args) -> dict:
        if self.crawl_result is None:
            return {"ok": False, "error": "no_crawl", "detail": "crawl first"}
        result = await CorsScanner(self.session, self.crawl_result).scan()
        ids = self.store.add_result(result)
        return {"ok": True, "data": {"module": "cors", "summary": result.summary,
                "findings": [{"id": fid, **_finding_brief(f)} for fid, f in zip(ids, result.findings)]}}

    async def _t_run_discovery(self, args) -> dict:
        result = await DiscoveryScanner(self.session, self.target).scan()
        ids = self.store.add_result(result)
        return {"ok": True, "data": {"module": "discovery", "summary": result.summary,
                "findings": [{"id": fid, **_finding_brief(f)} for fid, f in zip(ids, result.findings)]}}

    async def _t_run_headers(self, args) -> dict:
        if self.crawl_result is None:
            return {"ok": False, "error": "no_crawl", "detail": "crawl first"}
        result = await HeaderScanner(self.crawl_result).scan()
        ids = self.store.add_result(result)
        return {"ok": True, "data": {"module": "headers", "summary": result.summary,
                "findings": [{"id": fid, **_finding_brief(f)} for fid, f in zip(ids, result.findings)]}}

    async def _t_get_injectables(self, args) -> dict:
        rows = [{"id": iid, "method": i.method, "url": i.url, "param": i.param}
                for iid, i in self.injectables.items()
                if not args.get("param") or i.param == args["param"]]
        return {"ok": True, "data": {"injectables": rows}}

    async def _t_get_findings(self, args) -> dict:
        return {"ok": True, "data": {"findings": self.store.table(
            severity_min=args.get("severity_min"), confirmed_only=bool(args.get("confirmed_only")))}}

    async def _t_http_request(self, args) -> dict:
        method = args.get("method", "GET").upper()
        url = args["url"]
        params = args.get("params") or {}
        data = args.get("data") or {}
        decision = self.gate.check_request(method, url, params=params, data=data, intent=args.get("intent", ""))
        if not decision.allowed:
            return {"ok": False, "error": "blocked", "detail": decision.reason}
        if method == "POST":
            resp = await self.session.client.post(url, params=params, data=data, follow_redirects=False)
        else:
            resp = await self.session.client.request(method, url, params=params, follow_redirects=False)
        body = resp.text
        return {"ok": True, "data": {"status": resp.status_code, "body_len": len(body),
                "content_type": resp.headers.get("content-type", ""),
                "body_excerpt": body[:400]}}

    async def _t_report(self, args) -> dict:
        results: list[ModuleResult] = self.store.merged_results()
        report = assemble_and_write(
            self.target, results, self.output,
            executive_summary=args.get("executive_summary", ""),
            html=self.html, sarif=self.sarif,
            endpoints=len(self.crawl_result.pages) if self.crawl_result else 0,
            injectables=len(self.injectables))
        self.report_paths = report["outputs"]
        return {"ok": True, "data": {"paths": report["outputs"], "score": report["summary"]["label"],
                "total_findings": report["summary"]["total_findings"]}, "done": True}
