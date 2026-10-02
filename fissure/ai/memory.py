"""Findings store + engagement state for an AI scan.

Holds the big data (findings, injectable handles) outside the LLM context so the
conversation stays lean; tools read/write here and hand the model short handles.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..reporting import Finding, ModuleResult


@dataclass
class FindingsStore:
    _findings: dict[str, Finding] = field(default_factory=dict)
    _module_of: dict[str, str] = field(default_factory=dict)
    module_results: list[ModuleResult] = field(default_factory=list)
    _n: int = 0

    def add_result(self, result: ModuleResult) -> list[str]:
        """Record a ModuleResult; return the new finding handles."""
        self.module_results.append(result)
        ids: list[str] = []
        for f in result.findings:
            self._n += 1
            fid = f"find_{self._n:03d}"
            self._findings[fid] = f
            self._module_of[fid] = result.module
            ids.append(fid)
        return ids

    def table(self, *, severity_min: str | None = None, confirmed_only: bool = False) -> list[dict]:
        order = ["info", "low", "medium", "high", "critical"]
        floor = order.index(severity_min) if severity_min in order else 0
        rows = []
        for fid, f in self._findings.items():
            if f.severity.lower() in order and order.index(f.severity.lower()) < floor:
                continue
            if confirmed_only and not f.confirmed:
                continue
            rows.append({"id": fid, "module": self._module_of[fid], "title": f.title,
                         "severity": f.severity, "confirmed": f.confirmed,
                         "cwe": f.cwe, "location": f.location})
        return rows

    def count(self) -> int:
        return len(self._findings)

    def merged_results(self) -> list[ModuleResult]:
        """One ModuleResult per module (findings concatenated) for reporting."""
        by_module: dict[str, ModuleResult] = {}
        for r in self.module_results:
            if r.module not in by_module:
                by_module[r.module] = ModuleResult(module=r.module, status=r.status,
                                                   summary=r.summary, findings=list(r.findings),
                                                   data=dict(r.data), errors=list(r.errors))
            else:
                by_module[r.module].findings.extend(r.findings)
        return list(by_module.values())
