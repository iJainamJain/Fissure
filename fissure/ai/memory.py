"""Findings store + engagement state for an AI scan.

Holds the big data (findings, injectable handles) outside the LLM context so the
conversation stays lean; tools read/write here and hand the model short handles.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from ..reporting import Finding, ModuleResult


def slugify(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:60] or "target"


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

    # ---- persistence (findings.jsonl) ----
    def save(self, directory: str | Path) -> None:
        d = Path(directory)
        d.mkdir(parents=True, exist_ok=True)
        with (d / "findings.jsonl").open("w", encoding="utf-8") as fh:
            for fid, f in self._findings.items():
                fh.write(json.dumps({"id": fid, "module": self._module_of[fid], **f.to_dict()}) + "\n")

    def load(self, directory: str | Path) -> "FindingsStore":
        fp = Path(directory) / "findings.jsonl"
        if not fp.exists():
            return self
        for line in fp.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            d = json.loads(line)
            f = Finding(title=d["title"], severity=d["severity"], location=d["location"],
                        evidence=d["evidence"], confirmed=d.get("confirmed", True),
                        cwe=d.get("cwe"), cvss=d.get("cvss"), metadata=d.get("metadata", {}))
            self._n += 1
            fid = d.get("id", f"find_{self._n:03d}")
            self._findings[fid] = f
            self._module_of[fid] = d["module"]
        groups: dict[str, list[Finding]] = defaultdict(list)
        for fid, f in self._findings.items():
            groups[self._module_of[fid]].append(f)
        for module, fs in groups.items():
            self.module_results.append(ModuleResult(module=module, status="success",
                                                    summary="(resumed from disk)", findings=fs))
        return self


@dataclass
class EngagementMemory:
    """Durable per-target state: which (module, input) pairs were already tested,
    so a resumed scan skips them. Stored at <base_dir>/<target-slug>/engagement.json.
    """

    base_dir: Path
    target_url: str
    scope: str = ""
    tested: set[str] = field(default_factory=set)
    notes: list[str] = field(default_factory=list)

    @property
    def dir(self) -> Path:
        return Path(self.base_dir) / slugify(self.target_url)

    @property
    def path(self) -> Path:
        return self.dir / "engagement.json"

    def load(self) -> "EngagementMemory":
        if self.path.exists():
            d = json.loads(self.path.read_text(encoding="utf-8"))
            self.tested = set(d.get("tested", []))
            self.notes = d.get("notes", [])
        return self

    def is_tested(self, sig: str) -> bool:
        return sig in self.tested

    def mark(self, sig: str) -> None:
        self.tested.add(sig)

    def save(self, extra: dict | None = None) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        payload = {
            "target": self.target_url,
            "scope": self.scope,
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "tested": sorted(self.tested),
            "notes": self.notes,
        }
        if extra:
            payload.update(extra)
        self.path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
