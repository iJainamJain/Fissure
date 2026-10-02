"""Assemble an AI-scan report in the same shape as the deterministic engine's,
reusing the HTML and SARIF writers so output is identical across Step 1 and 2.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .. import __version__
from ..html_report import generate_html_report
from ..reporting import ModuleResult, risk_label
from ..targets import Target


def assemble_and_write(target: Target, results: list[ModuleResult], output: str, *,
                       executive_summary: str = "", html: bool = True, sarif: bool = False,
                       endpoints: int = 0, injectables: int = 0) -> dict[str, Any]:
    score = sum(r.risk_points() for r in results)
    report: dict[str, Any] = {
        "schema_version": "1.0",
        "tool": {"name": "Fissure AI", "version": __version__},
        "created_at": datetime.now(timezone.utc).isoformat(),
        "target": target.to_dict(),
        "executive_summary": executive_summary,
        "summary": {
            "score": score,
            "label": risk_label(score),
            "endpoints_crawled": endpoints,
            "injectables_found": injectables,
            "total_findings": sum(len(r.findings) for r in results),
        },
        "modules": {r.module: r.to_dict() for r in results},
        "outputs": {"json": output},
    }
    out = Path(output)
    out.parent.mkdir(parents=True, exist_ok=True)
    if html:
        report["outputs"]["html"] = generate_html_report(report, str(out.with_suffix(".html")))
    if sarif:
        from ..sarif import generate_sarif
        report["outputs"]["sarif"] = generate_sarif(report, str(out.with_suffix(".sarif")))
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report
