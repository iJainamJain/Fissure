"""SARIF 2.1.0 export.

SARIF is the standard static-analysis interchange format; GitHub code-scanning
ingests it natively. Exporting findings as SARIF lets Fissure plug into CI and
show results on a PR. We map Fissure severities to SARIF levels:

    critical / high  -> error
    medium           -> warning
    low / info       -> note
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
_URL_RE = re.compile(r"https?://[^\s()]+")


def _slug(title: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")


def _uri(location: str) -> str:
    m = _URL_RE.search(location or "")
    return m.group(0) if m else (location or "unknown")


def generate_sarif(report: dict[str, Any], output_path: str) -> str:
    rules: dict[str, dict] = {}
    results: list[dict] = []

    for module in report["modules"].values():
        for f in module["findings"]:
            rule_id = _slug(f["title"])
            if rule_id not in rules:
                rule = {
                    "id": rule_id,
                    "name": f["title"],
                    "shortDescription": {"text": f["title"]},
                    "defaultConfiguration": {"level": _LEVEL.get(f["severity"].lower(), "warning")},
                    "properties": {"security-severity": _security_severity(f)},
                }
                if f.get("cwe"):
                    rule["properties"]["cwe"] = f["cwe"]
                    rule["relationships"] = [{"target": {"id": f["cwe"],
                                                         "toolComponent": {"name": "CWE"}}}]
                rules[rule_id] = rule
            results.append({
                "ruleId": rule_id,
                "level": _LEVEL.get(f["severity"].lower(), "warning"),
                "message": {"text": f["evidence"]},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": _uri(f["location"])}}}],
                "properties": {"severity": f["severity"], "confirmed": f["confirmed"],
                               "module": module["module"], "cwe": f.get("cwe")},
            })

    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {
                "name": "Fissure",
                "version": report["tool"]["version"],
                "informationUri": "https://github.com/",
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(sarif, indent=2), encoding="utf-8")
    return str(path)


def _security_severity(finding: dict) -> str:
    """A 0.0–10.0 string GitHub uses to bucket severity, derived from our bands."""
    if finding.get("cvss") is not None:
        return str(finding["cvss"])
    return {"critical": "9.0", "high": "7.5", "medium": "5.0", "low": "3.0", "info": "0.0"} \
        .get(finding["severity"].lower(), "5.0")
