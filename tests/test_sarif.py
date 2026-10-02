"""SARIF 2.1.0 export shape."""

from __future__ import annotations

import json

from fissure.sarif import generate_sarif


def _report():
    return {
        "tool": {"name": "Fissure", "version": "0.1.0"},
        "modules": {
            "sqli": {"module": "sqli", "findings": [
                {"title": "SQL injection (error-based)", "severity": "critical",
                 "location": "GET http://localhost/vuln?id= (param: id)",
                 "evidence": "DB error leaked", "confirmed": True, "cwe": "CWE-89", "cvss": None},
            ]},
            "headers": {"module": "headers", "findings": [
                {"title": "Missing security header: content-security-policy", "severity": "medium",
                 "location": "http://localhost/", "evidence": "No CSP", "confirmed": True,
                 "cwe": "CWE-693", "cvss": None},
            ]},
        },
    }


def test_sarif_structure(tmp_path):
    out = tmp_path / "r.sarif"
    generate_sarif(_report(), str(out))
    doc = json.loads(out.read_text())

    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "Fissure"
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert "sql-injection-error-based" in rule_ids

    levels = {res["level"] for res in run["results"]}
    assert levels == {"error", "warning"}  # critical->error, medium->warning
    sqli = next(r for r in run["results"] if r["ruleId"] == "sql-injection-error-based")
    assert sqli["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].startswith("http://localhost/vuln")
    assert sqli["properties"]["cwe"] == "CWE-89"
