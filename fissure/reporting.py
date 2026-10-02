"""Shared result types and status vocabulary for Fissure modules.

Every scanner module returns a :class:`ModuleResult`. A result carries zero or
more :class:`Finding` objects plus free-form ``data`` for the report. Statuses
are explicit so the report can tell "clean" apart from "could not test".
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

ModuleStatus = Literal["success", "partial", "failure", "unreachable", "unsupported"]

# Points feed the risk score. Kept close to CVSS-ish bands so the report reads
# sensibly next to a manual pentest write-up.
SEVERITY_POINTS = {
    "critical": 25,
    "high": 16,
    "medium": 9,
    "low": 4,
    "info": 0,
}


@dataclass
class Finding:
    """A single confirmed or suspected issue on the target."""

    title: str
    severity: str  # one of SEVERITY_POINTS keys
    location: str  # URL + parameter the finding applies to
    evidence: str  # what proved it (matched error string, reflected marker, delay, ...)
    confirmed: bool = True  # False => heuristic / needs manual confirmation
    cwe: str | None = None  # e.g. "CWE-89" — industry-standard weakness id
    cvss: float | None = None  # optional CVSS v3.1 base score (0.0–10.0)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def points(self) -> int:
        base = SEVERITY_POINTS.get(self.severity.lower(), 0)
        return base if self.confirmed else max(1, base // 2)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["points"] = self.points
        return data


@dataclass
class ModuleResult:
    module: str
    status: ModuleStatus
    summary: str
    findings: list[Finding] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    started_at: str | None = None
    duration_seconds: float | None = None

    def risk_points(self) -> int:
        if self.status not in {"success", "partial"}:
            return 0
        return sum(finding.points for finding in self.findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "module": self.module,
            "status": self.status,
            "summary": self.summary,
            "findings": [finding.to_dict() for finding in self.findings],
            "risk_points": self.risk_points(),
            "data": self.data,
            "errors": self.errors,
            "timing": {
                "started_at": self.started_at,
                "duration_seconds": self.duration_seconds,
            },
        }


def risk_label(score: int) -> str:
    if score >= 60:
        return "CRITICAL"
    if score >= 35:
        return "HIGH"
    if score >= 15:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "CLEAN"
