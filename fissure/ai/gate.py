"""Guardrail layer — enforced in code, between the model's request and the network.

Order per request: scope → payload denylist → destructiveness (HITL) → allow.
A block is returned as a decision, never raised, so the agent can recover in-loop.
Permission state comes only from engagement config passed here, never from the
conversation — so prompt-injection in a scanned page cannot widen scope.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable
from urllib.parse import urlsplit

from ..targets import Target

# Read-only probes are fine; these are never allowed from a model-authored request.
_DENY = re.compile(
    r"\b(drop\s+table|truncate\s+table|delete\s+from|insert\s+into|update\s+\w+\s+set)\b"
    r"|\brm\s+-rf|\bmkfs\b|\bshutdown\b|\breboot\b|:\(\)\s*\{|/dev/tcp/"
    r"|\b(curl|wget)\b", re.IGNORECASE)
# URL/param shapes that change server state -> require human approval.
_DESTRUCTIVE_URL = re.compile(r"/(logout|delete|remove|drop|transfer|purchase|checkout|reset)\b"
                              r"|action=(delete|remove|disable|transfer|purchase)", re.IGNORECASE)


@dataclass
class Decision:
    allowed: bool
    reason: str = ""


class Gate:
    def __init__(self, target: Target, *, allow_public: bool = False,
                 approval_cb: Callable[[dict], bool] | None = None) -> None:
        self.target = target
        self.allow_public = allow_public
        self.approval_cb = approval_cb  # returns True to approve a state-changing action

    def check_request(self, method: str, url: str, *, params: dict | None = None,
                      data: dict | None = None, intent: str = "") -> Decision:
        host = urlsplit(url).hostname
        if host and host != self.target.hostname:
            # Different host than the authorized target: out of scope.
            from ..targets import _classify  # type: ignore
            if _classify(host) == "public" and not self.allow_public:
                return Decision(False, f"scope: refusing out-of-scope host {host!r}")
            return Decision(False, f"scope: {host!r} is not the authorized target {self.target.hostname!r}")

        blob = " ".join([url, " ".join((params or {}).values()), " ".join((data or {}).values())])
        if _DENY.search(blob):
            return Decision(False, "denylist: request contains a destructive/exfiltration pattern")

        state_changing = method.upper() != "GET" or bool(_DESTRUCTIVE_URL.search(url))
        if state_changing:
            if self.approval_cb is None:
                return Decision(False, "state-changing action requires human approval (none configured)")
            approved = self.approval_cb({"method": method, "url": url, "params": params,
                                         "data": data, "intent": intent})
            if not approved:
                return Decision(False, "operator declined the state-changing action")
        return Decision(True)
