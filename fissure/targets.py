"""Target normalization and scope enforcement.

Fissure sends *active* payloads, so scope control is a safety feature, not a
convenience. By default only loopback and private-range hosts are allowed;
scanning a public host requires an explicit opt-in flag that stands in for
"I have written authorization to test this system".
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from ipaddress import ip_address
from typing import Literal
from urllib.parse import urlsplit

Scope = Literal["local", "private", "public"]


class TargetError(ValueError):
    """Raised when a target cannot be parsed."""


class ScopeError(PermissionError):
    """Raised when a target is outside the authorized scan scope."""


@dataclass(frozen=True)
class Target:
    raw_input: str
    scheme: str
    hostname: str
    port: int
    base_url: str  # site root, e.g. http://host:port  (used for path discovery)
    start_url: str  # full requested URL incl. path/query (crawl seed)
    scope: Scope = "public"

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def normalize_target(raw: str, *, prefer_https: bool | None = None) -> Target:
    raw = (raw or "").strip()
    if not raw:
        raise TargetError("Target cannot be empty.")

    parts = urlsplit(raw if "://" in raw else f"//{raw}", scheme="")
    if parts.scheme and parts.scheme.lower() not in {"http", "https"}:
        raise TargetError(f"Unsupported scheme: {parts.scheme}")

    hostname = parts.hostname
    if not hostname:
        raise TargetError(f"Could not read a hostname from: {raw}")

    try:
        explicit_port = parts.port
    except ValueError as exc:
        raise TargetError(f"Invalid port in target: {raw}") from exc

    scope = _classify(hostname)
    if parts.scheme:
        scheme = parts.scheme.lower()
    elif explicit_port == 443:
        scheme = "https"
    elif prefer_https is not None:
        scheme = "https" if prefer_https else "http"
    else:
        scheme = "http" if scope in {"local", "private"} else "https"

    port = explicit_port or (443 if scheme == "https" else 80)
    if not 1 <= port <= 65535:
        raise TargetError(f"Port out of range: {port}")

    default_port = 443 if scheme == "https" else 80
    host = hostname if (port == default_port and explicit_port is None) else f"{hostname}:{port}"
    base_url = f"{scheme}://{host}"

    path = parts.path or "/"
    start_url = f"{base_url}{path}"
    if parts.query:
        start_url += f"?{parts.query}"

    return Target(raw_input=raw, scheme=scheme, hostname=hostname, port=port,
                  base_url=base_url, start_url=start_url, scope=scope)


def validate_scope(target: Target, *, allow_public: bool = False) -> None:
    if target.scope == "public" and not allow_public:
        raise ScopeError(
            f"Target '{target.hostname}' is a PUBLIC host. Fissure sends active "
            "attack payloads and refuses public targets by default. Re-run with "
            "--allow-public only if you have explicit written authorization to test it."
        )


def _classify(hostname: str) -> str:
    lowered = hostname.lower().strip("[]")
    if lowered == "localhost":
        return "local"
    try:
        ip = ip_address(lowered)
    except ValueError:
        return "public"  # a DNS name we cannot resolve to a private range here
    if ip.is_loopback:
        return "local"
    if ip.is_private or ip.is_link_local:
        return "private"
    return "public"
