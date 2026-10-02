"""Command-line entry point for Fissure."""

from __future__ import annotations

import argparse
import asyncio
import sys

from . import __version__
from .engine import Engine
from .targets import ScopeError, TargetError

BANNER = (
    "Fissure sends active attack payloads. Only scan systems you own or have\n"
    "explicit written authorization to test. Default scope is localhost/private.\n"
)


def _parse_kv(pairs: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for item in pairs or []:
        if "=" not in item:
            raise SystemExit(f"Expected key=value, got: {item!r}")
        k, v = item.split("=", 1)
        out[k.strip()] = v.strip()
    return out


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="fissure", description="Active web-application vulnerability scanner.")
    p.add_argument("target", help="Target URL or host (e.g. http://localhost/dvwa/)")
    p.add_argument("-o", "--output", default="fissure_report.json", help="JSON report path.")
    p.add_argument("--html", action="store_true", help="Also write an HTML report next to the JSON.")
    p.add_argument("--sarif", action="store_true", help="Also write a SARIF 2.1.0 report (for CI / code scanning).")
    p.add_argument("--fail-on", choices=["info", "low", "medium", "high", "critical"],
                   help="Exit non-zero if any finding is at or above this severity (for CI gates).")
    p.add_argument("--timeout", type=float, default=10.0, help="Per-request timeout (seconds).")
    p.add_argument("--allow-public", action="store_true",
                   help="Permit a public target. Requires written authorization to test it.")
    p.add_argument("--cookie", action="append", default=[], metavar="NAME=VALUE",
                   help="Session cookie (repeatable). DVWA needs PHPSESSID and security.")
    p.add_argument("--header", action="append", default=[], metavar="NAME=VALUE",
                   help="Extra request header (repeatable).")
    p.add_argument("--crawl-pages", type=int, default=25)
    p.add_argument("--crawl-depth", type=int, default=2)
    p.add_argument("--crawl-delay", type=float, default=0.0, help="Delay between crawl requests (seconds).")
    p.add_argument("--login-url", help="Form-login URL to authenticate before scanning.")
    p.add_argument("--login-data", action="append", default=[], metavar="FIELD=VALUE",
                   help="Login form field (repeatable), e.g. username=admin password=password.")
    p.add_argument("--login-success-text", help="Text that must appear after a successful login.")
    p.add_argument("--login-token-field", help="Hidden anti-CSRF field name in the login form "
                   "(auto-detected if omitted, e.g. DVWA's user_token).")
    p.add_argument("--version", action="version", version=f"Fissure {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    sys.stderr.write(BANNER + "\n")

    login = None
    if args.login_url:
        login = {"url": args.login_url, "data": _parse_kv(args.login_data),
                 "success_text": args.login_success_text, "token_field": args.login_token_field}

    try:
        engine = Engine(
            args.target,
            output=args.output,
            timeout=args.timeout,
            allow_public=args.allow_public,
            cookies=_parse_kv(args.cookie),
            headers=_parse_kv(args.header),
            crawl_pages=args.crawl_pages,
            crawl_depth=args.crawl_depth,
            crawl_delay=args.crawl_delay,
            html=args.html,
            sarif=args.sarif,
            login=login,
        )
    except ScopeError as exc:
        sys.stderr.write(f"Scope refused: {exc}\n")
        return 2
    except TargetError as exc:
        sys.stderr.write(f"Bad target: {exc}\n")
        return 2

    report = asyncio.run(engine.run())
    s = report["summary"]
    print(f"\n{report['tool']['name']} {report['tool']['version']} — {report['target']['base_url']}")
    print(f"  endpoints crawled : {s['endpoints_crawled']}")
    print(f"  injectable inputs : {s['injectables_found']}")
    print(f"  findings          : {s['total_findings']}")
    print(f"  risk              : {s['label']} ({s['score']} pts)")
    print(f"  JSON report       : {report['outputs']['json']}")
    if "html" in report["outputs"]:
        print(f"  HTML report       : {report['outputs']['html']}")
    if "sarif" in report["outputs"]:
        print(f"  SARIF report      : {report['outputs']['sarif']}")

    if args.fail_on:
        order = ["info", "low", "medium", "high", "critical"]
        threshold = order.index(args.fail_on)
        worst = -1
        for module in report["modules"].values():
            for f in module["findings"]:
                worst = max(worst, order.index(f["severity"].lower()) if f["severity"].lower() in order else -1)
        if worst >= threshold:
            print(f"  gate              : FAIL (found {order[worst]} >= {args.fail_on})")
            return 1
        print(f"  gate              : PASS (nothing >= {args.fail_on})")
        return 0
    return 1 if s["total_findings"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
