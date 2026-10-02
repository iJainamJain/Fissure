"""`fissure-ai` — run the Claude-orchestrated agent against a target.

Requires `pip install fissure-scan[ai]` and ANTHROPIC_API_KEY. Model ids default
to current Claude models; override with --brain-model / --worker-model.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys

from ..targets import ScopeError, TargetError
from .agent import Agent
from .hive import Budget, Hive
from .llm import AnthropicClient, GeminiClient

BANNER = ("Fissure AI drives active attack payloads via an LLM agent. Authorized,\n"
          "localhost/private targets only unless --allow-public (with written permission).\n")

# provider -> (client class, default model, env var)
PROVIDERS = {
    "anthropic": (AnthropicClient, "claude-opus-5-5", "ANTHROPIC_API_KEY"),
    "gemini": (GeminiClient, "gemini-3.5-flash", "GEMINI_API_KEY"),
}


def _approval(req: dict) -> bool:
    sys.stderr.write(f"\n[APPROVAL] {req['method']} {req['url']}  intent: {req.get('intent','')}\n")
    try:
        return input("Approve this state-changing action? [y/N] ").strip().lower() == "y"
    except EOFError:
        return False


def _cookies(pairs):
    out = {}
    for item in pairs or []:
        if "=" in item:
            k, v = item.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="fissure-ai", description="Claude-orchestrated web pentest agent.")
    p.add_argument("target")
    p.add_argument("-o", "--output", default="fissure_ai_report.json")
    p.add_argument("--allow-public", action="store_true")
    p.add_argument("--cookie", action="append", default=[], metavar="NAME=VALUE")
    p.add_argument("--provider", choices=list(PROVIDERS), default="anthropic",
                   help="LLM provider for the brain (anthropic or gemini).")
    p.add_argument("--brain-model", default=None, help="Model id (defaults per provider).")
    p.add_argument("--worker-model", default=None, help="Optional cheap worker model (same provider).")
    p.add_argument("--max-steps", type=int, default=40)
    p.add_argument("--workdir", default=".fissure", help="Where engagement state is persisted.")
    p.add_argument("--resume", action="store_true", help="Resume a prior engagement for this target (skip tested inputs).")
    p.add_argument("--sarif", action="store_true")
    p.add_argument("--no-html", action="store_true")
    args = p.parse_args(argv)
    sys.stderr.write(BANNER + "\n")

    client_cls, default_model, env_var = PROVIDERS[args.provider]
    if not os.environ.get(env_var):
        sys.stderr.write(f"{env_var} is not set (required for --provider {args.provider}).\n")
        return 2

    brain = client_cls(args.brain_model or default_model, tier="brain")
    worker = client_cls(args.worker_model, tier="worker") if args.worker_model else None
    hive = Hive(brain, worker, budget=Budget(max_steps=args.max_steps))

    try:
        agent = Agent(args.target, hive, allow_public=args.allow_public, output=args.output,
                      cookies=_cookies(args.cookie), approval_cb=_approval,
                      html=not args.no_html, sarif=args.sarif,
                      workdir=args.workdir, resume=args.resume,
                      progress=lambda stage, detail: sys.stderr.write(f"  · {stage}: {detail}\n"))
    except ScopeError as exc:
        sys.stderr.write(f"Scope refused: {exc}\n"); return 2
    except TargetError as exc:
        sys.stderr.write(f"Bad target: {exc}\n"); return 2

    result = asyncio.run(agent.run())
    print(f"\nFissure AI — {result['stop']} after {result['steps']} step(s), {result['findings']} finding(s)")
    for kind, path in (result["outputs"] or {}).items():
        print(f"  {kind:<6}: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
