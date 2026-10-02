"""Fissure AI (Step 2) — a Claude-orchestrated pentester that drives the
deterministic Fissure scanner as its toolbelt.

The LLM plans, chains, confirms, and triages; the Step-1 modules do all
detection for zero tokens. Guardrails (scope, denylist, approval) are enforced
in the tool layer, never by the prompt. See docs/FISSURE_AI_DESIGN.md.

Importing this package does not require the `anthropic` SDK; only constructing
an `AnthropicClient` does (`pip install fissure-scan[ai]`).
"""
