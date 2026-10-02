"""Brain/worker routing and the scan budget.

The brain (Claude) does tool-use planning and final judgement. The optional
worker (Haiku / Gemini Flash) only compacts large tool output and drafts prose.
If no worker is configured, compaction falls back to deterministic truncation.
Rule enforced by convention: never call an LLM where deterministic code suffices.
"""

from __future__ import annotations

from dataclasses import dataclass

from .llm import LLMClient


@dataclass
class Budget:
    max_steps: int = 40
    token_budget: int = 200_000
    steps: int = 0
    tokens: int = 0

    def tick(self, tokens: int = 0) -> None:
        self.steps += 1
        self.tokens += tokens

    def exceeded(self) -> bool:
        return self.steps >= self.max_steps or self.tokens >= self.token_budget

    def reason(self) -> str:
        if self.steps >= self.max_steps:
            return f"max_steps ({self.max_steps}) reached"
        if self.tokens >= self.token_budget:
            return f"token budget ({self.token_budget}) reached"
        return ""


class Hive:
    def __init__(self, brain: LLMClient, worker: LLMClient | None = None, *, budget: Budget | None = None) -> None:
        self.brain = brain
        self.worker = worker
        self.budget = budget or Budget()

    def compact(self, text: str, hint: str, *, max_out: int = 600) -> str:
        if len(text) <= max_out:
            return text
        if self.worker is not None:
            try:
                return self.worker.compact(text, hint, max_out=max_out)
            except Exception:
                pass  # fall back to deterministic truncation
        return text[:max_out] + " …[truncated]"
