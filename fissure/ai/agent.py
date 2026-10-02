"""The orchestrator loop: a plain Anthropic Messages-API tool-use (ReAct) loop.

Claude plans; the ToolRegistry runs Step-1 code; the Hive worker compacts large
tool output; the Gate enforces safety. Stops when `report` is called, on budget
exhaustion, or after a nudge if the model stalls.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, Callable

from ..http import Session
from ..targets import ScopeError, Target, normalize_target, validate_scope
from .gate import Gate
from .hive import Hive
from .memory import EngagementMemory, FindingsStore
from .prompts import INITIAL_TASK, NUDGE, SYSTEM_PROMPT
from .tools import ToolRegistry


class Agent:
    def __init__(self, target_input: str, hive: Hive, *, allow_public: bool = False,
                 output: str = "fissure_ai_report.json", cookies: dict | None = None,
                 approval_cb: Callable[[dict], bool] | None = None, html: bool = True,
                 sarif: bool = False, timeout: float = 15.0, workdir: str = ".fissure",
                 resume: bool = False, progress: Callable[[str, str], None] | None = None) -> None:
        self.target: Target = normalize_target(target_input)
        validate_scope(self.target, allow_public=allow_public)
        self.hive = hive
        self.output = output
        self.cookies = cookies or {}
        self.gate = Gate(self.target, allow_public=allow_public, approval_cb=approval_cb)
        self.html = html
        self.sarif = sarif
        self.timeout = timeout
        self.workdir = workdir
        self.resume = resume
        self.progress = progress

    def _emit(self, stage: str, detail: str = "") -> None:
        if self.progress:
            self.progress(stage, detail)

    async def run(self) -> dict[str, Any]:
        store = FindingsStore()
        memory = EngagementMemory(self.workdir, self.target.base_url, scope=self.target.scope)
        if self.resume:
            memory.load()
            store.load(memory.dir)
        async with Session(timeout=self.timeout, cookies=self.cookies) as session:
            tools = ToolRegistry(session, self.target, self.gate, store, self.output,
                                 html=self.html, sarif=self.sarif, memory=memory)
            specs = tools.specs()
            messages: list[dict] = [{"role": "user", "content": INITIAL_TASK.format(
                base_url=self.target.base_url, scope=self.target.scope)}]
            nudged = False

            while not self.hive.budget.exceeded():
                resp = await asyncio.to_thread(
                    self.hive.brain.complete, system=SYSTEM_PROMPT, messages=messages,
                    tools=specs, max_tokens=4096)
                self.hive.budget.tick(resp.usage.total)

                # Rebuild the assistant turn as content blocks for the API.
                assistant_blocks: list[dict] = []
                if resp.text:
                    assistant_blocks.append({"type": "text", "text": resp.text})
                for call in resp.tool_calls:
                    assistant_blocks.append({"type": "tool_use", "id": call.id,
                                             "name": call.name, "input": call.input})
                messages.append({"role": "assistant", "content": assistant_blocks or [{"type": "text", "text": ""}]})

                if resp.stop_reason != "tool_use" or not resp.tool_calls:
                    if tools.report_paths or nudged:
                        break
                    messages.append({"role": "user", "content": NUDGE})
                    nudged = True
                    continue

                tool_results: list[dict] = []
                done = False
                for call in resp.tool_calls:
                    self._emit("tool", call.name)
                    out = await tools.dispatch(call.name, call.input)
                    if out.pop("done", False):
                        done = True
                    content = json.dumps(out)
                    # Tool envelopes are already bounded (handles, field caps). Only ask a
                    # worker model to compress when one is configured and output is large;
                    # never truncate structured JSON blindly (it would corrupt it).
                    if self.hive.worker is not None and len(content) > 2000:
                        content = self.hive.compact(content, call.name, max_out=1500)
                    tool_results.append({"type": "tool_result", "tool_use_id": call.id, "content": content})
                messages.append({"role": "user", "content": tool_results})
                memory.save(extra={"findings": store.count()})  # persist progress each batch
                store.save(memory.dir)
                if done:
                    break

            if tools.report_paths is None:
                # Model never finalized; write the report from whatever was gathered.
                out = await tools.dispatch("report", {"executive_summary":
                    "Auto-finalized: the agent stopped before calling report."})
                tools.report_paths = out.get("data", {}).get("paths")

            return {"outputs": tools.report_paths, "findings": store.count(),
                    "steps": self.hive.budget.steps, "stop": self.hive.budget.reason() or "report"}
