"""Engagement persistence: findings store round-trip, engagement state, and resume."""

from __future__ import annotations

import json

from fissure.ai.agent import Agent
from fissure.ai.hive import Budget, Hive
from fissure.ai.llm import LLMResponse, MockLLMClient, ToolCall
from fissure.ai.memory import EngagementMemory, FindingsStore
from fissure.reporting import Finding, ModuleResult


def test_findings_store_round_trip(tmp_path):
    store = FindingsStore()
    store.add_result(ModuleResult(module="sqli", status="success", summary="x", findings=[
        Finding(title="SQL injection (error-based)", severity="critical",
                location="GET http://h/q (param: q)", evidence="DB error", cwe="CWE-89")]))
    store.save(tmp_path)

    reloaded = FindingsStore().load(tmp_path)
    assert reloaded.count() == 1
    merged = reloaded.merged_results()
    assert merged[0].module == "sqli" and merged[0].findings[0].cwe == "CWE-89"


def test_engagement_memory_persist(tmp_path):
    mem = EngagementMemory(tmp_path, "http://localhost:8080/app")
    mem.mark("sqli:GET http://localhost:8080/app/x [id]")
    mem.save()

    reloaded = EngagementMemory(tmp_path, "http://localhost:8080/app").load()
    assert reloaded.is_tested("sqli:GET http://localhost:8080/app/x [id]")
    assert (reloaded.path).exists()


def _find_id(messages, param):
    payload = json.loads(messages[-1]["content"][0]["content"])
    for inj in payload["data"]["injectables"]:
        if inj["param"] == param:
            return inj["id"]
    raise AssertionError("not found")


async def test_agent_persists_and_resume_skips(vulnlab_url, tmp_path):
    work = str(tmp_path / "state")

    def responder(step, messages):
        if step == 0:
            return LLMResponse("recon", [ToolCall("c0", "crawl", {"max_depth": 0})], "tool_use")
        if step == 1:
            return LLMResponse("sqli", [ToolCall("c1", "run_sqli", {"param": "q"})], "tool_use")
        if step == 2:
            return LLMResponse("done", [ToolCall("c2", "report", {"executive_summary": "x"})], "tool_use")
        return LLMResponse("end", [], "end")

    # First engagement: records sqli on q as tested + persists findings.
    agent = Agent(f"{vulnlab_url}/search?q=1", Hive(MockLLMClient(responder), budget=Budget(max_steps=8)),
                  output=str(tmp_path / "r1.json"), html=False, workdir=work)
    await agent.run()
    mem = EngagementMemory(work, agent.target.base_url).load()
    assert any(s.startswith("sqli:") for s in mem.tested)

    # Second engagement resumes: re-requesting run_sqli on q must be skipped.
    skipped = {}

    def responder2(step, messages):
        if step == 0:
            return LLMResponse("recon", [ToolCall("d0", "crawl", {"max_depth": 0})], "tool_use")
        if step == 1:
            return LLMResponse("sqli-again", [ToolCall("d1", "run_sqli", {"param": "q"})], "tool_use")
        if step == 2:
            # capture the tool result for the run_sqli call
            skipped["note"] = json.loads(messages[-1]["content"][0]["content"])
            return LLMResponse("done", [ToolCall("d2", "report", {"executive_summary": "x"})], "tool_use")
        return LLMResponse("end", [], "end")

    agent2 = Agent(f"{vulnlab_url}/search?q=1", Hive(MockLLMClient(responder2), budget=Budget(max_steps=8)),
                   output=str(tmp_path / "r2.json"), html=False, workdir=work, resume=True)
    await agent2.run()
    assert "already tested" in skipped["note"]["data"].get("note", "")
