"""Fissure AI: orchestrator loop + tools + guardrails, driven by a scripted mock LLM."""

from __future__ import annotations

import json

from fissure.ai.agent import Agent
from fissure.ai.gate import Gate
from fissure.ai.hive import Budget, Hive
from fissure.ai.llm import GeminiClient, LLMResponse, MockLLMClient, ToolCall, ToolSpec
from fissure.targets import normalize_target


def _find_injectable_id(messages, param):
    """Pull an injectable id for `param` out of the last tool_result (crawl output)."""
    last = messages[-1]["content"]
    payload = json.loads(last[0]["content"])
    for inj in payload["data"]["injectables"]:
        if inj["param"] == param:
            return inj["id"]
    raise AssertionError(f"no injectable for param {param}")


def _responder():
    def responder(step, messages):
        if step == 0:
            return LLMResponse("recon", [ToolCall("c0", "crawl", {"max_depth": 1})], "tool_use")
        if step == 1:
            iid = _find_injectable_id(messages, "q")
            return LLMResponse("sqli", [ToolCall("c1", "run_sqli", {"injectable_id": iid})], "tool_use")
        if step == 2:
            return LLMResponse("headers", [ToolCall("c2", "run_headers", {})], "tool_use")
        if step == 3:
            return LLMResponse("report", [ToolCall("c3", "report",
                               {"executive_summary": "Confirmed SQL injection on the q parameter."})], "tool_use")
        return LLMResponse("done", [], "end")
    return responder


async def test_agent_runs_full_engagement(vulnlab_url, tmp_path):
    out = str(tmp_path / "ai.json")
    hive = Hive(MockLLMClient(_responder()), budget=Budget(max_steps=10))
    agent = Agent(vulnlab_url, hive, output=out, html=False)
    result = await agent.run()

    assert result["stop"] == "report"
    report = json.loads((tmp_path / "ai.json").read_text())
    assert report["tool"]["name"] == "Fissure AI"
    assert report["executive_summary"].startswith("Confirmed SQL injection")
    sqli = report["modules"].get("sqli", {})
    assert any("SQL injection" in f["title"] for f in sqli.get("findings", []))
    # headers module (A05) ran too
    assert "headers" in report["modules"]


async def test_agent_auto_finalizes_if_model_stalls(vulnlab_url, tmp_path):
    # Model crawls then immediately ends without calling report -> agent must still write one.
    def responder(step, messages):
        if step == 0:
            return LLMResponse("recon", [ToolCall("c0", "crawl", {"max_depth": 0})], "tool_use")
        return LLMResponse("I think I'm done.", [], "end")
    hive = Hive(MockLLMClient(responder), budget=Budget(max_steps=10))
    result = await Agent(vulnlab_url, hive, output=str(tmp_path / "a.json"), html=False).run()
    assert result["outputs"] and (tmp_path / "a.json").exists()


# ---- guardrails (no network) ----

def _gate(approval=None):
    return Gate(normalize_target("http://localhost:8080/app/"), approval_cb=approval)


def test_gate_blocks_out_of_scope_host():
    d = _gate().check_request("GET", "http://evil.example/collect")
    assert not d.allowed and "scope" in d.reason


def test_gate_blocks_denylisted_payload():
    d = _gate().check_request("GET", "http://localhost:8080/app/x", params={"q": "1; DROP TABLE users"})
    assert not d.allowed and "denylist" in d.reason


def test_gate_requires_approval_for_post():
    assert not _gate(approval=None).check_request("POST", "http://localhost:8080/app/save").allowed
    assert _gate(approval=lambda req: True).check_request("POST", "http://localhost:8080/app/save").allowed
    assert not _gate(approval=lambda req: False).check_request("POST", "http://localhost:8080/app/save").allowed


def test_gate_allows_in_scope_get():
    assert _gate().check_request("GET", "http://localhost:8080/app/search", params={"q": "test"}).allowed


# ---- Gemini format translation (pure, no SDK/key needed) ----

def test_gemini_message_translation():
    messages = [
        {"role": "user", "content": "hi"},
        {"role": "assistant", "content": [{"type": "text", "text": "ok"},
                                          {"type": "tool_use", "id": "c1", "name": "crawl", "input": {"x": 1}}]},
        {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "c1", "content": '{"ok":true}'}]},
    ]
    contents = GeminiClient._to_contents(messages)
    assert contents[0] == {"role": "user", "parts": [{"text": "hi"}]}
    assert contents[1]["role"] == "model"
    assert any("function_call" in p for p in contents[1]["parts"])
    fr = contents[2]["parts"][0]["function_response"]
    assert fr["name"] == "crawl"  # mapped back from the tool_use id
    assert fr["response"]["result"] == '{"ok":true}'


def test_gemini_tools_translation():
    decls = GeminiClient._to_tools([ToolSpec("crawl", "desc", {"type": "object", "properties": {}})])
    assert decls[0]["function_declarations"][0] == {
        "name": "crawl", "description": "desc", "parameters": {"type": "object", "properties": {}}}
