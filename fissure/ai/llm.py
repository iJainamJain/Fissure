"""Provider-agnostic LLM client abstraction.

`LLMClient` is the single seam every model plugs into. `AnthropicClient` is the
real brain/worker (needs the `anthropic` SDK + API key). `MockLLMClient` scripts
responses for offline tests so the agent loop, tools, and guardrails can be
verified without any API call.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Protocol, runtime_checkable


@dataclass
class ToolSpec:
    name: str
    description: str
    input_schema: dict[str, Any]

    def to_anthropic(self) -> dict[str, Any]:
        return {"name": self.name, "description": self.description, "input_schema": self.input_schema}


@dataclass
class ToolCall:
    id: str
    name: str
    input: dict[str, Any]


@dataclass
class Usage:
    input_tokens: int = 0
    output_tokens: int = 0

    @property
    def total(self) -> int:
        return self.input_tokens + self.output_tokens


@dataclass
class LLMResponse:
    text: str | None
    tool_calls: list[ToolCall] = field(default_factory=list)
    stop_reason: str = "end"  # "tool_use" | "end" | "max_tokens"
    usage: Usage = field(default_factory=Usage)


@runtime_checkable
class LLMClient(Protocol):
    tier: str  # "brain" | "worker"

    def complete(self, *, system: str, messages: list[dict], tools: list[ToolSpec] | None = None,
                 max_tokens: int = 4096, temperature: float = 0.0) -> LLMResponse: ...

    def compact(self, text: str, hint: str, *, max_out: int = 400) -> str: ...


class AnthropicClient:
    """Real Claude client. Requires `pip install anthropic` and ANTHROPIC_API_KEY."""

    def __init__(self, model: str, *, tier: str = "brain", api_key: str | None = None) -> None:
        self.model = model
        self.tier = tier
        self._api_key = api_key
        self.__client = None

    @property
    def _client(self):
        if self.__client is None:
            try:
                import anthropic
            except ImportError as exc:  # pragma: no cover - env-dependent
                raise RuntimeError("The 'anthropic' package is required: pip install fissure-scan[ai]") from exc
            self.__client = anthropic.Anthropic(api_key=self._api_key)
        return self.__client

    def complete(self, *, system, messages, tools=None, max_tokens=4096, temperature=0.0) -> LLMResponse:
        kwargs: dict[str, Any] = {
            "model": self.model, "system": system, "messages": messages,
            "max_tokens": max_tokens, "temperature": temperature,
        }
        if tools:
            kwargs["tools"] = [t.to_anthropic() for t in tools]
        resp = self._client.messages.create(**kwargs)
        text_parts, calls = [], []
        for block in resp.content:
            if block.type == "text":
                text_parts.append(block.text)
            elif block.type == "tool_use":
                calls.append(ToolCall(id=block.id, name=block.name, input=dict(block.input)))
        stop = {"tool_use": "tool_use", "end_turn": "end", "max_tokens": "max_tokens"}.get(resp.stop_reason, "end")
        usage = Usage(resp.usage.input_tokens, resp.usage.output_tokens)
        return LLMResponse(text="".join(text_parts) or None, tool_calls=calls, stop_reason=stop, usage=usage)

    def compact(self, text: str, hint: str, *, max_out: int = 400) -> str:
        if len(text) <= max_out:
            return text
        resp = self._client.messages.create(
            model=self.model, max_tokens=max_out // 3 + 64,
            system="Summarize the given scanner output to the essential security facts. Be terse.",
            messages=[{"role": "user", "content": f"[{hint}]\n{text[:6000]}"}],
        )
        out = "".join(b.text for b in resp.content if b.type == "text")
        return out[:max_out]


class GeminiClient:
    """Google Gemini client (free-tier friendly). Requires `pip install google-genai`
    and GEMINI_API_KEY. Translates the agent's Anthropic-style tool-use messages
    to Gemini's function-calling format and back.
    """

    def __init__(self, model: str, *, tier: str = "brain", api_key: str | None = None) -> None:
        self.model = model
        self.tier = tier
        self._api_key = api_key
        self.__client = None

    @property
    def _client(self):
        if self.__client is None:
            try:
                from google import genai
            except ImportError as exc:  # pragma: no cover - env-dependent
                raise RuntimeError("The 'google-genai' package is required: pip install google-genai") from exc
            self.__client = genai.Client(api_key=self._api_key)
        return self.__client

    @staticmethod
    def _to_contents(messages: list[dict]) -> list[dict]:
        """Anthropic-style messages -> Gemini `contents`. Maps tool_use ids to
        function names so tool_result turns carry the right function_response name."""
        id_to_name: dict[str, str] = {}
        contents: list[dict] = []
        for m in messages:
            role = "model" if m["role"] == "assistant" else "user"
            parts: list[dict] = []
            content = m["content"]
            if isinstance(content, str):
                parts.append({"text": content})
            else:
                for b in content:
                    t = b.get("type")
                    if t == "text" and b.get("text"):
                        parts.append({"text": b["text"]})
                    elif t == "tool_use":
                        id_to_name[b["id"]] = b["name"]
                        parts.append({"function_call": {"name": b["name"], "args": b.get("input", {})}})
                    elif t == "tool_result":
                        name = id_to_name.get(b.get("tool_use_id"), "tool")
                        parts.append({"function_response": {"name": name,
                                     "response": {"result": b.get("content", "")}}})
            if not parts:
                parts.append({"text": ""})
            contents.append({"role": role, "parts": parts})
        return contents

    @staticmethod
    def _to_tools(tools: list[ToolSpec]) -> list[dict]:
        return [{"function_declarations": [
            {"name": t.name, "description": t.description, "parameters": t.input_schema} for t in tools]}]

    def complete(self, *, system, messages, tools=None, max_tokens=4096, temperature=0.0) -> LLMResponse:
        config: dict[str, Any] = {"system_instruction": system, "temperature": temperature,
                                  "max_output_tokens": max_tokens}
        if tools:
            config["tools"] = self._to_tools(tools)
        resp = self._client.models.generate_content(
            model=self.model, contents=self._to_contents(messages), config=config)

        text_parts, calls = [], []
        cand = resp.candidates[0]
        for i, part in enumerate(cand.content.parts or []):
            fc = getattr(part, "function_call", None)
            if fc:
                calls.append(ToolCall(id=f"call_{i}", name=fc.name, input=dict(fc.args or {})))
            elif getattr(part, "text", None):
                text_parts.append(part.text)
        stop = "tool_use" if calls else ("max_tokens" if "MAX_TOKENS" in str(cand.finish_reason) else "end")
        um = getattr(resp, "usage_metadata", None)
        usage = Usage(getattr(um, "prompt_token_count", 0) or 0, getattr(um, "candidates_token_count", 0) or 0)
        return LLMResponse(text="".join(text_parts) or None, tool_calls=calls, stop_reason=stop, usage=usage)

    def compact(self, text: str, hint: str, *, max_out: int = 400) -> str:
        if len(text) <= max_out:
            return text
        resp = self._client.models.generate_content(
            model=self.model, contents=[{"role": "user", "parts": [{"text": f"[{hint}]\n{text[:6000]}"}]}],
            config={"system_instruction": "Summarize the scanner output to the essential security facts. Be terse.",
                    "max_output_tokens": max_out // 3 + 64})
        out = "".join(p.text for p in (resp.candidates[0].content.parts or []) if getattr(p, "text", None))
        return out[:max_out]


class MockLLMClient:
    """Scripted client for tests. `responder(step, messages) -> LLMResponse`."""

    tier = "brain"

    def __init__(self, responder: Callable[[int, list[dict]], LLMResponse]) -> None:
        self._responder = responder
        self._step = 0

    def complete(self, *, system, messages, tools=None, max_tokens=4096, temperature=0.0) -> LLMResponse:
        resp = self._responder(self._step, messages)
        self._step += 1
        return resp

    def compact(self, text: str, hint: str, *, max_out: int = 400) -> str:
        return text[:max_out]
