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
