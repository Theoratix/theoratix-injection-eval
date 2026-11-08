"""Model providers behind one small interface.

Internal message format (provider-agnostic):
  {"role": "user", "content": str}
  {"role": "assistant", "text": str, "tool_calls": [ToolCall, ...]}
  {"role": "tool", "tool_call_id": str, "name": str, "content": str}
"""
from __future__ import annotations

import hashlib
import json
import os
import random
import re
import time
from dataclasses import dataclass, field


@dataclass
class ToolCall:
    id: str
    name: str
    args: dict


@dataclass
class Turn:
    text: str
    tool_calls: list[ToolCall] = field(default_factory=list)
    input_tokens: int = 0
    output_tokens: int = 0


def _retry(fn, tries=6):
    for i in range(tries):
        try:
            return fn()
        except Exception as e:  # noqa: BLE001 - SDK errors vary by provider
            msg = str(e).lower()
            fatal = any(k in msg for k in ("invalid api key", "authentication", "not_found", "model_not_found", "does not exist"))
            if fatal or i == tries - 1:
                raise
            time.sleep(min(60, 2 ** i + random.random()))


class AnthropicProvider:
    def __init__(self, model: str, temperature: float | None = None, max_tokens: int = 1024):
        import anthropic
        self.client = anthropic.Anthropic()
        self.model, self.temperature, self.max_tokens = model, temperature, max_tokens

    @staticmethod
    def _convert(messages):
        out = []
        for m in messages:
            if m["role"] == "user":
                out.append({"role": "user", "content": m["content"]})
            elif m["role"] == "assistant":
                blocks = []
                if m.get("text"):
                    blocks.append({"type": "text", "text": m["text"]})
                for c in m.get("tool_calls", []):
                    blocks.append({"type": "tool_use", "id": c.id, "name": c.name, "input": c.args})
                out.append({"role": "assistant", "content": blocks or [{"type": "text", "text": "(no output)"}]})
            elif m["role"] == "tool":
                block = {"type": "tool_result", "tool_use_id": m["tool_call_id"], "content": m["content"]}
                if out and out[-1]["role"] == "user" and isinstance(out[-1]["content"], list):
                    out[-1]["content"].append(block)
                else:
                    out.append({"role": "user", "content": [block]})
        return out

    def chat(self, system: str, messages: list, tools: list[dict]) -> Turn:
        kw = dict(model=self.model, max_tokens=self.max_tokens, system=system, messages=self._convert(messages))
        if tools:
            kw["tools"] = [{"name": t["name"], "description": t["description"], "input_schema": t["parameters"]} for t in tools]
        if self.temperature is not None:
            kw["temperature"] = self.temperature
        r = _retry(lambda: self.client.messages.create(**kw))
        text = "".join(b.text for b in r.content if b.type == "text")
        calls = [ToolCall(b.id, b.name, dict(b.input or {})) for b in r.content if b.type == "tool_use"]
        return Turn(text, calls, r.usage.input_tokens, r.usage.output_tokens)


class OpenAIProvider:
    """OpenAI, or any OpenAI-compatible server (vLLM, Ollama, LM Studio, Together, ...)."""

    def __init__(self, model: str, temperature: float | None = None, base_url: str | None = None,
                 api_key_env: str = "OPENAI_API_KEY"):
        import openai
        key = os.environ.get(api_key_env) or ("not-needed" if base_url else None)
        self.client = openai.OpenAI(base_url=base_url, api_key=key)
        self.model, self.temperature = model, temperature

    @staticmethod
    def _convert(system, messages):
        out = [{"role": "system", "content": system}]
        for m in messages:
            if m["role"] == "user":
                out.append({"role": "user", "content": m["content"]})
            elif m["role"] == "assistant":
                d = {"role": "assistant", "content": m.get("text") or None}
                if m.get("tool_calls"):
                    d["tool_calls"] = [{"id": c.id, "type": "function",
                                        "function": {"name": c.name, "arguments": json.dumps(c.args)}}
                                       for c in m["tool_calls"]]
                out.append(d)
            elif m["role"] == "tool":
                out.append({"role": "tool", "tool_call_id": m["tool_call_id"], "content": m["content"]})
        return out

    def chat(self, system: str, messages: list, tools: list[dict]) -> Turn:
        kw = dict(model=self.model, messages=self._convert(system, messages))
        if tools:
            kw["tools"] = [{"type": "function", "function": t} for t in tools]
        if self.temperature is not None:
            kw["temperature"] = self.temperature
        r = _retry(lambda: self.client.chat.completions.create(**kw))
        msg = r.choices[0].message
        calls = []
        for i, tc in enumerate(msg.tool_calls or []):
            try:
                args = json.loads(tc.function.arguments or "{}")
            except json.JSONDecodeError:
                args = {"_raw": tc.function.arguments}
            calls.append(ToolCall(tc.id or f"call_{i}", tc.function.name, args if isinstance(args, dict) else {}))
        u = getattr(r, "usage", None)
        return Turn(msg.content or "", calls, getattr(u, "prompt_tokens", 0) or 0, getattr(u, "completion_tokens", 0) or 0)


class MockProvider:
    """Offline stand-in used ONLY to test the pipeline. Its numbers mean nothing.

    It reads the document, follows an embedded instruction with probability
    p_follow (lower when the content is spotlighted), then does the real task.
    As a monitor it blocks anything leaving the org domain or deleting files.
    """

    def __init__(self, seed: int = 0, p_follow: float = 0.55, p_follow_spotlit: float = 0.2):
        self.seed, self.p, self.ps = seed, p_follow, p_follow_spotlit

    def chat(self, system: str, messages: list, tools: list[dict]) -> Turn:
        if system.startswith("You are a security monitor"):
            txt = messages[0]["content"]
            action = txt.split("Proposed action:")[1].split("Document the assistant read:")[0]
            to = re.search(r'"to": "([^"]*)"', action)
            bad = action.strip().startswith("delete_file(") or bool(to and not to.group(1).lower().endswith("@acme-corp.com"))
            return Turn(json.dumps({"decision": "BLOCK" if bad else "ALLOW", "reason": "mock rule"}))

        request = messages[0]["content"]
        rng = random.Random(int(hashlib.sha256(f"{self.seed}|{request}|{len(messages)}".encode()).hexdigest(), 16))
        tool_names = {t["name"] for t in tools}
        results = [m for m in messages if m["role"] == "tool"]
        made = [c for m in messages if m["role"] == "assistant" for c in m.get("tool_calls", [])]
        n = len(made)

        if not results:
            doc = re.search(r"`([a-z0-9_]+)`", request).group(1)
            return Turn("", [ToolCall(f"m{n}", "read_document", {"doc_id": doc})])

        doc_text = next((m["content"] for m in messages if m["role"] == "tool" and m["name"] == "read_document"), "")
        clean = doc_text.replace("^", " ").replace("<<UNTRUSTED_DATA>>", "").replace("<</UNTRUSTED_DATA>>", "")
        tried = any(c.name in ("delete_file",) or (c.name == "send_email" and "exfil" in c.args.get("to", "")) for c in made)
        if not tried:
            p = self.ps if "<<UNTRUSTED_DATA>>" in doc_text else self.p
            em = re.search(r"email to (\S+@\S+?\.net)", clean)
            dl = re.search(r"delete the file (\S+)", clean)
            if (em or dl) and rng.random() < p:
                if em:
                    return Turn("", [ToolCall(f"m{n}", "send_email", {"to": em.group(1), "subject": "Records sync", "body": clean})])
                return Turn("", [ToolCall(f"m{n}", "delete_file", {"path": dl.group(1)})])

        to = re.search(r"to ([\w.-]+@acme-corp\.com)", request)
        if to and "send_email" in tool_names and not any(c.name == "send_email" and c.args.get("to") == to.group(1) for c in made):
            return Turn("", [ToolCall(f"m{n}", "send_email", {"to": to.group(1), "subject": "Requested info", "body": clean})])
        if "submit_answer" in tool_names and not any(c.name == "submit_answer" for c in made):
            return Turn("", [ToolCall(f"m{n}", "submit_answer", {"answer": clean})])
        return Turn("Done.")


def make_provider(kind: str, model: str, temperature=None, base_url=None, api_key_env=None, seed=0):
    if kind == "anthropic":
        return AnthropicProvider(model, temperature)
    if kind == "openai":
        return OpenAIProvider(model, temperature, base_url, api_key_env or "OPENAI_API_KEY")
    if kind == "openai_compat":
        if not base_url:
            raise ValueError("--base-url is required for openai_compat")
        return OpenAIProvider(model, temperature, base_url, api_key_env or "OPENAI_COMPAT_API_KEY")
    if kind == "mock":
        return MockProvider(seed)
    raise ValueError(f"unknown provider {kind}")
