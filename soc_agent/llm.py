"""Provider layer.

CLAUDE.md section 2 settles the reasoning engine as native tool use: the model
receives the tool schemas and chooses the calls. That architecture is preserved
here. What is NOT fixed is which gateway serves it, because the operator
supplied a Nara Router key rather than an Anthropic key.

So the conversation is held in one normalised form and converted at the edge:
  SOC_API_STYLE=openai     -> POST {BASE_URL}/chat/completions
  SOC_API_STYLE=anthropic  -> POST {BASE_URL}/messages  (Anthropic tool-use shape)

Switching back to Claude is SOC_BASE_URL + SOC_MODEL + SOC_API_STYLE, nothing
else. See Toknow/DECISIONS.md D-002.
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

from . import config, schemas


class LLMError(RuntimeError):
    pass


@dataclass
class ToolCall:
    id: str
    name: str
    args: dict[str, Any]


@dataclass
class LLMResponse:
    text: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    stop_reason: str = ""
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def wants_tools(self) -> bool:
        return bool(self.tool_calls)


# --------------------------------------------------------------------------
# Normalised conversation helpers
# --------------------------------------------------------------------------
def user(text: str) -> dict[str, Any]:
    return {"role": "user", "content": text}


def assistant(text: str, tool_calls: list[ToolCall] | None = None) -> dict[str, Any]:
    return {"role": "assistant", "content": text, "tool_calls": tool_calls or []}


def tool_results(results: list[dict[str, Any]]) -> dict[str, Any]:
    """results: [{"id":..., "name":..., "content": "<json string>"}]"""
    return {"role": "tool_results", "results": results}


# --------------------------------------------------------------------------
# Conversion
# --------------------------------------------------------------------------
def _to_openai(system: str, messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = [{"role": "system", "content": system}]
    for m in messages:
        if m["role"] == "user":
            out.append({"role": "user", "content": m["content"]})
        elif m["role"] == "assistant":
            msg: dict[str, Any] = {"role": "assistant", "content": m.get("content") or ""}
            if m.get("tool_calls"):
                msg["tool_calls"] = [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {"name": tc.name,
                                     "arguments": json.dumps(tc.args)},
                    }
                    for tc in m["tool_calls"]
                ]
            out.append(msg)
        elif m["role"] == "tool_results":
            for r in m["results"]:
                out.append({"role": "tool", "tool_call_id": r["id"],
                            "name": r["name"], "content": r["content"]})
    return out


def _to_anthropic(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for m in messages:
        if m["role"] == "user":
            out.append({"role": "user", "content": m["content"]})
        elif m["role"] == "assistant":
            blocks: list[dict[str, Any]] = []
            if m.get("content"):
                blocks.append({"type": "text", "text": m["content"]})
            for tc in m.get("tool_calls", []):
                blocks.append({"type": "tool_use", "id": tc.id,
                               "name": tc.name, "input": tc.args})
            out.append({"role": "assistant", "content": blocks or [
                {"type": "text", "text": "(no content)"}]})
        elif m["role"] == "tool_results":
            out.append({
                "role": "user",
                "content": [
                    {"type": "tool_result", "tool_use_id": r["id"],
                     "content": r["content"]}
                    for r in m["results"]
                ],
            })
    return out


# --------------------------------------------------------------------------
# Transport
# --------------------------------------------------------------------------
_last_call: float = 0.0


def _pace() -> None:
    """Keep a minimum gap between requests.

    The free tier enforces a per-minute request limit, and an agent loop is
    bursty by nature - a six-scenario run fires dozens of calls back to back.
    Spacing them is cheaper than absorbing 429s.
    """
    global _last_call
    if config.MIN_INTERVAL <= 0:
        return
    gap = time.monotonic() - _last_call
    if gap < config.MIN_INTERVAL:
        time.sleep(config.MIN_INTERVAL - gap)
    _last_call = time.monotonic()


# Retry policy: 429 (rate limited) and 5xx (server-side) only. NEVER a 4xx.
#
# A 400 is by definition a statement that the request itself is unacceptable;
# replaying it unchanged cannot succeed. An earlier version of this file
# special-cased "Could not read the request body." as transient and retried it.
# That was wrong twice over: it burned ~8 minutes of exponential backoff on
# scenario 4 and produced no diagnostic information, and in a project graded on
# failure recovery, a retry loop that cannot succeed IS the failure to recover.
# 408 is excluded too - it is a 4xx, and a server that timed out reading one
# request will not read an identical replay any better.
RETRY_STATUS = (429, 500, 502, 503, 504, 529)


def _post(url: str, headers: dict[str, str], body: dict[str, Any],
          timeout: int = 120) -> dict[str, Any]:
    """POST with backoff on rate limits and transient server errors.

    Retries 429 and 5xx, plus the narrow class of 400s that describe a failure
    to read the request rather than a problem with its contents. A validation
    400 is never retried - replaying it would just fail identically.
    """
    data = json.dumps(body).encode("utf-8")
    last: Exception | None = None

    for attempt in range(config.RETRY_MAX + 1):
        _pace()
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", "replace")
            # On a 4xx the body is the diagnosis - keep all of it, plus the
            # request shape, rather than truncating the one thing that explains
            # why the request was rejected.
            if 400 <= exc.code < 500:
                shape = {
                    "model": body.get("model"),
                    "max_tokens": body.get("max_tokens"),
                    "messages": len(body.get("messages", [])),
                    "tools": len(body.get("tools", [])),
                    "approx_body_bytes": len(data),
                }
                detail = (raw + chr(10) + "  request shape: "
                          + json.dumps(shape))
            else:
                detail = raw[:1200]
            last = LLMError(f"HTTP {exc.code} from {url}: {detail}")
            if exc.code not in RETRY_STATUS:
                raise last from exc
            if attempt == config.RETRY_MAX:
                break
            # Honour Retry-After when the gateway sends one.
            try:
                wait = float(exc.headers.get("Retry-After", "") or 0)
            except (TypeError, ValueError):
                wait = 0.0
            wait = wait or config.RETRY_BASE * (2 ** attempt)
            time.sleep(min(wait, 90.0))
        except urllib.error.URLError as exc:
            last = LLMError(f"Could not reach {url}: {exc.reason}")
            if attempt == config.RETRY_MAX:
                break
            time.sleep(config.RETRY_BASE * (2 ** attempt))

    raise last or LLMError(f"Request to {url} failed with no diagnostic.")


def _parse_openai(payload: dict[str, Any]) -> LLMResponse:
    try:
        choice = payload["choices"][0]
    except (KeyError, IndexError) as exc:
        raise LLMError(f"Unexpected response shape: {json.dumps(payload)[:600]}") from exc
    msg = choice.get("message", {})
    calls: list[ToolCall] = []
    for tc in msg.get("tool_calls") or []:
        fn = tc.get("function", {})
        raw_args = fn.get("arguments") or "{}"
        try:
            args = json.loads(raw_args) if isinstance(raw_args, str) else raw_args
        except json.JSONDecodeError:
            args = {"__unparsed__": raw_args}
        calls.append(ToolCall(id=tc.get("id") or f"call_{len(calls)}",
                              name=fn.get("name", ""), args=args or {}))
    return LLMResponse(text=msg.get("content") or "", tool_calls=calls,
                       stop_reason=choice.get("finish_reason", ""), raw=payload)


def _parse_anthropic(payload: dict[str, Any]) -> LLMResponse:
    if "content" not in payload:
        raise LLMError(f"Unexpected response shape: {json.dumps(payload)[:600]}")
    text_parts, calls = [], []
    for block in payload.get("content", []):
        if block.get("type") == "text":
            text_parts.append(block.get("text", ""))
        elif block.get("type") == "tool_use":
            calls.append(ToolCall(id=block.get("id", ""), name=block.get("name", ""),
                                  args=block.get("input") or {}))
    return LLMResponse(text="\n".join(p for p in text_parts if p),
                       tool_calls=calls,
                       stop_reason=payload.get("stop_reason", ""), raw=payload)


def chat(system: str, messages: list[dict[str, Any]],
         tool_names: list[str] | None = None) -> LLMResponse:
    """One turn. The model sees the tool schemas and chooses what to call."""
    if not config.API_KEY:
        raise LLMError(
            "No API key. Set SOC_API_KEY in .env (see .env.example)."
        )
    base = config.BASE_URL.rstrip("/")

    if config.API_STYLE == "anthropic":
        body = {
            "model": config.MODEL,
            "max_tokens": config.MAX_TOKENS,
            "temperature": config.TEMPERATURE,
            "system": system,
            "messages": _to_anthropic(messages),
            "tools": schemas.anthropic_tools(tool_names),
        }
        headers = {
            "content-type": "application/json",
            "x-api-key": config.API_KEY,
            "anthropic-version": "2023-06-01",
        }
        return _parse_anthropic(_post(f"{base}/messages", headers, body))

    body = {
        "model": config.MODEL,
        "max_tokens": config.MAX_TOKENS,
        "temperature": config.TEMPERATURE,
        "messages": _to_openai(system, messages),
        "tools": schemas.openai_tools(tool_names),
        "tool_choice": "auto",
    }
    headers = {
        "content-type": "application/json",
        "authorization": f"Bearer {config.API_KEY}",
    }
    return _parse_openai(_post(f"{base}/chat/completions", headers, body))
