# BugBîner AI — Unified AI Provider Layer
# Author: Joudi Janble
#
# One interface for every supported AI backend:
#   • ollama     — local models via the native Ollama API (qwen2.5:7b, qwen3.5:9b, ...)
#   • openai     — ANY OpenAI-compatible API (OpenAI, OpenRouter, Groq, DeepSeek,
#                  Together, Mistral, xAI, LM Studio, vLLM, LocalAI, ...)
#   • anthropic  — Claude (vision + tool use)
#   • gemini     — Google Gemini (vision + tool use)
#   • zai        — Z.AI / GLM models via their OpenAI-compatible API (vision via glm-5.3-flash)
#
# Nothing is downloaded or requested at server startup. A model is only used when
# the user explicitly asks for a chat/scan, and local models are pulled only from
# the settings screen.

from __future__ import annotations

import base64
import json
import logging
import urllib.request
import urllib.error

import aiohttp

try:
    from config import load_config
except Exception:  # pragma: no cover - allows importing this module standalone
    def load_config():
        return {}


PROVIDERS = ("ollama", "openai", "anthropic", "gemini", "zai")

PROVIDER_LABELS = {
    "ollama": "Ollama (Local)",
    "openai": "OpenAI-compatible API",
    "anthropic": "Anthropic Claude",
    "gemini": "Google Gemini",
    "zai": "Z.AI (GLM)",
}

DEFAULT_BASE = {
    "ollama": "http://localhost:11434",
    "openai": "https://api.openai.com/v1",
    "anthropic": "https://api.anthropic.com",
    "gemini": "https://generativelanguage.googleapis.com/v1beta",
    # Z.AI / GLM — OpenAI-compatible. Coding-Plan keys use
    # https://api.z.ai/api/coding/paas/v4 instead.
    "zai": "https://api.z.ai/api/paas/v4",
}

DEFAULT_MODEL = {
    "ollama": "qwen2.5:7b",
    "openai": "gpt-4o-mini",
    "anthropic": "claude-3-5-sonnet-latest",
    "gemini": "gemini-2.0-flash",
    "zai": "glm-5.3",
}

# Providers whose default model cannot read images get a separate vision default.
DEFAULT_VISION = {
    "zai": "glm-5.3-flash",
}

# Known vision-capable model name fragments (used only for Ollama auto-detection
# and for a friendly warning on the other providers).
VISION_NAME_PATS = ("vl", "vision", "llava", "bakllava", "moondream",
                    "minicpm-v", "llama3.2-vision", "qwen2.5vl", "qwen2-vl",
                    "qwen3.5", "gemma3", "gemma4")


class ProviderError(RuntimeError):
    pass


# ─────────────────────────────────────────────────────────────────────────────
#  Config resolution
# ─────────────────────────────────────────────────────────────────────────────
def _as_float(v, default):
    try:
        return float(v)
    except Exception:
        return default


def _as_int(v, default):
    try:
        return int(v)
    except Exception:
        return default


def _as_bool(v, default=False):
    if isinstance(v, bool):
        return v
    if v is None:
        return default
    return str(v).strip().lower() in ("1", "true", "yes", "on", "enabled")


def resolve(cfg: dict | None = None) -> dict:
    """Merge the stored config into one effective provider description."""
    cfg = dict(cfg or load_config() or {})
    provider = str(cfg.get("ai_provider") or "ollama").strip().lower()
    if provider not in PROVIDERS:
        provider = "ollama"

    base = str(cfg.get("ai_base_url") or "").strip().rstrip("/")
    if provider == "ollama":
        base = base or str(cfg.get("ollama_base") or DEFAULT_BASE["ollama"]).rstrip("/")
        model = str(cfg.get("ai_model") or cfg.get("ollama_model") or DEFAULT_MODEL["ollama"]).strip()
    else:
        base = base or DEFAULT_BASE[provider]
        model = str(cfg.get("ai_model") or "").strip() or DEFAULT_MODEL[provider]

    chat_model = str(cfg.get("chat_model") or "").strip() or model
    # A cloud provider must never inherit the local Ollama model as its chat model
    # (e.g. after switching providers in settings).
    _ollama_model = str(cfg.get("ollama_model") or "").strip()
    if provider != "ollama" and _ollama_model and chat_model == _ollama_model and model != chat_model:
        chat_model = model
    vision_model = str(cfg.get("vision_model") or "").strip()
    if not vision_model:
        vision_model = DEFAULT_VISION.get(provider, model)

    # Small local model used for instant answers to normal questions. Only applies
    # to Ollama (cloud models ignore it); empty = same as the chat model.
    fast_model = str(cfg.get("fast_model") or "").strip() if provider == "ollama" else ""

    return {
        "provider": provider,
        "label": PROVIDER_LABELS.get(provider, provider),
        "base_url": base,
        "api_key": str(cfg.get("ai_api_key") or "").strip(),
        "model": model,
        "chat_model": chat_model,
        "fast_model": fast_model,
        "vision_model": vision_model,
        "temperature": _as_float(cfg.get("ai_temperature", 0.15), 0.15),
        "num_ctx": _as_int(cfg.get("ai_num_ctx", 4096), 4096),
        "max_tokens": _as_int(cfg.get("ai_max_tokens", 3000), 3000),
        "thinking": _as_bool(cfg.get("ai_thinking"), False),
        "headers": cfg.get("ai_headers") if isinstance(cfg.get("ai_headers"), dict) else {},
    }


def public_config(cfg: dict | None = None) -> dict:
    """Config for the UI — the API key is only reported as present/absent."""
    cfg = dict(cfg or load_config() or {})
    eff = resolve(cfg)
    key = eff["api_key"]
    return {
        "ai_provider": eff["provider"],
        "ai_base_url": cfg.get("ai_base_url") or "",
        "ai_model": cfg.get("ai_model") or "",
        "chat_model": cfg.get("chat_model") or "",
        "fast_model": eff.get("fast_model") or "",
        "vision_model": cfg.get("vision_model") or "",
        "ai_temperature": eff["temperature"],
        "ai_num_ctx": eff["num_ctx"],
        "ai_max_tokens": eff["max_tokens"],
        "ai_has_key": bool(key),
        "ai_key_hint": (key[:4] + "…" + key[-4:]) if len(key) > 10 else ("••••" if key else ""),
        "ollama_base": cfg.get("ollama_base") or DEFAULT_BASE["ollama"],
        "ollama_model": cfg.get("ollama_model") or DEFAULT_MODEL["ollama"],
        "effective": {
            "provider": eff["provider"],
            "provider_label": eff["label"],
            "base_url": eff["base_url"],
            "model": eff["model"],
            "chat_model": eff["chat_model"],
            "fast_model": eff["fast_model"],
            "vision_model": eff["vision_model"],
        },
        "providers": [{"id": p, "label": PROVIDER_LABELS[p], "default_base": DEFAULT_BASE[p],
                       "default_model": DEFAULT_MODEL[p]} for p in PROVIDERS],
    }


# ─────────────────────────────────────────────────────────────────────────────
#  Small helpers
# ─────────────────────────────────────────────────────────────────────────────
def _guess_media(b64: str) -> str:
    try:
        raw = base64.b64decode(b64[:64] + "=" * (-len(b64[:64]) % 4))
        if raw.startswith(b"\x89PNG\r\n\x1a\n"):
            return "image/png"
        if raw.startswith(b"\xff\xd8\xff"):
            return "image/jpeg"
        if raw.startswith(b"GIF8"):
            return "image/gif"
        if raw[:4] == b"RIFF" and raw[8:12] == b"WEBP":
            return "image/webp"
    except Exception:
        pass
    return "image/jpeg"


def _norm_images(images) -> list[dict]:
    out = []
    for img in images or []:
        if not img:
            continue
        if isinstance(img, str):
            out.append({"base64": img, "mediaType": _guess_media(img)})
        elif isinstance(img, dict):
            b = img.get("base64") or img.get("data") or ""
            if b:
                out.append({"base64": b, "mediaType": img.get("mediaType") or _guess_media(b)})
    return out


def _headers(eff: dict) -> dict:
    h = {"Content-Type": "application/json", **(eff.get("headers") or {})}
    key = eff.get("api_key") or ""
    p = eff["provider"]
    if p in ("openai", "zai") and key:
        if "azure" in (eff.get("base_url") or "").lower():
            h["api-key"] = key
        else:
            h["Authorization"] = f"Bearer {key}"
    elif p == "anthropic":
        if key:
            h["x-api-key"] = key
        h["anthropic-version"] = "2023-06-01"
    elif p == "gemini" and key:
        h["x-goog-api-key"] = key
    return h


def _join(base: str, path: str) -> str:
    base = (base or "").rstrip("/")
    if not path:
        return base
    return base + ("/" if not path.startswith("/") else "") + path.lstrip("/") if not base.endswith(path) else base


def _endpoint(eff: dict) -> str:
    base = eff["base_url"].rstrip("/")
    p = eff["provider"]
    if p == "ollama":
        return base + "/api/chat"
    if p in ("openai", "zai"):
        if base.endswith("/chat/completions"):
            return base
        return base + "/chat/completions"
    if p == "anthropic":
        if base.endswith("/messages"):
            return base
        if base.endswith("/v1"):
            return base + "/messages"
        return base + "/v1/messages"
    if p == "gemini":
        model = eff.get("model") or DEFAULT_MODEL["gemini"]
        if base.endswith(":generateContent") or base.endswith(":streamGenerateContent"):
            return base
        return base + f"/models/{model}:generateContent"
    return base


def _models_endpoint(eff: dict) -> str:
    base = eff["base_url"].rstrip("/")
    p = eff["provider"]
    if p == "ollama":
        return base + "/api/tags"
    if p in ("openai", "zai"):
        return base + "/models"
    if p == "anthropic":
        if base.endswith("/v1"):
            return base + "/models"
        return base + "/v1/models"
    if p == "gemini":
        return base + "/models"
    return base + "/models"


# ─────────────────────────────────────────────────────────────────────────────
#  Message / tool conversion
# ─────────────────────────────────────────────────────────────────────────────
def _tool_args(v):
    if isinstance(v, dict):
        return v
    if isinstance(v, str) and v.strip():
        try:
            return json.loads(v)
        except Exception:
            return {"input": v}
    return {}


def _pop_pending(pending: list, name: str) -> str:
    for i, (n, cid) in enumerate(pending):
        if n == name:
            return pending.pop(i)[1]
    return pending.pop(0)[1] if pending else "call_0"


def _assign_tool_ids(messages: list) -> list:
    """Return a shallow copy where every tool_call has an id and tool messages get tool_call_id."""
    out = []
    pending = []
    for m in messages:
        m = dict(m)
        role = m.get("role")
        if role == "assistant" and m.get("tool_calls"):
            tcs = []
            for i, tc in enumerate(m["tool_calls"]):
                tc = dict(tc)
                fn = dict(tc.get("function") or {})
                cid = tc.get("id") or f"call_{len(out)}_{i}"
                tc["id"] = cid
                fn["arguments"] = _tool_args(fn.get("arguments"))
                tc["function"] = fn
                tcs.append(tc)
                pending.append((fn.get("name", ""), cid))
            m["tool_calls"] = tcs
        elif role == "tool":
            cid = m.get("tool_call_id") or _pop_pending(pending, m.get("tool_name", ""))
            m["tool_call_id"] = cid
        out.append(m)
    return out


def _openai_messages(messages: list) -> list:
    out = []
    for m in _assign_tool_ids(messages):
        role = m.get("role")
        content = m.get("content")
        if role == "assistant":
            o = {"role": "assistant", "content": content or None}
            if m.get("tool_calls"):
                o["tool_calls"] = [{
                    "id": tc["id"], "type": "function",
                    "function": {"name": tc["function"]["name"],
                                 "arguments": json.dumps(tc["function"].get("arguments") or {}, ensure_ascii=False)},
                } for tc in m["tool_calls"]]
            if o["content"] is None and not o.get("tool_calls"):
                o["content"] = ""
            out.append(o)
        elif role == "tool":
            out.append({"role": "tool", "tool_call_id": m.get("tool_call_id") or "call_0",
                        "content": str(content or "")})
        else:
            imgs = _norm_images(m.get("images"))
            if imgs and role == "user":
                parts = []
                if content:
                    parts.append({"type": "text", "text": str(content)})
                for im in imgs:
                    parts.append({"type": "image_url",
                                  "image_url": {"url": f"data:{im['mediaType']};base64,{im['base64']}"}})
                out.append({"role": "user", "content": parts})
            else:
                out.append({"role": role or "user", "content": content if content is not None else ""})
    return out


def _anthropic_payload(messages: list, tools=None, system_extra: str = "") -> tuple[str, list, list | None]:
    system_parts = []
    out = []
    for m in _assign_tool_ids(messages):
        role = m.get("role")
        content = m.get("content") or ""
        if role == "system":
            if content:
                system_parts.append(str(content))
            continue
        if role == "tool":
            cid = m.get("tool_call_id") or "call_0"
            out.append({"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": cid,
                 "content": str(content)[:12000] or "(empty)"}]})
            continue
        if role == "assistant":
            blocks = []
            if content:
                blocks.append({"type": "text", "text": str(content)})
            for tc in (m.get("tool_calls") or []):
                blocks.append({"type": "tool_use", "id": tc["id"],
                               "name": tc["function"]["name"],
                               "input": tc["function"].get("arguments") or {}})
            if blocks:
                out.append({"role": "assistant", "content": blocks})
            continue
        blocks = []
        for im in _norm_images(m.get("images")):
            blocks.append({"type": "image", "source": {
                "type": "base64", "media_type": im["mediaType"], "data": im["base64"]}})
        if content:
            blocks.append({"type": "text", "text": str(content)})
        out.append({"role": "user", "content": blocks or [{"type": "text", "text": ""}]})

    atools = None
    if tools:
        atools = []
        for t in tools:
            fn = t.get("function") if isinstance(t, dict) and "function" in t else t
            atools.append({
                "name": fn.get("name", ""),
                "description": fn.get("description", ""),
                "input_schema": fn.get("parameters") or {"type": "object", "properties": {}},
            })
    if system_extra:
        system_parts.append(system_extra)
    return "\n\n".join(system_parts), out, atools


def _gemini_payload(messages: list, tools=None, system_extra: str = "") -> tuple[dict, list, list | None]:
    system_parts = []
    contents = []
    for m in _assign_tool_ids(messages):
        role = m.get("role")
        content = m.get("content") or ""
        if role == "system":
            if content:
                system_parts.append(str(content))
            continue
        if role == "tool":
            name = m.get("tool_name") or (m.get("tool_calls") or [{}])[0].get("function", {}).get("name", "tool")
            contents.append({"role": "user", "parts": [{
                "functionResponse": {"name": name,
                                     "response": {"result": str(content)[:12000] or "(empty)"}}}]})
            continue
        if role == "assistant":
            parts = []
            if content:
                parts.append({"text": str(content)})
            for tc in (m.get("tool_calls") or []):
                parts.append({"functionCall": {
                    "name": tc["function"]["name"],
                    "args": tc["function"].get("arguments") or {}}})
            if parts:
                contents.append({"role": "model", "parts": parts})
            continue
        parts = []
        if content:
            parts.append({"text": str(content)})
        for im in _norm_images(m.get("images")):
            parts.append({"inlineData": {"mimeType": im["mediaType"], "data": im["base64"]}})
        contents.append({"role": "user", "parts": parts or [{"text": ""}]})

    payload = {"contents": contents}
    if system_parts or system_extra:
        payload["systemInstruction"] = {"parts": [{"text": "\n\n".join(system_parts + ([system_extra] if system_extra else []))}]}
    gtools = None
    if tools:
        decls = []
        for t in tools:
            fn = t.get("function") if isinstance(t, dict) and "function" in t else t
            decls.append({"name": fn.get("name", ""),
                          "description": fn.get("description", ""),
                          "parameters": fn.get("parameters") or {"type": "object", "properties": {}}})
        gtools = [{"functionDeclarations": decls}]
    return payload, contents, gtools


# ─────────────────────────────────────────────────────────────────────────────
#  Response parsing
# ─────────────────────────────────────────────────────────────────────────────
def _parse_ollama(data: dict) -> dict:
    msg = data.get("message") or {}
    tcs = []
    for i, tc in enumerate(msg.get("tool_calls") or []):
        fn = tc.get("function") or {}
        tcs.append({"id": tc.get("id") or f"call_{i}",
                    "function": {"name": fn.get("name", ""),
                                 "arguments": _tool_args(fn.get("arguments"))}})
    return {"role": "assistant", "content": msg.get("content") or "", "tool_calls": tcs}


def _parse_openai(data: dict) -> dict:
    ch = (data.get("choices") or [{}])[0]
    msg = ch.get("message") or {}
    tcs = []
    for i, tc in enumerate(msg.get("tool_calls") or []):
        fn = tc.get("function") or {}
        tcs.append({"id": tc.get("id") or f"call_{i}",
                    "function": {"name": fn.get("name", ""),
                                 "arguments": _tool_args(fn.get("arguments"))}})
    return {"role": "assistant", "content": msg.get("content") or "", "tool_calls": tcs}


def _parse_anthropic(data: dict) -> dict:
    text = ""
    tcs = []
    for block in data.get("content") or []:
        t = block.get("type")
        if t == "text":
            text += block.get("text") or ""
        elif t == "tool_use":
            tcs.append({"id": block.get("id") or f"call_{len(tcs)}",
                        "function": {"name": block.get("name", ""),
                                     "arguments": block.get("input") or {}}})
    return {"role": "assistant", "content": text, "tool_calls": tcs}


def _parse_gemini(data: dict) -> dict:
    cand = (data.get("candidates") or [{}])[0]
    parts = (cand.get("content") or {}).get("parts") or []
    text = ""
    tcs = []
    for part in parts:
        if "text" in part:
            text += part.get("text") or ""
        if "functionCall" in part:
            fc = part.get("functionCall") or {}
            tcs.append({"id": f"call_{len(tcs)}",
                        "function": {"name": fc.get("name", ""),
                                     "arguments": fc.get("args") or {}}})
    return {"role": "assistant", "content": text, "tool_calls": tcs}


def _parse_response(eff: dict, data: dict) -> dict:
    p = eff["provider"]
    if p == "ollama":
        return _parse_ollama(data)
    if p in ("openai", "zai"):
        return _parse_openai(data)
    if p == "anthropic":
        return _parse_anthropic(data)
    if p == "gemini":
        return _parse_gemini(data)
    return {"role": "assistant", "content": "", "tool_calls": []}


def _build_payload(eff: dict, messages: list, tools=None, model=None, max_tokens=None,
                   temperature=None, stream=False, system_extra: str = "") -> dict:
    p = eff["provider"]
    model = model or eff["model"]
    max_tokens = int(max_tokens or eff["max_tokens"])
    temperature = eff["temperature"] if temperature is None else temperature

    if p == "ollama":
        msgs = []
        for m in _assign_tool_ids(messages):
            mm = {"role": m.get("role"), "content": m.get("content") or ""}
            if m.get("images"):
                mm["images"] = [im["base64"] for im in _norm_images(m["images"])]
            if m.get("tool_calls"):
                mm["tool_calls"] = [{"function": {"name": tc["function"]["name"],
                                                  "arguments": tc["function"].get("arguments") or {}}}
                                    for tc in m["tool_calls"]]
            if m.get("role") == "tool":
                mm["tool_name"] = m.get("tool_name") or ""
            msgs.append(mm)
        payload = {"model": model, "messages": msgs, "stream": bool(stream),
                   "think": False, "keep_alive": "2h",
                   "options": {"num_ctx": eff["num_ctx"],
                               "temperature": temperature, "num_predict": max_tokens}}
        if system_extra:
            payload["messages"].insert(0, {"role": "system", "content": system_extra})
        if tools:
            payload["tools"] = tools
        return payload

    if p in ("openai", "zai"):
        payload = {"model": model, "messages": _openai_messages(messages),
                   "temperature": temperature, "max_tokens": max_tokens,
                   "stream": bool(stream)}
        # Z.AI: skip the reasoning pass for fast, predictable replies. GLM-5.3-Flash
        # only supports thinking=enabled, so leave that family alone.
        if p == "zai" and not eff.get("thinking") and "5.3-flash" not in model.lower():
            payload["thinking"] = {"type": "disabled"}
        if system_extra:
            payload["messages"].insert(0, {"role": "system", "content": system_extra})
        if tools:
            payload["tools"] = tools
        return payload

    if p == "anthropic":
        system, msgs, atools = _anthropic_payload(messages, tools, system_extra)
        payload = {"model": model, "messages": msgs, "max_tokens": max_tokens,
                   "temperature": temperature}
        if system:
            payload["system"] = system
        if atools:
            payload["tools"] = atools
        return payload

    if p == "gemini":
        payload, _contents, gtools = _gemini_payload(messages, tools, system_extra)
        payload["generationConfig"] = {"temperature": temperature, "maxOutputTokens": max_tokens}
        if gtools:
            payload["tools"] = gtools
        return payload

    raise ProviderError(f"Unsupported provider: {p}")


# ─────────────────────────────────────────────────────────────────────────────
#  Non-streaming call
# ─────────────────────────────────────────────────────────────────────────────
async def chat(cfg: dict | None = None, messages: list = None, tools=None, model: str | None = None,
               max_tokens: int | None = None, temperature: float | None = None,
               images=None, system_extra: str = "", timeout: int = 240) -> dict:
    eff = resolve(cfg)
    messages = list(messages or [])
    imgs = _norm_images(images)
    if imgs:
        if messages and messages[-1].get("role") == "user":
            messages[-1] = {**messages[-1], "images": (messages[-1].get("images") or []) + imgs}
        else:
            messages.append({"role": "user", "content": "", "images": imgs})

    payload = _build_payload(eff, messages, tools, model, max_tokens, temperature,
                             stream=False, system_extra=system_extra)
    url = _endpoint(eff) if eff["provider"] != "gemini" else _endpoint({**eff, "model": model or eff["model"]})
    try:
        async with aiohttp.ClientSession() as s:
            async with s.post(url, headers=_headers(eff), json=payload,
                              timeout=aiohttp.ClientTimeout(total=timeout)) as r:
                raw = await r.read()
                txt = raw.decode("utf-8", errors="replace")
                if r.status >= 400:
                    raise ProviderError(_http_error(eff, r.status, txt))
                try:
                    data = json.loads(txt)
                except Exception:
                    raise ProviderError(f"Invalid JSON from {eff['label']}: {txt[:300]}")
                return _parse_response(eff, data)
    except ProviderError:
        raise
    except aiohttp.ClientConnectorError as e:
        raise ProviderError(_connection_hint(eff, e))
    except Exception as e:
        raise ProviderError(f"{eff['label']} request failed: {e}")


def _http_error(eff: dict, status: int, txt: str) -> str:
    detail = txt.strip()
    try:
        j = json.loads(txt)
        detail = (j.get("error") or {}).get("message") if isinstance(j.get("error"), dict) else j.get("error") or j.get("message") or detail
    except Exception:
        pass
    detail = str(detail)[:400]
    if status in (401, 403):
        return f"{eff['label']}: authentication failed ({status}). Check the API key. {detail}"
    if status == 404:
        return f"{eff['label']}: endpoint/model not found ({status}). Check base URL and model name. {detail}"
    if status == 429:
        return f"{eff['label']}: rate limited (429). Try again later. {detail}"
    return f"{eff['label']} error {status}: {detail}"


def _connection_hint(eff: dict, err) -> str:
    if eff["provider"] == "ollama":
        return ("Ollama is not reachable at " + eff["base_url"] +
                ". Start it with: ollama serve  — or change the base URL in AI settings.")
    return f"Cannot reach {eff['label']} at {eff['base_url']}: {err}"


# ─────────────────────────────────────────────────────────────────────────────
#  Streaming call (text only — tools are used with the non-streaming call)
# ─────────────────────────────────────────────────────────────────────────────
async def stream_chat(cfg: dict | None = None, messages: list = None, model: str | None = None,
                      max_tokens: int | None = None, temperature: float | None = None,
                      images=None, system_extra: str = "", timeout: int = 300):
    eff = resolve(cfg)
    messages = list(messages or [])
    imgs = _norm_images(images)
    if imgs:
        if messages and messages[-1].get("role") == "user":
            messages[-1] = {**messages[-1], "images": (messages[-1].get("images") or []) + imgs}
        else:
            messages.append({"role": "user", "content": "", "images": imgs})

    p = eff["provider"]
    payload = _build_payload(eff, messages, None, model, max_tokens, temperature,
                             stream=True, system_extra=system_extra)
    url = _endpoint({**eff, "model": model or eff["model"]}) if p == "gemini" else _endpoint(eff)
    if p == "gemini":
        url = url.replace(":generateContent", ":streamGenerateContent") + "?alt=sse"

    try:
        async with aiohttp.ClientSession() as s:
            async with s.post(url, headers=_headers(eff), json=payload,
                              timeout=aiohttp.ClientTimeout(total=timeout)) as r:
                if r.status >= 400:
                    txt = (await r.read()).decode("utf-8", errors="replace")
                    raise ProviderError(_http_error(eff, r.status, txt))
                if p == "ollama":
                    async for raw in r.content:
                        line = raw.decode("utf-8", errors="replace").strip()
                        if not line:
                            continue
                        try:
                            c = json.loads(line)
                        except Exception:
                            continue
                        d = (c.get("message") or {}).get("content") or ""
                        if d:
                            yield d
                        if c.get("done"):
                            return
                else:
                    async for raw in r.content:
                        line = raw.decode("utf-8", errors="replace").strip()
                        if not line or not line.startswith("data:"):
                            continue
                        ds = line[5:].strip()
                        if ds == "[DONE]":
                            return
                        try:
                            c = json.loads(ds)
                        except Exception:
                            continue
                        d = ""
                        if p in ("openai", "zai"):
                            ch = (c.get("choices") or [{}])[0]
                            d = (ch.get("delta") or {}).get("content") or ""
                        elif p == "anthropic":
                            if c.get("type") == "content_block_delta":
                                d = (c.get("delta") or {}).get("text") or ""
                        elif p == "gemini":
                            cand = (c.get("candidates") or [{}])[0]
                            parts = (cand.get("content") or {}).get("parts") or []
                            d = "".join(part.get("text") or "" for part in parts)
                        if d:
                            yield d
    except ProviderError:
        raise
    except aiohttp.ClientConnectorError as e:
        raise ProviderError(_connection_hint(eff, e))
    except Exception as e:
        raise ProviderError(f"{eff['label']} stream failed: {e}")


# ─────────────────────────────────────────────────────────────────────────────
#  Connection test + model listing
# ─────────────────────────────────────────────────────────────────────────────
async def list_models(cfg: dict | None = None) -> list[str]:
    eff = resolve(cfg)
    url = _models_endpoint(eff)
    try:
        async with aiohttp.ClientSession() as s:
            async with s.get(url, headers=_headers(eff),
                             timeout=aiohttp.ClientTimeout(total=20)) as r:
                txt = (await r.read()).decode("utf-8", errors="replace")
                if r.status >= 400:
                    raise ProviderError(_http_error(eff, r.status, txt))
                data = json.loads(txt)
    except ProviderError:
        raise
    except aiohttp.ClientConnectorError as e:
        raise ProviderError(_connection_hint(eff, e))
    except Exception as e:
        raise ProviderError(f"Cannot list models: {e}")

    p = eff["provider"]
    if p == "ollama":
        return sorted({m.get("name", "") for m in (data.get("models") or []) if m.get("name")})
    if p in ("openai", "zai"):
        return sorted({m.get("id", "") for m in (data.get("data") or []) if m.get("id")})
    if p == "anthropic":
        return sorted({m.get("id", "") for m in (data.get("data") or []) if m.get("id")})
    if p == "gemini":
        out = []
        for m in data.get("models") or []:
            name = (m.get("name") or "").replace("models/", "")
            if name:
                out.append(name)
        return sorted(out)
    return []


async def test_connection(cfg: dict | None = None) -> dict:
    """Cheap, non-generating connectivity test. Never pulls/downloads a model."""
    eff = resolve(cfg)
    result = {"ok": False, "provider": eff["provider"], "provider_label": eff["label"],
              "base_url": eff["base_url"], "model": eff["model"],
              "chat_model": eff["chat_model"], "vision_model": eff["vision_model"],
              "models": [], "message": ""}
    try:
        models = await list_models(cfg)
        result["models"] = models
        if eff["provider"] == "ollama":
            wanted = {eff["model"], eff["chat_model"], eff["vision_model"]}
            installed = set(models)
            # Ollama may report "qwen2.5:7b" while the user typed "qwen2.5"
            def _eq(a, b):
                return a == b or a.split(":")[0] == b.split(":")[0]
            missing = [w for w in wanted if w and not any(_eq(w, m) for m in installed)]
            if missing:
                result["message"] = ("Connected to Ollama, but these models are not installed: "
                                     + ", ".join(missing) + ". Download them from AI settings.")
                result["missing"] = missing
            else:
                result["ok"] = True
                result["message"] = f"Connected to Ollama — {len(models)} model(s) installed."
        else:
            result["ok"] = True
            if eff["model"] and models and not any(eff["model"] == m for m in models):
                result["message"] = (f"Connected — API key accepted. '{eff['model']}' was not in the "
                                     f"model list; it may still be valid.")
            else:
                result["message"] = f"Connected to {eff['label']} — {len(models)} model(s) available."
    except ProviderError as e:
        result["message"] = str(e)
    except Exception as e:
        result["message"] = f"Connection test failed: {e}"
    return result


# ─────────────────────────────────────────────────────────────────────────────
#  Ollama model management (pull / delete) — only from settings
# ─────────────────────────────────────────────────────────────────────────────
async def pull_model(base_url: str, model: str):
    """Yield progress dicts from Ollama's /api/pull. Does not raise on network errors."""
    base = (base_url or DEFAULT_BASE["ollama"]).rstrip("/")
    payload = {"model": model, "stream": True}
    try:
        async with aiohttp.ClientSession() as s:
            async with s.post(base + "/api/pull", json=payload,
                              timeout=aiohttp.ClientTimeout(total=3600, sock_read=600)) as r:
                if r.status >= 400:
                    txt = (await r.read()).decode("utf-8", errors="replace")
                    yield {"error": f"Ollama pull error {r.status}: {txt[:300]}"}
                    return
                async for raw in r.content:
                    line = raw.decode("utf-8", errors="replace").strip()
                    if not line:
                        continue
                    try:
                        d = json.loads(line)
                    except Exception:
                        continue
                    if d.get("error"):
                        yield {"error": str(d["error"])}
                        return
                    total = d.get("total") or 0
                    done = d.get("completed") or 0
                    pct = (done / total * 100.0) if total else 0
                    yield {"status": d.get("status") or "", "completed": done,
                           "total": total, "percent": round(pct, 1), "done": bool(d.get("done"))}
    except aiohttp.ClientConnectorError as e:
        yield {"error": _connection_hint({"provider": "ollama", "base_url": base, "label": "Ollama"}, e)}
    except Exception as e:
        yield {"error": f"Ollama pull failed: {e}"}


async def delete_model(base_url: str, model: str) -> dict:
    base = (base_url or DEFAULT_BASE["ollama"]).rstrip("/")
    try:
        async with aiohttp.ClientSession() as s:
            async with s.delete(base + "/api/delete", json={"model": model},
                                timeout=aiohttp.ClientTimeout(total=60)) as r:
                if r.status >= 400:
                    txt = (await r.read()).decode("utf-8", errors="replace")
                    return {"ok": False, "message": f"Delete failed ({r.status}): {txt[:200]}"}
                return {"ok": True, "message": f"Deleted {model}"}
    except Exception as e:
        return {"ok": False, "message": f"Delete failed: {e}"}


# ─────────────────────────────────────────────────────────────────────────────
#  Synchronous helper for thread-pool callers (ai_analyzer)
# ─────────────────────────────────────────────────────────────────────────────
def sync_chat(cfg: dict | None = None, prompt: str = "", system: str = "",
              max_tokens: int = 1500, temperature: float = 0.1, timeout: int = 60) -> str:
    """Blocking completion used by ai_analyzer (runs inside a worker thread)."""
    eff = resolve(cfg)
    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})
    p = eff["provider"]
    payload = _build_payload(eff, messages, None, None, max_tokens, temperature,
                             stream=False)
    url = _endpoint(eff)
    headers = _headers(eff)

    if p == "gemini":
        # urllib cannot easily stream, but the non-stream endpoint works
        url = url.replace(":streamGenerateContent", ":generateContent")

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
        parsed = _parse_response(eff, json.loads(raw))
        return (parsed.get("content") or "").strip()
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read().decode("utf-8", errors="replace")[:300]
        except Exception:
            pass
        logging.warning(f"AI provider HTTP {e.code}: {body}")
        return ""
    except Exception as e:
        logging.warning(f"AI provider sync call failed: {e}")
        return ""
