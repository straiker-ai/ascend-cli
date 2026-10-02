"""Recognise the SHAPE of a chat response envelope, and name the likely reply path.

Most chat backends return one of a handful of well-known JSON envelopes — an OpenAI-style
`choices[].message.content`, a transcript `messages[]` with the reply last, a `{recipient_id,
text}` list, a bare `{reply|response|answer|text}` object, a double-encoded `{data: "<json>"}`.
Derivation already guesses a response path from the captured reply, and that is the source of
truth; this adds a STRUCTURAL prior on top: "this looks like shape X, whose reply is usually at
path Y". It is advisory only — it never mutates a config. The caller prints it, carries it in the
result for the model to reason with, and offers it as a patch suggestion when derivation found no
path at all. Recognising structure, not branding a vendor, keeps it honest and keeps it useful on
targets no preset covers.

`recognize(ev)` reads the captured chat response and returns
``{framework, response_path, confidence, signals}`` or ``{framework: None}`` when nothing matches.
Read-only, never raises.
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional

_ASSISTANT_ROLES = {"assistant", "bot", "ai", "model", "agent"}
_REPLY_KEYS = ("reply", "response", "answer", "text", "content", "message", "output", "completion")


def _resp_json(ev: Dict[str, Any], prompt: Optional[str]) -> Optional[Any]:
    prompt = (prompt or "").strip()
    last = None
    for p in ev.get("pairs") or []:
        req = p.get("request") or {}
        resp = p.get("response") or {}
        body = resp.get("json")
        if body is None:
            raw = resp.get("raw_body") or resp.get("body")
            if isinstance(raw, (dict, list)):
                body = raw
            elif isinstance(raw, str) and raw.strip().startswith(("{", "[")):
                try:
                    body = json.loads(raw)
                except ValueError:
                    body = None
        if body is None:
            continue
        rb = req.get("raw_body") or req.get("body") or ""
        if prompt and prompt[:60] in (rb if isinstance(rb, str) else str(rb)):
            return body
        last = body
    return last


def _has_path(obj: Any, path: str) -> bool:
    cur = obj
    for seg in path.replace("[]", ".*").split("."):
        if seg in ("", "*"):
            if not isinstance(cur, list) or not cur:
                return False
            cur = cur[-1]
            continue
        if isinstance(cur, dict) and seg in cur:
            cur = cur[seg]
        elif isinstance(cur, list) and seg.lstrip("-").isdigit():
            try:
                cur = cur[int(seg)]
            except IndexError:
                return False
        else:
            return False
    return isinstance(cur, str)


def recognize(ev: Dict[str, Any]) -> Dict[str, Any]:
    """Name the response envelope shape and the reply path it implies. Advisory; never raises."""
    try:
        body = _resp_json(ev, ev.get("prompt_sent"))
    except Exception:  # noqa: BLE001
        body = None
    if body is None:
        return {"framework": None}

    # OpenAI / Azure OpenAI / many gateways: choices[].message.content
    if isinstance(body, dict) and isinstance(body.get("choices"), list) and body["choices"]:
        ch = body["choices"][0]
        if isinstance(ch, dict) and isinstance(ch.get("message"), dict):
            return {"framework": "openai-style chat completion", "response_path": "choices.0.message.content",
                    "confidence": 0.9, "signals": ["choices[].message"]}
        if isinstance(ch, dict) and "text" in ch:
            return {"framework": "openai-style completion", "response_path": "choices.0.text",
                    "confidence": 0.85, "signals": ["choices[].text"]}

    # Anthropic Messages: content[].text (a list of typed blocks)
    if isinstance(body, dict) and isinstance(body.get("content"), list) and body["content"] \
            and isinstance(body["content"][0], dict) and "text" in body["content"][0]:
        return {"framework": "anthropic-style messages", "response_path": "content.*.text",
                "confidence": 0.85, "signals": ["content[].text"]}

    # Rasa / webhook bots: a list of {recipient_id?, text}
    if isinstance(body, list) and body and isinstance(body[0], dict) and "text" in body[0]:
        return {"framework": "rasa/webhook message list", "response_path": "*.text",
                "confidence": 0.8, "signals": ["[].text"]}

    # Transcript envelope: messages[] with the assistant turn last (gateways, GraphQL DTOs)
    if isinstance(body, dict):
        for key in ("messages", "conversation", "history", "turns"):
            arr = body.get(key)
            if isinstance(arr, list) and arr and isinstance(arr[-1], dict):
                last = arr[-1]
                role = str(last.get("role") or last.get("sender") or last.get("from") or "").lower()
                txt_key = next((k for k in ("content", "text", "message", "value") if isinstance(last.get(k), str)), None)
                if txt_key and (role in _ASSISTANT_ROLES or role == ""):
                    return {"framework": f"transcript envelope ({key}[], reply last)",
                            "response_path": f"{key}.-1.{txt_key}", "confidence": 0.75,
                            "signals": [f"{key}[] with a role"]}

    # Double-encoded: {data: "<json string>"} — decode and recurse one level for the note
    if isinstance(body, dict) and isinstance(body.get("data"), str) and body["data"].strip().startswith(("{", "[")):
        return {"framework": "double-encoded envelope (data holds JSON as a string)",
                "response_path": "data~json", "confidence": 0.6, "signals": ["data: <json string>"]}

    # Flat reply object: the single obvious reply key
    if isinstance(body, dict):
        for key in _REPLY_KEYS:
            if isinstance(body.get(key), str) and body[key].strip():
                return {"framework": "flat reply object", "response_path": key,
                        "confidence": 0.6, "signals": [f"{{{key}: ...}}"]}
        # nested one level: {result:{reply:...}} / {data:{answer:...}}
        for k, v in body.items():
            if isinstance(v, dict):
                for key in _REPLY_KEYS:
                    if isinstance(v.get(key), str) and v[key].strip():
                        return {"framework": "nested reply object", "response_path": f"{k}.{key}",
                                "confidence": 0.5, "signals": [f"{{{k}: {{{key}: ...}}}}"]}

    return {"framework": None}
