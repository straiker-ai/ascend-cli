"""
dispatch.py — route a leased probe body to the right adapter, with a
conversation/session model that makes multi-turn attacks correct.

Why this layer exists
---------------------
The v2 bridge protocol hands us `payload.body` (the already-rendered request the
assessment wants sent to the target) and expects us to return the target's real
response. Iris puts ONLY the prompt on the wire — there is no conversation id
(see iris `common/models/probe.py`: Probe has `prompt`, not `conversation_id`).
Per-target session/conversation logic that Iris runs server-side via plugins
(`prober/plugins/*_chat.py`) for direct apps therefore has to live HERE for a
bridge/thin app.

Multi-turn correctness model
----------------------------
Each adapter instance can hold target-side session state (e.g. SessionAPIAdapter
mints a conversation id on the first call and reuses it). We keep ONE persistent
adapter instance per conversation and route successive turns to it. Because Iris
gives us no correlation id, the default conversation policy is "sequential": the
app runs at concurrency 1 so only one conversation is ever in flight, and the
persistent instance threads the turns — this is exactly why the legacy Go bridge
used `max_workers: 1` for session/browser targets. Stateless single-turn apps
can safely run concurrently (`max_workers > 1`, a fresh-or-shared instance).

The policy is pluggable: if a target DOES echo a correlation value we can read
off `payload.headers` or the response, set `conversation_key` in config to
demux concurrent conversations instead of forcing sequential.
"""
import asyncio
import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple

from adapters import (  # noqa: F401  (lifted framework, all registered below)
    BotAdapter, DirectAPIAdapter, SessionAPIAdapter, BrowserAdapter,
    AmazonConnectAdapter, SCRT2DirectAdapter, AgentforceAdapter,
    SlackDirectAdapter, VertexAIAdapter, WebSocketAdapter,
    CopilotStudioAdapter, SSEStreamAdapter, SessionPollAdapter,
    SentinelStreamAdapter, BedrockAdapter, CustomModuleAdapter,
)

logger = logging.getLogger("ascendbridge.dispatch")

ADAPTER_REGISTRY: Dict[str, type] = {
    "direct_api": DirectAPIAdapter,
    "session_api": SessionAPIAdapter,
    "browser": BrowserAdapter,
    "amazon_connect": AmazonConnectAdapter,
    "scrt2_direct": SCRT2DirectAdapter,
    "agentforce": AgentforceAdapter,
    "slack_direct": SlackDirectAdapter,
    "vertex_ai": VertexAIAdapter,
    "websocket_direct": WebSocketAdapter,
    "copilot_studio": CopilotStudioAdapter,
    "sse_stream": SSEStreamAdapter,
    "session_poll": SessionPollAdapter,
    "sentinel_stream": SentinelStreamAdapter,
    "bedrock": BedrockAdapter,
    "custom": CustomModuleAdapter,   # a per-app adapter written as code
}

# Adapters that carry per-conversation session state → must run sequentially
# unless the config supplies an explicit conversation_key to demux.
STATEFUL_ADAPTERS = {
    "session_api", "browser", "amazon_connect", "scrt2_direct",
    "agentforce", "slack_direct", "copilot_studio", "websocket_direct", "session_poll", "sentinel_stream", "custom",
    "bedrock",   # agent/agentcore modes thread a runtime session id -> run sequentially
}

# Common field names a rendered probe body uses to carry the prompt text.
_PROMPT_FIELDS = ("prompt", "message", "input", "text", "query", "content", "question")



def merge_auth(config: Dict[str, Any], *, timeout_s: float = 20.0,
               verify_tls: bool = True) -> Dict[str, Any]:
    """Resolve a config's ``auth`` block into headers/cookies/params.

    THIS IS THE FIX for the seam where `adapter validate` authenticated (it called the
    same logic in discovery/validate.py) but `runtime start`/`chat` did not, so relayed
    probes went out unauthenticated. Every path that builds outbound requests calls this,
    so validate and the live relay send identical credentials. Auth material comes from
    env refs via layers.auth; a failure is annotated, not raised, so the adapter surfaces
    it once.
    """
    auth_block = config.get("auth")
    if not auth_block or (isinstance(auth_block, dict) and auth_block.get("type") in (None, "none")):
        return config
    try:
        from layers.auth import AuthProvider  # lazy: only when a config actually needs auth
        provider = AuthProvider(auth_block)
        material = provider.materialize(timeout_s=timeout_s, verify_tls=verify_tls)
        merged = material.merge_into_config(config)
        # The token the provider just obtained, for the lifecycle's JWT-`exp` check. This merged
        # dict lives only inside TargetCaller for the run and is never written to disk; the
        # underscore marks it as runtime state, like `_auth_error` below.
        if provider.token:
            merged["_auth_token"] = provider.token
        return merged
    except Exception as exc:  # noqa: BLE001
        merged = dict(config)
        merged["_auth_error"] = str(exc)
        return merged


class ConfigError(ValueError):
    pass


from configs import config_dir, resolve_config_path  # shared with the CLI


def load_config(name_or_inline: Any) -> Dict[str, Any]:
    """Accept a config reference (name / filename / path) or an inline dict.

    Delegates to the shared resolver so the relay and the CLI resolve identically —
    previously they diverged and `runtime start --config out/bot.json` failed while
    `adapter validate --config out/bot.json` worked."""
    import configs as _configs
    try:
        return _configs.load_config(name_or_inline)
    except (ValueError, FileNotFoundError) as e:
        raise ConfigError(str(e))


def extract_prompt(body: Any, config: Dict[str, Any]) -> str:
    """Pull the prompt text out of a rendered probe body of unknown shape."""
    field = config.get("prompt_field")
    if isinstance(body, str):
        return body
    if isinstance(body, dict):
        if field:
            if field in body:
                return str(body[field])
            raise ConfigError(f"prompt_field '{field}' not in probe body keys={list(body)}")
        for f in _PROMPT_FIELDS:
            if f in body and isinstance(body[f], (str, int, float)):
                return str(body[f])
        # Nested single-string fallback: deepest lone string value.
        found = _deepest_string(body)
        if found is not None:
            return found
    raise ConfigError(f"could not locate prompt in probe body (type={type(body).__name__})")


def _deepest_string(obj: Any) -> Optional[str]:
    if isinstance(obj, str):
        return obj
    if isinstance(obj, dict):
        for v in obj.values():
            r = _deepest_string(v)
            if r is not None:
                return r
    if isinstance(obj, list) and obj:
        return _deepest_string(obj[0])
    return None


def shape_result(adapter_result: Dict[str, Any], config: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
    """Turn an adapter result into (status_code, result_body) for /v2/result.

    The assessment's response_template (commonly {"response": "{{RESPONSE}}"})
    parses our body, so we always surface the text under `response` and mirror
    it under the configured `response_field` if different. On adapter failure we
    still return a body (never drop the probe) with an accurate status_code.
    """
    field = config.get("response_field", "response")
    text = adapter_result.get("response", "") or ""
    ok = adapter_result.get("success", False)
    body: Dict[str, Any] = {"response": text}
    if field != "response":
        body[field] = text
    meta = adapter_result.get("metadata") or {}
    if meta:
        body["_meta"] = meta
    if not ok:
        body["_error"] = adapter_result.get("error", "adapter failure")
        # honour a real upstream status if the adapter reported one
        status = (meta or {}).get("status_code")
        return (int(status) if isinstance(status, int) else 502), body
    return 200, body


class ConversationRouter:
    """Caches persistent adapter instances per conversation key.

    A shared asyncio loop runs adapter coroutines. A per-conversation lock keeps
    a stateful adapter's turns strictly ordered even if the caller is threaded.
    """

    def __init__(self) -> None:
        self._instances: Dict[str, BotAdapter] = {}
        self._locks: Dict[str, threading.Lock] = {}
        self._guard = threading.Lock()
        self._loop = asyncio.new_event_loop()
        self._loop_thread = threading.Thread(target=self._run_loop, daemon=True)
        self._loop_thread.start()

    def _run_loop(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._loop.run_forever()

    def _key(self, adapter_type: str, config_name: str, conv: Optional[str]) -> str:
        return f"{adapter_type}:{config_name}:{conv or 'default'}"

    def _adapter_for(self, adapter_type: str, key: str) -> BotAdapter:
        with self._guard:
            inst = self._instances.get(key)
            if inst is None:
                cls = ADAPTER_REGISTRY[adapter_type]
                inst = cls()
                self._instances[key] = inst
            lock = self._locks.setdefault(key, threading.Lock())
        return inst, lock  # type: ignore[return-value]

    def send(self, adapter_type: str, config: Dict[str, Any], config_name: str,
             prompt: str, conv_key: Optional[str], timeout_s: float) -> Dict[str, Any]:
        if adapter_type not in ADAPTER_REGISTRY:
            return {"response": "", "success": False,
                    "error": f"unknown adapter '{adapter_type}'; "
                             f"known={sorted(ADAPTER_REGISTRY)}", "metadata": {}}
        key = self._key(adapter_type, config_name, conv_key)
        inst, lock = self._adapter_for(adapter_type, key)
        # Serialize turns for one conversation; different conversations proceed in parallel.
        with lock:
            fut = asyncio.run_coroutine_threadsafe(inst.send_prompt(prompt, config), self._loop)
            try:
                return fut.result(timeout=timeout_s)
            except Exception as e:  # includes timeout
                return {"response": "", "success": False,
                        "error": f"{type(e).__name__}: {e}", "metadata": {}}

    def reset(self, adapter_type: Optional[str] = None) -> int:
        """Drop cached instances (force fresh sessions). Returns count dropped."""
        with self._guard:
            keys = [k for k in self._instances
                    if adapter_type is None or k.startswith(f"{adapter_type}:")]
            for k in keys:
                self._instances.pop(k, None)
                self._locks.pop(k, None)
        return len(keys)


def conversation_key(probe_message: Dict[str, Any], config: Dict[str, Any]) -> Optional[str]:
    """Derive a conversation key for demuxing concurrent conversations.

    Default: None (sequential policy — one conversation in flight per app).
    If config sets `conversation_key`, read it from headers (header:<Name>) or
    the rendered body (body:<field>). Lets a target that DOES echo a stable
    correlation value run concurrent conversations.
    """
    spec = config.get("conversation_key")
    if not spec:
        return None
    payload = probe_message.get("payload", {})
    if spec.startswith("header:"):
        return (payload.get("headers") or {}).get(spec.split(":", 1)[1])
    if spec.startswith("body:"):
        body = payload.get("body")
        if isinstance(body, dict):
            return body.get(spec.split(":", 1)[1])
    return None
