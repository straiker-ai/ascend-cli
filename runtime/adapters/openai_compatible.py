"""OpenAI-compatible chat completions adapter — one POST per prompt, no browser.

The `/v1/chat/completions` contract is the most widely re-implemented chat API: OpenAI and Azure
OpenAI, and the gateways and servers that speak it (LiteLLM, vLLM, Ollama, many enterprise AI
gateways). A target that exposes it is wired from its URL and a key; no capture is needed.

Request:  POST {endpoint}  {"model": ..., "messages": [{"role": "user", "content": prompt}],
                            "stream": false}
Response: choices[0].message.content — a string, or a list of content parts whose `text` is joined.

Config keys:
  endpoint        - the chat completions URL, or a base URL (``/v1/chat/completions`` is appended
                    when the path does not already end in ``/chat/completions``)
  model           - the model or deployment name. Optional: when absent the adapter asks the
                    server once (GET {base}/v1/models) and uses the first model it lists.
  system_prompt   - optional system message sent before the prompt
  max_tokens      - optional (default 512); temperature - optional
  headers         - extra request headers (non-secret); credentials come from the standard
                    `auth` block (`--bearer` → Authorization: Bearer; Azure: `--api-key api-key:<v>`)
  timeout_ms      - request timeout (optional; otherwise derived from the platform's per-probe window)

Stateless: each prompt is its own conversation, so probes run in parallel.
"""
from __future__ import annotations

import json
import logging
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit, urlunsplit

import requests

from .base import BotAdapter, resolve_timeout_s

logger = logging.getLogger(__name__)
_CHAT_SUFFIX = "/chat/completions"


def chat_url(endpoint: str) -> str:
    """The chat completions URL for a full URL or a base URL (query string preserved)."""
    parts = urlsplit(endpoint.strip())
    path = parts.path.rstrip("/")
    if not path.endswith(_CHAT_SUFFIX):
        path = (path + "/v1" if not path.endswith("/v1") else path) + _CHAT_SUFFIX
    return urlunsplit((parts.scheme, parts.netloc, path, parts.query, ""))


def models_url(endpoint: str) -> str:
    """The models listing beside a chat completions URL (same query string, e.g. api-version)."""
    parts = urlsplit(chat_url(endpoint))
    base = parts.path[: -len(_CHAT_SUFFIX)]
    return urlunsplit((parts.scheme, parts.netloc, base + "/models", parts.query, ""))


def extract_text(body: Any) -> str:
    """The assistant text of a chat completion, whatever shape `content` took."""
    if not isinstance(body, dict):
        return ""
    choices = body.get("choices")
    if not isinstance(choices, list) or not choices:
        return ""
    msg = (choices[0] or {}).get("message") if isinstance(choices[0], dict) else None
    content = (msg or {}).get("content") if isinstance(msg, dict) else None
    if content is None and isinstance(choices[0], dict):
        content = choices[0].get("text")                        # legacy completions shape
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(str(p.get("text") or "") for p in content if isinstance(p, dict))
    return ""


def error_text(resp: Any) -> str:
    """What an error body says, in one line."""
    try:
        body = resp.json()
        err = body.get("error") if isinstance(body, dict) else None
        if isinstance(err, dict):
            return str(err.get("message") or err.get("code") or err)[:300]
        if isinstance(err, str):
            return err[:300]
    except Exception:  # noqa: BLE001
        pass
    return str(getattr(resp, "text", "") or "")[:300]


class OpenAICompatibleAdapter(BotAdapter):
    """Send a prompt as a chat completion and return the assistant's text."""

    def __init__(self) -> None:
        self._discovered_model: Optional[str] = None

    def _headers(self, config: Dict[str, Any]) -> Dict[str, str]:
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        extra = config.get("headers") or {}
        if isinstance(extra, dict):
            headers.update({str(k): str(v) for k, v in extra.items()})
        return headers

    def _model(self, config: Dict[str, Any], headers: Dict[str, str], timeout: float) -> str:
        model = str(config.get("model") or "").strip()
        if model:
            return model
        if self._discovered_model:
            return self._discovered_model
        url = models_url(str(config.get("endpoint") or ""))
        resp = requests.get(url, headers=headers, timeout=min(timeout, 20.0), verify=config.get("verify_tls", True))
        resp.raise_for_status()
        data = resp.json()
        rows: List[Any] = data.get("data") if isinstance(data, dict) else data if isinstance(data, list) else []
        ids = [str(r.get("id")) for r in rows if isinstance(r, dict) and r.get("id")]
        if not ids:
            raise ValueError(f"no model configured and {url} lists none")
        self._discovered_model = ids[0]
        logger.info("openai_compatible: no model configured; using the first listed: %s", ids[0])
        return ids[0]

    async def send_prompt(self, prompt: str, config: Dict[str, Any]) -> Dict[str, Any]:
        start = time.time()
        endpoint = str(config.get("endpoint") or config.get("url") or "").strip()
        if not endpoint:
            return self._fail("No endpoint configured", start)
        url = chat_url(endpoint)
        headers = self._headers(config)
        timeout = resolve_timeout_s(config)
        try:
            model = self._model(config, headers, timeout)
        except requests.RequestException as e:
            return self._fail(f"could not list models to pick one (set `model`): {e}", start,
                              status_code=getattr(getattr(e, "response", None), "status_code", None))
        except ValueError as e:
            return self._fail(str(e), start)
        messages: List[Dict[str, str]] = []
        if config.get("system_prompt"):
            messages.append({"role": "system", "content": str(config["system_prompt"])})
        messages.append({"role": "user", "content": prompt})
        body: Dict[str, Any] = {"model": model, "messages": messages, "stream": False,
                                "max_tokens": int(config.get("max_tokens") or 512)}
        if config.get("temperature") is not None:
            body["temperature"] = float(config["temperature"])
        try:
            logger.info("openai_compatible: POST %s model=%s", url, model)
            resp = requests.post(url, json=body, headers=headers, timeout=timeout, verify=config.get("verify_tls", True))
        except requests.RequestException as e:
            return self._fail(f"HTTP error: {e}", start)
        if resp.status_code >= 400:
            return self._fail(f"HTTP {resp.status_code}: {error_text(resp)}", start,
                              status_code=resp.status_code, raw=str(getattr(resp, "text", ""))[:500])
        try:
            data = resp.json()
        except ValueError:
            return self._fail("expected a JSON chat completion, got non-JSON", start, raw=str(resp.text)[:500])
        text = extract_text(data)
        if not text:
            return self._fail("no assistant text in the completion", start, raw=json.dumps(data)[:500])
        usage = data.get("usage") if isinstance(data, dict) else None
        return self._ok(text, start, adapter="openai_compatible", model=model,
                        finish_reason=((data.get("choices") or [{}])[0] or {}).get("finish_reason") if isinstance(data, dict) else None,
                        usage=usage if isinstance(usage, dict) else None)
