"""
Direct API adapter — for chatbots with a simple REST endpoint.

Supports configurable endpoint, headers, request body template,
and response extraction via JSONPath-like dot notation.

Works for: OpenAI-compatible APIs, any stateless chat endpoint, custom REST APIs.

Config keys:
  endpoint      - Full URL to POST to
  method        - HTTP method (default: POST)
  headers       - Dict of additional headers (e.g. Authorization)
  body          - Request body template with {{PROMPT}} placeholder
  response_path - Dot-notation path to extract response (e.g. "choices.0.message.content")
  timeout_ms    - Request timeout in milliseconds (default: 60000)
"""

import json
import time
import logging
from typing import Any, Dict

import requests
from urllib.parse import quote

from .base import BotAdapter, utf8_text, tls_kwargs, tls_min_adapter
from .websocket_direct import _json_escape

logger = logging.getLogger(__name__)


class DirectAPIAdapter(BotAdapter):
    """Send a prompt via direct HTTP POST and extract the response."""

    async def send_prompt(self, prompt: str, config: Dict[str, Any]) -> Dict[str, Any]:
        start = time.time()

        endpoint = config.get("endpoint")
        if not endpoint:
            return self._fail("No endpoint configured", start)

        method = config.get("method", "POST").upper()
        timeout = config.get("timeout_ms", 60000) / 1000

        headers = {"Content-Type": "application/json"}
        headers.update(config.get("headers", {}))

        # Prompts can live in the URL (path/query params), not just the body — substitute
        # (URL-encoded) if the endpoint contains the placeholder.
        if "{{PROMPT}}" in endpoint:
            endpoint = endpoint.replace("{{PROMPT}}", quote(prompt, safe=""))

        # Determine encoding from Content-Type: JSON (default), form-urlencoded, or raw.
        ctype = str(headers.get("Content-Type", "application/json")).lower()
        body_template = config.get("body", {})
        send_kwargs = {}
        try:
            if "application/x-www-form-urlencoded" in ctype and isinstance(body_template, dict):
                # form encoding: substitute raw (requests will urlencode the mapping)
                form = {k: (v.replace("{{PROMPT}}", prompt) if isinstance(v, str) else v)
                        for k, v in body_template.items()}
                send_kwargs["data"] = form
            elif body_template:
                body_str = json.dumps(body_template).replace("{{PROMPT}}", _json_escape(prompt))
                send_kwargs["json"] = json.loads(body_str)
        except (TypeError, ValueError) as e:
            return self._fail(f"body template render failed: {e}", start)

        try:
            logger.info(f"DirectAPI: {method} {endpoint}")
            tls_min = config.get("tls_min")
            if tls_min:
                # a minimum-TLS pin needs a Session (the adapter is mounted per-scheme)
                sess = requests.Session()
                ad = tls_min_adapter(tls_min)
                if ad:
                    sess.mount("https://", ad)
                resp = sess.request(method, endpoint, headers=headers, timeout=timeout,
                                    **tls_kwargs(config), **send_kwargs)
            else:
                resp = requests.request(method, endpoint, headers=headers, timeout=timeout,
                                        **tls_kwargs(config), **send_kwargs)
            resp.raise_for_status()
        except requests.RequestException as e:
            return self._fail(f"HTTP error: {e}", start, status_code=getattr(getattr(e, "response", None), "status_code", None))

        extract_path = config.get("response_path")
        # Try JSON; fall back to raw text for plain-text bots.
        try:
            data = resp.json()
        except (json.JSONDecodeError, ValueError):
            data = None
        if data is None:
            # No JSON body — if the caller didn't demand a path, the raw text IS the answer.
            if extract_path:
                return self._fail(f"expected JSON for response_path '{extract_path}' but got non-JSON",
                                  start, raw=utf8_text(resp)[:500])
            return self._ok(utf8_text(resp).strip(), start, adapter="direct_api", format="text")

        _path = extract_path or "response"
        response_text = _extract(data, _path)
        if response_text is None and not extract_path:
            # No path configured and no obvious 'response' key — best-effort deepest string.
            response_text = _deepest_str(data)
        if response_text is None:
            return self._fail(
                "Could not extract response at path '%s'" % _path,
                start, raw=json.dumps(data)[:500])

        return self._ok(str(response_text).strip(), start, adapter="direct_api")


def _deepest_str(obj: Any) -> Any:
    """Best-effort: return the deepest lone string value (for schemaless responses)."""
    if isinstance(obj, str):
        return obj
    if isinstance(obj, dict):
        for v in obj.values():
            r = _deepest_str(v)
            if r is not None:
                return r
    if isinstance(obj, list) and obj:
        return _deepest_str(obj[-1])
    return None


def _extract(data: Any, path: str) -> Any:
    """Extract a value from nested dict/list using dot notation.

    Example: _extract({"choices": [{"message": {"content": "hi"}}]}, "choices.0.message.content") -> "hi"
    """
    parts = path.split(".")
    current = data
    for part in parts:
        if current is None:
            return None
        if isinstance(current, dict):
            current = current.get(part)
        elif isinstance(current, list):
            try:
                current = current[int(part)]
            except (ValueError, IndexError):
                return None
        else:
            return None
    return current
