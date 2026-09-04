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
  timeout_ms    - Request timeout in milliseconds (optional; otherwise derived from the platform's per-probe window)
  stop_marker   - Streaming terminator to strip off a plain-text reply ("<<<END>>>", "[DONE]",
                  "<EOS>"); a string or a list. Opt-in: without it nothing is removed, so a
                  target with no terminator can never lose real text. Discovery sets this when
                  it observes one, because the marker is transport and the scorer would
                  otherwise read it as the agent's words on every turn.
"""

import json
import re
import time
import logging
from typing import Any, Dict

import requests
from urllib.parse import quote

from .base import BotAdapter, utf8_text, tls_kwargs, tls_min_adapter, resolve_timeout_s
from .websocket_direct import _json_escape

logger = logging.getLogger(__name__)


def _strip_stop(text: str, config: Dict[str, Any]) -> str:
    """Remove a streaming terminator from a plain-text reply.

    A chunked text/plain agent closes its body with a marker -- `<<<END>>>`, `[DONE]`, `<EOS>`.
    That marker is transport, not speech, but with no JSON envelope to separate them it lands at
    the end of the answer and the scorer reads it as the agent's words. Exactly the same class of
    defect as SSE progress chatter arriving as the reply, and it corrupts EVERY turn against such
    a target rather than failing loudly once.

    Opt-in: only a `stop_marker` that discovery actually observed (or an operator set) is
    removed, so this cannot eat real text from a target that has no terminator. A list is
    accepted because some servers alternate markers.
    """
    marker = config.get("stop_marker")
    out = (text or "").strip()
    if not marker:
        return out
    for m in ([marker] if isinstance(marker, str) else list(marker)):
        if m and out.endswith(m):
            out = out[: -len(m)].rstrip()
    return out


class DirectAPIAdapter(BotAdapter):
    """Send a prompt via direct HTTP POST and extract the response."""

    async def send_prompt(self, prompt: str, config: Dict[str, Any]) -> Dict[str, Any]:
        start = time.time()

        endpoint = config.get("endpoint")
        if not endpoint:
            return self._fail("No endpoint configured", start)

        method = config.get("method", "POST").upper()
        timeout = resolve_timeout_s(config)

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

        # A credential can ride in the query string (`--api-key ...:in=query`, Gemini's `?key=`),
        # which this tool bakes into the endpoint itself. Never log or report the raw URL.
        def _safe(text):
            try:
                from manual import redact_url
                return redact_url(text) if isinstance(text, str) and text.startswith("http") \
                    else re.sub(r"([?&](?:key|api_?key|access_token|token)=)[^&\s]+",
                                r"\1[REDACTED]", str(text), flags=re.I)
            except Exception:
                return text

        try:
            logger.info(f"DirectAPI: {method} {_safe(endpoint)}")
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
            return self._fail(f"HTTP error: {_safe(e)}", start,
                                  status_code=getattr(getattr(e, "response", None), "status_code", None))

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
            return self._ok(_strip_stop(utf8_text(resp), config), start,
                            adapter="direct_api", format="text")

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

    A ``*`` segment (also written ``[]``) maps over a list and CONCATENATES what it finds, which
    is how an answer split across several content blocks is read back whole::

        _extract({"content": [{"text": "How can"}, {"text": " I help?"}]}, "content.*.text")
        -> "How can I help?"

    Without this the deriver had to pick one index, and picking one index means every probe scores
    a fragment. Measured on a two-block target: the path landed on ``content.1.text``, so every
    answer started mid-sentence and everything in block 0 -- which is where a leaked system prompt
    appears, since it comes first -- was discarded on every probe of every assessment. The run
    still completed and reported LOW risk.

    Blocks are joined with no separator because they are consecutive runs of one message, not a
    list of distinct items; the fragments above concatenate into the original sentence.

    A NEGATIVE index counts from the end, so ``messages.-1.content`` is "the last message". That
    is the shape of every transcript-returning target — a gateway or GraphQL envelope that hands
    back the whole conversation, user turn first, assistant reply last. Without it the deriver had
    to name a fixed index: ``messages.0.content`` scores the probe's OWN prompt echoed back, and
    ``messages.1.content`` breaks the moment the target adds a system turn.
    """
    # `content[].text` splits as ["content[]", "text"], so a trailing `[]` expands into its key
    # plus a wildcard segment; a bare `[]` is the wildcard on its own.
    parts = []
    for p in path.split("."):
        if p.endswith("[]") and len(p) > 2:
            parts.extend([p[:-2], "*"])
        else:
            parts.append("*" if p == "[]" else p)
    current = data
    for i, part in enumerate(parts):
        if current is None:
            return None
        if part == "*":
            if not isinstance(current, list):
                return None
            rest = ".".join(parts[i + 1:])
            vals = [(_extract(item, rest) if rest else item) for item in current]
            vals = [v for v in vals if isinstance(v, str)]
            return "".join(vals) if vals else None
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
