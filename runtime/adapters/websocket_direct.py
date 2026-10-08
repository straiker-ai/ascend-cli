"""
WebSocket adapter — for chat targets that speak WebSocket instead of REST/SSE.

WHEN TO USE THIS vs. NATIVE ASCEND WEBSOCKET
--------------------------------------------
Ascend natively handles a *plain JSON* WebSocket target (it "sends the prompt and
collects all messages until close"). For that case you do NOT need this adapter —
just point Ascend at the `wss://` endpoint with a request/response template.

Use THIS adapter (behind the local proxy + bridge) when the WebSocket is not a
simple request/response-until-close, e.g.:
  - a handshake / auth / subscribe frame must be sent before the prompt,
  - the prompt must be wrapped in an envelope (JSON with an id, type, etc.),
  - the answer must be assembled from streamed frames and you need to know when it
    is "done" (a terminal frame, or an idle gap), rather than waiting for close,
  - the server keeps the socket open (so "collect until close" would hang).
For *binary* protocols (protobuf / MessagePack) subclass this and override
`_encode` / `_decode`.

CONFIG KEYS
-----------
  ws_url            - wss://... endpoint (required)
  headers           - dict of extra headers for the handshake (e.g. Authorization, Cookie, Origin)
  subprotocols      - list of WS subprotocols to negotiate (optional)
  init_messages     - list of frames to send right after connect (auth/subscribe).
                      Each item is a string, or a dict (sent as JSON). {{PROMPT}} allowed.
  send_template     - the frame to send for the prompt. String or dict; put {{PROMPT}}
                      where the prompt text goes. Default: {"type":"message","text":"{{PROMPT}}"}
  response_path     - dot-path to the answer text inside a JSON frame (e.g. "data.text").
                      If a frame matches, its value is collected. Omit to collect any
                      string under common keys (text/content/message/delta/token).
  done_when         - {"path": "...", "equals": "..."} or {"contains": "..."} — a frame
                      that signals the answer is complete. Optional.
  idle_ms           - if no done_when, stop after this many ms of silence BETWEEN frames (default 1500).
  first_frame_ms    - how long to wait for the FIRST frame (default: the probe budget). The idle gap
                      never applies before the first frame: a model's think time is not silence.
  timeout_ms        - overall hard timeout in ms (optional; otherwise derived from the platform's per-probe window)
  aggregate         - "concat" (default) join collected chunks, or "last" take the last.
"""

import asyncio
import json
import logging
import time
from typing import Any, Dict, List, Optional

from .base import BotAdapter, resolve_timeout_s

logger = logging.getLogger(__name__)


class WebSocketAdapter(BotAdapter):
    """Send a prompt over a (persistent-handshake) WebSocket and assemble the reply."""

    async def send_prompt(self, prompt: str, config: Dict[str, Any]) -> Dict[str, Any]:
        start = time.time()
        try:
            import websockets  # lazy: only needed for this adapter
        except ImportError:
            return self._fail(
                "The 'websockets' package is required for websocket_direct "
                "(pip install websockets).", start)

        ws_url = config.get("ws_url") or config.get("url")
        if not ws_url:
            return self._fail("No ws_url configured", start)

        headers = config.get("headers", {}) or {}
        subprotocols = config.get("subprotocols") or None
        timeout = resolve_timeout_s(config)
        idle = config.get("idle_ms", 1500) / 1000
        # How long to wait for the FIRST frame. The idle gap is a rule about silence BETWEEN
        # frames; applied before any frame it is a rule about the target's think time, and a
        # 1.5 s think-time budget fails every model-backed target on a cold path. MEASURED on a
        # Lambda-backed socket: 25 of 26 probes came back "No response frames collected" under
        # a run while the same target answered 9 of 10 direct calls in 2.5-3.8 s. Default: the
        # whole probe budget, less a margin so the adapter reports the timeout itself.
        first_frame = config.get("first_frame_ms")
        first_wait = (float(first_frame) / 1000) if first_frame else max(idle, timeout - 5.0)
        done_when = config.get("done_when")
        rpath = config.get("response_path")
        aggregate = config.get("aggregate", "concat")

        send_frame = config.get("send_template", {"type": "message", "text": "{{PROMPT}}"})
        init_messages = config.get("init_messages", []) or []

        seen: Dict[str, Any] = {"frames": 0, "error": None}
        try:
            resp = await asyncio.wait_for(
                self._converse(websockets, ws_url, headers, subprotocols, init_messages,
                               send_frame, prompt, rpath, done_when, idle, aggregate,
                               first_wait=first_wait, seen=seen),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            return self._fail(f"WebSocket timeout after {timeout}s", start, reason="ws_timeout",
                              next="the whole probe budget passed: raise timeout_ms only if the target is known to be slow; otherwise check the socket answers at all")
        except Exception as e:  # noqa: BLE001 — surface any handshake/protocol error to Ascend
            return self._fail(f"WebSocket error: {e}", start, reason="ws_error",
                              next="a handshake or protocol error: confirm ws_url, subprotocols and headers against the capture")

        if not resp:
            # Say what was seen: a gateway error frame, frames without answer text (a wrong
            # response_path), or true silence — three different fixes.
            if seen.get("error"):
                return self._fail(f"Socket answered with an error frame: {seen['error']}", start, reason="error_frame",
                                  next="the gateway or backend errored, not the adapter: read the target's logs; the send frame may be wrong for it")
            if seen.get("frames"):
                return self._fail(f"{seen['frames']} frame(s) received but none carried answer text "
                                  "(check response_path)", start, reason="no_answer_text",
                                  next="set response_path to the field that carries the reply in the received frames")
            return self._fail(f"No response frames collected within {first_wait:.0f}s", start, reason="no_first_frame",
                              next="nothing arrived in the think-time wait: check the send frame matches what the page sends, or raise first_frame_ms")
        return self._ok(resp.strip(), start, adapter="websocket_direct")

    async def _converse(self, websockets, ws_url, headers, subprotocols, init_messages,
                        send_frame, prompt, rpath, done_when, idle, aggregate,
                        first_wait: Optional[float] = None, seen: Optional[Dict[str, Any]] = None) -> str:
        seen = seen if seen is not None else {}
        first_wait = idle if first_wait is None else first_wait
        # `additional_headers` (websockets>=13) vs `extra_headers` (older) — try both.
        connect_kw = {"subprotocols": subprotocols, "open_timeout": 10, "max_size": 10 * 1024 * 1024}
        try:
            ws_cm = websockets.connect(ws_url, additional_headers=headers, **connect_kw)
        except TypeError:
            ws_cm = websockets.connect(ws_url, extra_headers=headers, **connect_kw)

        async with ws_cm as ws:
            for m in init_messages:
                await ws.send(self._encode(m, prompt))
            await ws.send(self._encode(send_frame, prompt))

            chunks: List[str] = []
            while True:
                # first frame: the target's think time; later frames: the idle gap between them
                wait = first_wait if not seen.get("frames") else idle
                try:
                    raw = await asyncio.wait_for(ws.recv(), timeout=wait)
                except asyncio.TimeoutError:
                    break  # idle gap => answer complete (or nothing ever came)
                except Exception:
                    break  # closed
                seen["frames"] = seen.get("frames", 0) + 1
                frame = self._decode(raw)
                err = self._error_frame(frame)
                if err:
                    seen["error"] = err
                    continue
                text = self._extract(frame, rpath)
                if text:
                    chunks.append(text)
                    if sum(len(c) for c in chunks) > 4 * 1024 * 1024 or len(chunks) > 5000:
                        break  # memory-DoS guard: stop reassembling a runaway stream
                if self._is_done(frame, done_when):
                    break
            if aggregate == "last":
                return chunks[-1] if chunks else ""
            return "".join(chunks)

    @staticmethod
    def _error_frame(frame: Any) -> Optional[str]:
        """A gateway's error frame is not an answer. API Gateway WebSocket answers a failed
        integration with {"message": "Internal server error", "connectionId": …, "requestId": …};
        read as text it would score as the bot's reply, and ignored it hides the reason."""
        if not isinstance(frame, dict):
            return None
        msg = frame.get("message")
        if isinstance(msg, str) and ("requestId" in frame or "connectionId" in frame) and len(frame) <= 4:
            return msg[:200]
        return None

    # -- protocol hooks (override for binary protocols) ------------------------
    def _encode(self, frame: Any, prompt: str) -> str:
        """Render a config frame to a wire string, substituting {{PROMPT}}."""
        if isinstance(frame, str):
            return frame.replace("{{PROMPT}}", prompt)
        s = json.dumps(frame)
        s = s.replace("{{PROMPT}}", _json_escape(prompt))
        return s

    def _decode(self, raw: Any) -> Any:
        """Parse an incoming frame. Returns a dict/list if JSON, else the raw string."""
        if isinstance(raw, (bytes, bytearray)):
            try:
                raw = raw.decode("utf-8", "ignore")
            except Exception:
                return {}
        try:
            return json.loads(raw)
        except (ValueError, TypeError):
            return raw  # plain-text frame

    # -- extraction ------------------------------------------------------------
    def _extract(self, frame: Any, rpath: Optional[str]) -> str:
        if isinstance(frame, str):
            return frame
        if rpath:
            v = _dot(frame, rpath)
            return v if isinstance(v, str) else ("" if v is None else json.dumps(v))
        # heuristic: pull the first string under common streaming keys
        if isinstance(frame, dict):
            for k in ("text", "content", "message", "delta", "token", "answer", "output"):
                v = frame.get(k)
                if isinstance(v, str):
                    return v
                if isinstance(v, dict):
                    for kk in ("text", "content", "value"):
                        if isinstance(v.get(kk), str):
                            return v[kk]
        return ""

    def _is_done(self, frame: Any, done_when: Optional[Dict[str, Any]]) -> bool:
        if not done_when:
            return False
        if "contains" in done_when:
            return done_when["contains"] in json.dumps(frame)
        path, equals = done_when.get("path"), done_when.get("equals")
        if path is not None:
            return _dot(frame, path) == equals
        return False


def _dot(data: Any, path: str) -> Any:
    """Walk a dot-path, transparently descending into JSON-encoded-as-STRING values.

    Real payloads nest JSON inside string fields, sometimes several levels deep, e.g.
    {"payload": "{\"data\": \"{\\\"text\\\": \\\"hi\\\"}\"}"}. A plain
    split(".") walk hits the string and returns None, silently losing the answer, so at
    each step a string that parses as JSON is decoded and traversal continues.
    """
    cur = data
    for part in path.split("."):
        # a string here can only continue the walk if it is itself JSON
        if isinstance(cur, str):
            cur = _maybe_decode(cur)
        if isinstance(cur, dict):
            cur = cur.get(part)
        elif isinstance(cur, list):
            try:
                cur = cur[int(part)]
            except (ValueError, IndexError):
                return None
        else:
            return None
    if isinstance(cur, str):
        # leave scalars alone, but unwrap a JSON string that holds the real object
        decoded = _maybe_decode(cur)
        if isinstance(decoded, (dict, list)):
            return decoded
    return cur


def _maybe_decode(s: str, _depth: int = 0) -> Any:
    """Return the parsed object if `s` is JSON (recursively, bounded), else `s`."""
    if _depth > 4 or not isinstance(s, str):
        return s
    t = s.strip()
    if not t or t[0] not in "{[":
        return s
    try:
        parsed = json.loads(t)
    except (ValueError, TypeError):
        return s
    if isinstance(parsed, str):
        return _maybe_decode(parsed, _depth + 1)
    return parsed


def _json_escape(s: str) -> str:
    # escape a raw string for safe injection into an already-serialized JSON template
    return json.dumps(s)[1:-1]
