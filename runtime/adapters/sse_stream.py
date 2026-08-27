"""
Generic SSE / token-stream adapter — for chat targets that stream their answer
back as many small frames instead of returning one JSON body.

THE PROBLEM THIS SOLVES
-----------------------
Modern LLM apps stream: the answer arrives as one frame per model delta, e.g.

    data: {"type": "token", "content": "I"}
    data: {"type": "token", "content": " can"}
    data: {"type": "status", "content": "Thinking..."}
    : keepalive
    data: {"type": "done"}

Point Ascend straight at an endpoint like that and the Console scores the raw
frames — you see a wall of {"type":"token",...} instead of the bot's answer.
This adapter reassembles the stream and hands the bridge ONE clean string.

WHEN TO USE THIS vs. direct_api
-------------------------------
Use `direct_api` when the target returns a single complete JSON body.
Use THIS adapter when the response is `text/event-stream` (SSE) or
newline-delimited JSON, i.e. the answer is spread across many frames.

It is the SSE analogue of `websocket_direct` — config-driven, not hardcoded to
any one vendor. If a target needs a bespoke handshake, subclass and override
`_bootstrap`.

FLOW
----
  1. (optional) bootstrap GET — establishes a session cookie and scrapes a CSRF
     token out of the page, then reuses both for every probe.
  2. POST the prompt, rendered into `request_template`.
  3. Read the stream frame by frame, concatenating the token frames, ignoring
     status/keepalive noise, stopping on the terminal frame.
  4. Return the assembled text.

Speed: same as the target's own latency (no browser, no polling).

REQUIRED CONFIG KEYS
--------------------
  base_url          - scheme://host:port of the target (e.g. http://localhost:8000)
  chat_path         - path of the streaming chat endpoint (e.g. /vendor/api/v1/chat)

OPTIONAL CONFIG KEYS
--------------------
  method            - HTTP method for the chat call (default "POST")
  request_template  - body to send; put {{PROMPT}} where the prompt goes.
                      Default: {"message": "{{PROMPT}}"}
  headers           - extra headers merged onto every request. IMPORTANT: if the
                      target fingerprints sessions (see below), set User-Agent /
                      Accept-Language / Accept-Encoding here so they stay stable.
  bootstrap         - dict; omit entirely if the target needs no session priming:
      url               path to GET first (e.g. "/vendor/")
      csrf_regex        regex with ONE capture group pulling a token out of the body
                        (e.g. '<meta name="csrf-token" content="([^"]+)">')
      csrf_header       header to send the captured token in (default "X-CSRF-Token")
      refresh_on_403    re-bootstrap once and retry after a 403 (default true)
      post_actions      list of extra calls to fire after the token is captured, for
                        targets where the agent has nothing to operate on until some
                        entity exists (register an account, open a conversation, pick
                        a tenant). Each item:
                          method      HTTP verb (default "POST")
                          url         path, relative to base_url
                          json        request body
                          skip_if     optional {"url": ..., "path": ..., "truthy": true}
                                      — GET that url first and skip this action when the
                                      dot-path value is already truthy/non-zero
                        Without this, an agent that needs context answers every probe
                        with "please provide your ID", which scores as a false PASS.
  stream            - dict describing the wire format:
      format            "sse" (default) or "ndjson"
      type_path         dot-path to a frame's type discriminator (default "type")
      token_types       frame types carrying answer text
                        (default ["token","delta","content_block_delta"])
      text_path         dot-path to the text inside a token frame (default "content")
      ignore_types      frame types to drop (default ["status","ping","keepalive"])
      done_when         {"path": "...", "equals": "..."} or {"contains": "..."}
                        (default {"path": "type", "equals": "done"})
      aggregate         "concat" (default) join the token frames, or "last"
      idle_ms           give up after this much silence between frames (default 20000)
  timeout_ms        - overall budget in ms (default 60000; raise for slow agentic targets, leaving headroom for delivery inside the ~90s reclaim window)
  verify_tls        - set false for self-signed targets (default true)

TIMEOUT BEHAVIOUR — read this before tuning
-------------------------------------------
Agentic targets that run tool chains can take far longer than the Ascend cloud's
platform's ~90s probe-reclaim window. When the budget runs out mid-stream this adapter returns the
text collected SO FAR with metadata `truncated: true`, rather than failing.
A partial agent answer is real evidence Ascend can score; "[ERROR] Timeout"
is not. It only fails when nothing at all arrived.
"""

import json
ABV2_STREAM_CHAR_CAP = 4 * 1024 * 1024  # cap total reassembled text (memory DoS guard)
import logging
import re
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

import requests

from .base import BotAdapter
from .websocket_direct import _dot, _json_escape

logger = logging.getLogger(__name__)

DEFAULT_TOKEN_TYPES = ["token", "delta", "content_block_delta"]
DEFAULT_IGNORE_TYPES = ["status", "ping", "keepalive"]
DEFAULT_DONE_WHEN = {"path": "type", "equals": "done"}
# Frames whose payload is one of these mean "stream finished" regardless of shape.
DONE_SENTINELS = {"[DONE]", "DONE"}


class SSEStreamAdapter(BotAdapter):
    """Send a prompt over HTTP and reassemble a streamed (SSE/NDJSON) reply."""

    def __init__(self):
        # One HTTP session per adapter instance. The router caches an instance per
        # (adapter, config_name), so the cookie jar + CSRF token survive across probes.
        self._session: Optional[requests.Session] = None
        self._csrf: Optional[str] = None
        self._conv: Optional[str] = None   # conversation id when the target requires a create step
        self._lock = threading.Lock()  # threads, not asyncio — the proxy is thread-per-request

    # -- session / bootstrap ---------------------------------------------------
    def _get_session(self, config: Dict[str, Any]) -> requests.Session:
        """Return the shared session, creating it with stable headers on first use.

        The headers are set ONCE on the session so that the bootstrap GET and every
        subsequent POST present an identical fingerprint. Targets that bind a session
        to User-Agent / Accept-Language / Accept-Encoding will silently invalidate it
        if these drift between requests.
        """
        if self._session is None:
            s = requests.Session()
            s.headers.update(config.get("headers", {}) or {})
            self._session = s
        return self._session

    def _reset_session(self) -> None:
        """Drop the cached session so the next attempt re-bootstraps from scratch.

        Closes the old session first — a wedged pooled connection survives simply
        dropping the reference, and would be reused for the rest of the run.
        """
        with self._lock:
            if self._session is not None:
                try:
                    self._session.close()
                except Exception:  # noqa: BLE001 — best effort teardown
                    pass
            self._session = None
            self._csrf = None

    def _bootstrap(self, config: Dict[str, Any], timeout: float) -> None:
        """GET a page to establish the session cookie and capture a CSRF token."""
        boot = config.get("bootstrap") or {}
        if not boot.get("url"):
            return

        session = self._get_session(config)
        url = _join(config["base_url"], boot["url"])
        resp = session.get(url, timeout=timeout, verify=config.get("verify_tls", True))
        resp.raise_for_status()

        pattern = boot.get("csrf_regex")
        if pattern:
            match = re.search(pattern, resp.text)
            if match:
                self._csrf = match.group(1)
                logger.debug("Bootstrapped CSRF token from %s", url)
            else:
                # Not fatal — the target may only enforce CSRF on some routes.
                logger.warning("csrf_regex did not match anything at %s", url)

        # Guarded by each action's own skip_if, which is evaluated against the CURRENT
        # session — so a genuinely re-primed session gets its context re-created, but
        # an already-provisioned one is left alone.
        for action in boot.get("post_actions") or []:
            self._run_post_action(action, config, timeout)

    def _run_post_action(
        self, action: Dict[str, Any], config: Dict[str, Any], timeout: float
    ) -> None:
        """Fire one setup call (e.g. register an account) after the token is captured.

        Failures are logged and swallowed: a target may already be provisioned, and a
        half-failed setup step should not take down the whole run.
        """
        session = self._get_session(config)
        base = config["base_url"]
        verify = config.get("verify_tls", True)
        name = action.get("name", action.get("url", "post_action"))

        skip = action.get("skip_if")
        if skip and skip.get("url"):
            try:
                probe = session.get(_join(base, skip["url"]), timeout=timeout, verify=verify)
                value = _dot(probe.json(), skip.get("path", ""))
                if bool(value) == bool(skip.get("truthy", True)):
                    logger.debug("post_action '%s' skipped (%s=%r)", name, skip.get("path"), value)
                    return
            except Exception as e:  # noqa: BLE001 — a failed probe just means "don't skip"
                logger.debug("post_action '%s' skip_if probe failed (%s); running anyway", name, e)

        headers = {"Content-Type": "application/json"}
        if self._csrf:
            headers[(config.get("bootstrap") or {}).get("csrf_header", "X-CSRF-Token")] = self._csrf

        try:
            resp = session.request(
                action.get("method", "POST"),
                _join(base, action["url"]),
                json=action.get("json"),
                headers=headers,
                timeout=timeout,
                verify=verify,
            )
            logger.info("post_action '%s' -> HTTP %s", name, resp.status_code)
            if resp.status_code >= 400:
                logger.warning("post_action '%s' body: %s", name, resp.text[:300])
        except Exception as e:  # noqa: BLE001 — never let setup abort the probe
            logger.warning("post_action '%s' failed: %s", name, e)

    # -- main entry point ------------------------------------------------------
    async def send_prompt(self, prompt: str, config: Dict[str, Any]) -> Dict[str, Any]:
        start = time.time()

        base_url = config.get("base_url")
        chat_path = config.get("chat_path")
        if not base_url or not chat_path:
            return self._fail("Missing required config: base_url, chat_path", start)

        timeout = config.get("timeout_ms", 60000) / 1000
        deadline = start + timeout
        url = _join(base_url, chat_path)
        method = config.get("method", "POST").upper()
        # Forgiving config: accept the stream keys either nested under "stream" OR
        # top-level (a common author mistake). Explicit "stream" sub-keys win.
        _top = {k: config[k] for k in
                ("format", "token_types", "text_path", "done_when", "aggregate", "idle_ms", "type_path")
                if k in config}
        stream_cfg = {**_top, **(config.get("stream", {}) or {})}
        boot = config.get("bootstrap") or {}
        refresh_on_403 = boot.get("refresh_on_403", True)

        # --- optional conversation step: POST /conversations -> id, then stream into
        # /conversations/{id}/responses. `{{CONV}}` is substituted in chat_path and the body,
        # mirroring session_poll's handling. This is the "REST create -> SSE named events" shape.
        conv = self._ensure_conversation(config, min(10.0, max(1.0, deadline - time.time())))
        if conv:
            url = _join(base_url, chat_path.replace("{{CONV}}", conv))

        body = self._render_body(
            config.get("request_template", {"message": "{{PROMPT}}"}), prompt
        )
        if conv:
            body = body.replace("{{CONV}}", conv)

        text, truncated, stalled = "", False, False
        try:
            for attempt in (1, 2):
                with self._lock:
                    if boot.get("url") and (self._session is None or self._csrf is None):
                        self._bootstrap(config, min(10.0, max(1.0, deadline - time.time())))

                session = self._get_session(config)
                headers = {"Content-Type": "application/json", "Accept": "text/event-stream"}
                if self._csrf:
                    headers[boot.get("csrf_header", "X-CSRF-Token")] = self._csrf

                idle = stream_cfg.get("idle_ms", 20000) / 1000
                read_timeout = max(1.0, min(idle, deadline - time.time()))

                resp = session.request(
                    method,
                    url,
                    data=body.encode("utf-8"),
                    headers=headers,
                    stream=True,
                    timeout=(10, read_timeout),
                    verify=config.get("verify_tls", True),
                )

                # A 403 usually means the CSRF token or session went stale — re-prime once.
                if resp.status_code == 403 and refresh_on_403 and attempt == 1:
                    resp.close()
                    logger.info("403 on %s — re-bootstrapping session and retrying", url)
                    self._reset_session()
                    continue

                if resp.status_code >= 400:
                    detail = resp.text[:500]
                    resp.close()
                    return self._fail(
                        f"HTTP {resp.status_code}: {detail}", start, adapter="sse_stream"
                    )

                text, truncated, stalled = self._read_stream(resp, stream_cfg, deadline)

                # An empty stream has two very different causes, and they must not share
                # a recovery path:
                #   stalled  -> the TARGET was too slow to emit a first frame. Re-priming
                #               the session does not help, and if post_actions seed data
                #               that triggers server-side work, re-priming makes the target
                #               slower still — a feedback loop that takes down the run.
                #   not stalled -> the server closed cleanly with nothing, i.e. the session
                #               really is wedged. That one is worth re-priming, or the same
                #               dead session silently fails every remaining prompt.
                if not text and not truncated and not stalled and attempt == 1:
                    logger.info("Empty stream from %s — re-priming session and retrying", url)
                    self._reset_session()
                    continue

                if not text and stalled:
                    return self._fail(
                        f"Target produced no output within {read_timeout:.0f}s "
                        f"(slow/overloaded target, session left intact)",
                        start, adapter="sse_stream", stalled=True,
                    )

                break

        except requests.RequestException as e:
            return self._fail(f"Request error: {e}", start, adapter="sse_stream")
        except Exception as e:  # noqa: BLE001 — never raise out of send_prompt
            logger.error("sse_stream adapter error: %s", e, exc_info=True)
            return self._fail(str(e), start, adapter="sse_stream")

        if not text:
            if truncated:
                # The stream WAS alive (status/keepalive frames arriving) but the agent
                # was still running tool rounds when the budget expired. That is a slow
                # target, not a misconfigured adapter — say so, or this gets debugged as
                # a parsing problem.
                return self._fail(
                    f"Agent still running tool rounds at the {timeout:.0f}s budget — "
                    f"no answer text emitted yet",
                    start, adapter="sse_stream", truncated=True,
                )
            return self._fail(
                "No response frames collected (check stream.token_types / text_path)",
                start,
                adapter="sse_stream",
            )

        return self._ok(text.strip(), start, adapter="sse_stream", truncated=truncated)

    # -- request rendering -----------------------------------------------------
    def _render_body(self, template: Any, prompt: str) -> str:
        """Serialize the request template, substituting {{PROMPT}} safely.

        The prompt is JSON-escaped before substitution so quotes and newlines in an
        adversarial prompt can't break out of the template.
        """
        if isinstance(template, str):
            return template.replace("{{PROMPT}}", _json_escape(prompt))
        return json.dumps(template).replace("{{PROMPT}}", _json_escape(prompt))

    # -- stream parsing --------------------------------------------------------
    def _read_stream(
        self, resp: requests.Response, cfg: Dict[str, Any], deadline: float
    ) -> Tuple[str, bool, bool]:
        """Consume the stream and return (assembled_text, truncated, stalled).

        `stalled` means the target went silent past its read timeout — a slow or
        overloaded target, as opposed to a session that has gone bad.
        """
        fmt = cfg.get("format", "sse")
        aggregate = cfg.get("aggregate", "concat")

        chunks: List[str] = []
        data_lines: List[str] = []
        cur_event: List[Optional[str]] = [None]   # SSE `event:` name for the buffered frame
        truncated = False
        stalled = False

        def flush() -> bool:
            """Parse one buffered event. Returns True when the stream is done."""
            ev = cur_event[0]
            cur_event[0] = None
            if not data_lines:
                # a bodyless named event can still be the terminator (event: done\n\n)
                return bool(ev) and self._event_is_done(ev, cfg)
            payload = "".join(data_lines)
            data_lines.clear()
            return self._handle_payload(payload, cfg, chunks, event=ev)

        try:
            for raw in resp.iter_lines(decode_unicode=False):
                if time.time() >= deadline:
                    truncated = True
                    break

                # iter_lines yields None/b"" for the blank line between SSE events.
                line = "" if not raw else (
                    raw.decode("utf-8", "replace") if isinstance(raw, (bytes, bytearray)) else raw
                )

                if fmt == "ndjson":
                    if not line.strip():
                        continue
                    if self._handle_payload(line.strip(), cfg, chunks):
                        break
                    continue

                if fmt in ("plaintext", "raw", "text"):
                    # No framing at all: every non-empty line/chunk IS answer text.
                    if not line:
                        continue
                    if line.strip() in DONE_SENTINELS:
                        break
                    chunks.append(line)
                    if sum(len(c) for c in chunks) > ABV2_STREAM_CHAR_CAP or len(chunks) > 20000:
                        break
                    continue

                # --- SSE framing ---
                if not line.strip():
                    if flush():          # blank line terminates an event
                        break
                    continue
                if line.startswith(":"):  # comment line — this is what eats keepalives
                    continue
                if line.startswith("data:"):
                    data_lines.append(line[5:].lstrip())
                elif line.startswith("event:"):
                    cur_event[0] = line[6:].strip()   # named-event dispatch (event: status|done)
                # `id:`, `retry:` carry no answer text — ignore.
            else:
                flush()  # stream ended without a trailing blank line

        except requests.RequestException as e:
            # A read timeout that happens PART-WAY THROUGH a stream surfaces as
            # ConnectionError wrapping urllib3's ReadTimeoutError — not as
            # requests.exceptions.ReadTimeout. Catching only the latter misreads a
            # slow target as a broken connection, which then triggers a needless
            # session re-prime (and re-runs any seeding post_actions).
            if _is_read_timeout(e):
                stalled = not chunks
                logger.debug("Target went silent (stalled=%s)", stalled)
            else:
                # Genuine transport error: keep partial text rather than losing it.
                logger.warning("Stream interrupted: %s", e)
        finally:
            resp.close()

        if aggregate == "last":
            return (chunks[-1] if chunks else ""), truncated, stalled
        return "".join(chunks), truncated, stalled

    @staticmethod
    def _event_is_done(event: Optional[str], cfg: Dict[str, Any]) -> bool:
        done_events = cfg.get("done_events")
        return bool(event) and bool(done_events) and event in done_events

    def _handle_payload(
        self, payload: str, cfg: Dict[str, Any], chunks: List[str], event: Optional[str] = None
    ) -> bool:
        """Process one frame payload. Appends any text; returns True if done.

        When the config declares `token_events`/`done_events`, dispatch is by SSE event
        NAME (event: status|done) — for streams whose content lives only in a named event
        and carry no JSON `type` discriminator.
        """
        if not payload:
            return self._event_is_done(event, cfg)

        # --- named-event routing (only when configured) ---
        token_events = cfg.get("token_events")
        done_events = cfg.get("done_events")
        if token_events or done_events:
            is_done = bool(done_events) and event in (done_events or [])
            wanted = (event in (token_events or [])) or is_done
            if event is not None and not wanted:
                return False              # a status/keepalive named event — ignore its data
            text = self._payload_text(payload, cfg)
            if text:
                chunks.append(text)
                if sum(len(c) for c in chunks) > ABV2_STREAM_CHAR_CAP:
                    return True
            return is_done

        if payload in DONE_SENTINELS:
            return True

        try:
            frame = json.loads(payload)
        except (ValueError, TypeError):
            # Not JSON — some targets stream bare text deltas.
            chunks.append(payload)
            if sum(len(c) for c in chunks) > ABV2_STREAM_CHAR_CAP or len(chunks) > 20000:
                return True  # memory-DoS guard: stop reassembling a runaway stream
            return False

        type_path = cfg.get("type_path", "type")
        ftype = _dot(frame, type_path) if type_path else None

        if ftype in (cfg.get("ignore_types") or DEFAULT_IGNORE_TYPES):
            return False

        done = self._is_done(frame, cfg.get("done_when", DEFAULT_DONE_WHEN))

        token_types = cfg.get("token_types") or DEFAULT_TOKEN_TYPES
        # Unknown/absent type => fall through to extraction; the heuristic below
        # handles targets that stream deltas without a discriminator.
        if ftype is None or ftype in token_types:
            text = self._extract(frame, cfg.get("text_path", "content"))
            if text:
                chunks.append(text)

        return done

    def _ensure_conversation(self, config: Dict[str, Any], timeout_s: float) -> Optional[str]:
        """Mint (once) the conversation id some platforms require before streaming.

        Two shapes are supported, matching what these APIs actually do:
          create.id_mode: "server"  -> POST create.url, read the id at create.id_path
          create.id_mode: "client"  -> we generate a uuid and POST it (the server just records it)

        Config:
          create:
            url        path (relative to base_url) or absolute
            method     default POST
            body       optional body template; {{CONV}} substituted for client-generated ids
            id_path    dot-path to the id in the response (default "id"); server mode only
            id_mode    "server" (default) | "client"
            per_prompt true to mint a fresh conversation for EVERY prompt (default: reuse)
        """
        create = config.get("create") or {}
        if not create.get("url"):
            return None
        with self._lock:
            if self._conv and not create.get("per_prompt"):
                return self._conv
            session = self._get_session(config)
            base_url = config.get("base_url") or ""
            url = create["url"] if str(create["url"]).startswith("http") else _join(base_url, create["url"])
            mode = create.get("id_mode", "server")
            conv = None
            body = create.get("body")
            if mode == "client":
                import uuid
                conv = f"abv2-{uuid.uuid4().hex}"
            payload = None
            if body is not None:
                payload = json.dumps(body)
                if conv:
                    payload = payload.replace("{{CONV}}", conv)
            headers = {"Content-Type": "application/json", **(config.get("headers") or {})}
            if self._csrf:
                headers[(config.get("bootstrap") or {}).get("csrf_header", "X-CSRF-Token")] = self._csrf
            r = session.request(create.get("method", "POST"), url,
                                data=payload.encode("utf-8") if payload is not None else None,
                                headers=headers, timeout=timeout_s,
                                verify=config.get("verify_tls", True))
            r.raise_for_status()
            if mode != "client":
                try:
                    conv = _dot(r.json(), create.get("id_path", "id"))
                except (ValueError, TypeError):
                    conv = None
                if conv is None:
                    raise RuntimeError(
                        f"create call to {url} returned no id at "
                        f"'{create.get('id_path','id')}': {utf8_text(r)[:200]}")
            self._conv = str(conv)
            logger.info("conversation %s created via %s", self._conv, url)
            return self._conv

    def _payload_text(self, payload: str, cfg: Dict[str, Any]) -> str:
        """Text out of a named-event data payload: JSON via text_path, else the raw string."""
        try:
            frame = json.loads(payload)
        except (ValueError, TypeError):
            return payload
        return self._extract(frame, cfg.get("text_path", "content")) or ""

    def _extract(self, frame: Any, text_path: Optional[str]) -> str:
        if isinstance(frame, str):
            return frame
        if text_path:
            value = _dot(frame, text_path)
            if isinstance(value, str):
                return value
            if value is not None:
                return json.dumps(value)
        if isinstance(frame, dict):
            for key in ("content", "text", "delta", "token", "message", "answer", "output"):
                value = frame.get(key)
                if isinstance(value, str):
                    return value
                if isinstance(value, dict):
                    for inner in ("text", "content", "value"):
                        if isinstance(value.get(inner), str):
                            return value[inner]
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


def _join(base: str, path: str) -> str:
    return f"{base.rstrip('/')}/{path.lstrip('/')}"


def _is_read_timeout(exc: BaseException) -> bool:
    """True if this exception is really 'the target stopped sending', however wrapped.

    requests raises ReadTimeout for a timeout on the initial response, but a timeout
    that lands mid-stream comes back as ConnectionError wrapping
    urllib3.exceptions.ReadTimeoutError. Walk the cause chain rather than trusting
    the outermost type.
    """
    if isinstance(exc, requests.exceptions.ReadTimeout):
        return True
    seen = set()
    cur: Optional[BaseException] = exc
    while cur is not None and id(cur) not in seen:
        seen.add(id(cur))
        if type(cur).__name__ in ("ReadTimeoutError", "ReadTimeout", "TimeoutError"):
            return True
        for arg in getattr(cur, "args", ()):
            if isinstance(arg, BaseException) and type(arg).__name__ in (
                "ReadTimeoutError", "ReadTimeout", "TimeoutError"
            ):
                return True
        cur = cur.__cause__ or cur.__context__
    return "read timed out" in str(exc).lower()
