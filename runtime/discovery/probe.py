"""
discovery.probe — non-browser API discovery ("they handed me a URL and nothing else").

THE GAP THIS CLOSES
-------------------
:mod:`discovery.capture` needs a browser and :func:`discovery.classify.load_har`
needs a HAR. Neither exists when a customer emails "here is the endpoint, go test
it" — sometimes not even the endpoint, just ``https://bot.customer.com/api``.
This module derives the missing evidence *empirically*: it talks to the target,
one benign prompt at a time, until a real answer comes back.

WHY EMPIRICAL AND NOT HEURISTIC
-------------------------------
Everything here is decided by what the target actually did, never by a score we
invented:

* the chat endpoint is the URL that **answered**, not the URL that looked chatty;
* the request shape is the body the target **accepted**, not the shape its path
  name suggested (path names only reorder the queue, they never decide);
* ``response_path`` is the JSON path whose value **is** the answer we received;
* a 200 proves nothing — a response that merely echoes the prompt, is empty, or
  is an error envelope is rejected as "not the chat endpoint" (see
  :func:`_understand_response` / :func:`score_answer`).

The output plugs into the existing pipeline two ways::

    r = probe_api("https://bot.example.com/api", headers={"Authorization": "Bearer …"})
    classify_evidence(r.evidence)     # full six-layer classification (auth, session, …)
    build_config(r)                   # or skip it: the probe already knows the contract

MANNERS (this code touches customer production systems)
-------------------------------------------------------
One innocuous prompt. Sequential requests, never parallel, with ``rate_limit_s``
between them. A hard ``max_attempts`` ceiling. It gives up after repeated auth
failures instead of guessing credentials, backs off on 429, and never retries a
5xx more than twice per endpoint. It never sends an adversarial payload — probing
is reconnaissance, not the assessment.

No network at import time: ``requests`` is imported inside the call that needs it,
which is also what makes the whole module unit-testable with ``requests``
monkeypatched (see ``tests/conftest.py::install_fake_requests``).
"""
from __future__ import annotations

import asyncio
import json
import re
import time
from dataclasses import dataclass, field, replace
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import quote, urlsplit

# --------------------------------------------------------------------------- #
# Constants                                                                    #
# --------------------------------------------------------------------------- #

#: The single benign prompt. Deliberately boring: it must be safe to send to a
#: production bot, and it must invite prose (a bare "hi" often gets a one-word
#: reply that is indistinguishable from a status token).
DEFAULT_PROMPT = "Hello, what can you help me with?"

#: Placeholder used by every adapter's body template.
PROMPT_TOKEN = "{{PROMPT}}"

_P = PROMPT_TOKEN

#: Ranked chat-path candidates, tried under the origin AND under the path prefix
#: the caller gave. Order is "how often this path is the chat endpoint in the
#: wild", most likely first — it only decides *queue order*, never the answer.
CANDIDATE_PATHS: Tuple[str, ...] = (
    "chat",
    "api/chat",
    "v1/chat",
    "chat/completions",
    "v1/chat/completions",
    "api/v1/chat",
    "message",
    "messages",
    "v1/messages",
    "api/message",
    "query",
    "ask",
    "invoke",
    "converse",
    # create-then-message contracts: the create call answers 2xx with an id and no answer, which
    # the diagnosis names as such instead of "no candidate path behaved like a chat endpoint"
    "conversations",
    "sessions",
    "session",
    "predict",
    "completion",
    "v1/completions",
    "agent",
    "agents/chat",
    "assistant",
    "generate",
    "run",
    "stream",
    "api/query",
    "api/ask",
    "conversation",
)

#: Ranked JSON body templates. Each contains ``{{PROMPT}}`` somewhere.
BODY_SHAPES: Tuple[Tuple[str, Any], ...] = (
    ("message", {"message": _P}),
    ("openai_messages", {"messages": [{"role": "user", "content": _P}]}),
    ("prompt", {"prompt": _P}),
    ("input", {"input": _P}),
    ("text", {"text": _P}),
    ("query", {"query": _P}),
    ("question", {"question": _P}),
    ("openai_messages_model", {"messages": [{"role": "user", "content": _P}], "model": "gpt-4"}),
    ("hf_inputs", {"inputs": _P}),
    ("gemini_contents", {"contents": [{"parts": [{"text": _P}]}]}),
    ("input_text", {"input": {"text": _P}}),
    ("data_message", {"data": {"message": _P}}),
    ("chat_input", {"chatInput": _P}),
    ("content", {"content": _P}),
    ("msg", {"msg": _P}),
)

#: Query-parameter names to try with GET (some targets take the prompt in the URL).
QUERY_PARAM_NAMES: Tuple[str, ...] = ("q", "message", "prompt")

# Response-body reading limits — one benign prompt should never need more.
_BODY_CAP_BYTES = 262_144
_ANSWER_PREVIEW = 240

# Politeness / abort thresholds (see module docstring).
_MAX_CONSECUTIVE_AUTH = 3
_MAX_RATE_LIMITED = 2
_MAX_5XX_PER_ENDPOINT = 2
_MAX_PHASE2_ENDPOINTS = 3

# An answer must clear this score to count as "the bot said something".
MIN_ANSWER_SCORE = 1.0

_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_HEXY_RE = re.compile(r"^[0-9a-f]{16,}$", re.I)
_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]?[\d:.\-+Z]*$")
_NUMERIC_RE = re.compile(r"^[-+]?\d+(\.\d+)?$")
_URLISH_RE = re.compile(r"^(https?://\S+|wss?://\S+|/[\w\-./]*)$", re.I)
_MIME_RE = re.compile(r"^[a-z]+/[a-z0-9.+\-]+$", re.I)
_MARKUP_RE = re.compile(r"^\s*<(!doctype|html|\?xml|svg)", re.I)
_SIGNIN_RE = re.compile(r"type=[\"']?password|sign[ -]?in|log[ -]?in|authenticate", re.I)


def _looks_like_signin(body: str) -> bool:
    """An HTML page with a password field or sign-in wording — what a login wall looks like."""
    head = (body or "")[:8192]
    return bool(_MARKUP_RE.match(head)) and bool(_SIGNIN_RE.search(head))

#: Values that are protocol chatter, never a bot's answer.
_NON_ANSWER_TOKENS = {
    "ok", "okay", "success", "successful", "true", "false", "null", "none",
    "error", "failed", "failure", "pending", "processing", "queued", "running",
    "completed", "complete", "done", "accepted", "created", "unknown", "n/a",
    "yes", "no", "user", "assistant", "system", "bot", "message", "text",
    "not found", "forbidden", "unauthorized", "bad request", "method not allowed",
    "internal server error", "service unavailable", "no", "stop", "length",
}

#: JSON keys whose values identify/describe rather than answer.
_ID_LEAF_KEYS = {
    "id", "uuid", "requestid", "request_id", "traceid", "trace_id", "sessionid",
    "session_id", "conversationid", "conversation_id", "threadid", "thread_id",
    "chatid", "chat_id", "messageid", "message_id", "runid", "run_id", "model",
    "object", "type", "role", "status", "state", "created", "created_at",
    "createdat", "updated_at", "timestamp", "finish_reason", "finishreason",
    # GraphQL stamps __typename on every object; its value is a type name, never an answer.
    "__typename", "typename",
    "stop_reason", "stopreason", "version", "provider", "engine", "index",
    "code", "locale", "language", "mimetype", "content_type", "contenttype",
}

#: JSON keys that usually DO carry the answer, best first.
_ANSWER_LEAF_KEYS: Tuple[str, ...] = (
    "answer", "response", "reply", "completion", "generated_text", "output_text",
    "content", "text", "message", "output", "result", "delta", "value", "data",
)

#: Containers whose contents are debug/diagnostic and NOT a stable answer location. A long
#: prose string inside one of these will outscore the real answer field unless penalized.
_VOLATILE_CONTAINERS = {
    "trace", "traces", "debug", "logs", "log", "steps", "events", "history",
    "spans", "diagnostics", "intermediate_steps", "reasoning", "thoughts",
}

#: Frame keys that carry streamed text (SSE/NDJSON token frames).
_STREAM_TEXT_KEYS: Tuple[str, ...] = (
    "content", "text", "delta", "token", "chunk", "message", "answer", "value", "data",
)

#: Payloads that terminate a stream.
_DONE_SENTINELS = {"[DONE]", "DONE", "[done]", "done"}

#: Frame `type` values that mean "the stream is finished".
_DONE_TYPES = {"done", "end", "complete", "completed", "final", "finish",
               "message_stop", "stream_end", "close"}


# --------------------------------------------------------------------------- #
# Public helpers (kept here so nothing imports a private name from classify)   #
# --------------------------------------------------------------------------- #
def string_paths(obj: Any, prefix: str = "") -> List[Tuple[str, str]]:
    """Every ``(dot_path, string_value)`` in a nested JSON structure.

    Local twin of ``classify._paths_to_strings``: duplicated deliberately rather
    than imported, because reaching across modules for a private name couples the
    two files' internals together.
    """
    out: List[Tuple[str, str]] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.extend(string_paths(v, f"{prefix}.{k}" if prefix else str(k)))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            out.extend(string_paths(v, f"{prefix}.{i}" if prefix else str(i)))
    elif isinstance(obj, str):
        out.append((prefix, obj))
    return out


def dot_get(obj: Any, path: str) -> Any:
    """Traverse ``obj`` by a dot-path, indexing lists with numeric segments."""
    cur = obj
    for part in (path or "").split("."):
        if cur is None or part == "":
            return None
        if isinstance(cur, dict):
            cur = cur.get(part)
        elif isinstance(cur, list):
            try:
                cur = cur[int(part)]
            except (ValueError, IndexError):
                return None
        else:
            return None
    return cur


def _json_escape(s: str) -> str:
    """Escape a string for splicing into a JSON document (no surrounding quotes)."""
    return json.dumps(s)[1:-1]


def _norm(s: str) -> str:
    """Whitespace/case-normalized text, for echo detection."""
    return " ".join((s or "").split()).strip().lower()


# --------------------------------------------------------------------------- #
# Data model                                                                   #
# --------------------------------------------------------------------------- #
@dataclass
class Shape:
    """One candidate request contract (method + how the prompt is carried).

    Exactly one of ``body`` / ``raw`` / ``query_param`` is set.
    """
    label: str
    method: str = "POST"
    body: Any = None                      # JSON template containing {{PROMPT}}
    raw: Optional[str] = None             # raw text body template
    query_param: Optional[str] = None     # prompt goes in ?<name>=
    content_type: Optional[str] = "application/json"

    def render(self, prompt: str) -> Any:
        """Substitute the real prompt into this shape's JSON template."""
        if self.body is None:
            return None
        return json.loads(json.dumps(self.body).replace(PROMPT_TOKEN, _json_escape(prompt)))


@dataclass
class Attempt:
    """One candidate we actually sent, and what came back.

    Kept for every attempt (win or lose) because "what did you try?" is the first
    question an operator asks when discovery fails.
    """
    url: str
    method: str
    shape: str
    status: Optional[int] = None
    ok: bool = False
    outcome: str = ""          # answer|echo|empty|error_envelope|no_answer|shape_rejected|
                               # auth|not_found|method_not_allowed|rate_limited|
                               # server_error|dns|unreachable|tls|transport
    detail: str = ""
    elapsed_ms: int = 0
    transport: Optional[str] = None
    response_path: Optional[str] = None
    answer_preview: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url, "method": self.method, "shape": self.shape,
            "status": self.status, "ok": self.ok, "outcome": self.outcome,
            "detail": self.detail, "elapsed_ms": self.elapsed_ms,
            "transport": self.transport, "response_path": self.response_path,
            "answer_preview": self.answer_preview,
        }


@dataclass
class ProbeResult:
    """What the probe learned. ``ok`` is True only for ``diagnosis == "ok"``.

    On ``diagnosis == "ambiguous"`` the endpoint/body/response fields still hold
    the best-scoring candidate (so an operator can eyeball it), but ``ok`` is
    False: more than one endpoint answered and only a human can say which one is
    the system under test.
    """
    ok: bool = False
    endpoint: Optional[str] = None
    method: Optional[str] = None
    request_body: Optional[Any] = None        # winning template, {{PROMPT}} restored
    response_path: Optional[str] = None
    response_text: Optional[str] = None
    transport: Optional[str] = None           # rest_json | sse | ndjson | text
    evidence: Dict[str, Any] = field(default_factory=dict)
    attempts: List[Attempt] = field(default_factory=list)
    diagnosis: str = "not_found"
    message: str = ""
    hint: str = ""
    # extras (not part of the required surface, but free to a caller)
    prompt: str = DEFAULT_PROMPT
    headers: Dict[str, str] = field(default_factory=dict)
    shape_label: Optional[str] = None
    stream_hints: Dict[str, Any] = field(default_factory=dict)
    alternatives: List[str] = field(default_factory=list)
    tried_urls: List[str] = field(default_factory=list)
    timeout_s: float = 20.0

    def to_dict(self) -> Dict[str, Any]:
        """JSON-safe view (for `ascend probe --json` style output)."""
        return {
            "ok": self.ok, "endpoint": self.endpoint, "method": self.method,
            "request_body": self.request_body, "response_path": self.response_path,
            "response_text": self.response_text, "transport": self.transport,
            "diagnosis": self.diagnosis, "message": self.message, "hint": self.hint,
            "shape": self.shape_label, "stream_hints": self.stream_hints,
            "alternatives": self.alternatives, "tried_urls": self.tried_urls,
            "attempts": [a.to_dict() for a in self.attempts],
        }


# --------------------------------------------------------------------------- #
# Candidate generation                                                         #
# --------------------------------------------------------------------------- #
def _split_url(url: str) -> Tuple[str, str, str, str]:
    """Return ``(origin, path, query, host)``; assume https:// when no scheme."""
    u = (url or "").strip()
    if not u:
        raise ValueError("empty url")
    if "://" not in u:
        u = "https://" + u
    parts = urlsplit(u)
    if not parts.netloc:
        raise ValueError(f"not an absolute URL: {url!r}")
    return f"{parts.scheme}://{parts.netloc}", parts.path or "", parts.query or "", parts.hostname or ""


def candidate_endpoints(url: str, extra_paths: Optional[Sequence[str]] = None,
                        limit: int = 20) -> List[str]:
    """Rank candidate chat URLs for ``url``, caller's own URL FIRST.

    Covers the two ways a customer hands over an API: the full endpoint (which we
    must try verbatim and unmodified) and a parent/base URL (where the endpoint
    lives one or two segments below). Candidates are generated under the given
    path, its parent, and the bare origin, so ``https://x/api/v2/bot`` also probes
    ``/api/v2/bot/chat``, ``/api/v2/chat`` and ``/chat``.
    """
    origin, path, query, _host = _split_url(url)
    out: List[str] = []

    given = path.rstrip("/")
    if given.strip("/"):
        out.append(origin + path + (f"?{query}" if query else ""))

    bases: List[str] = []
    if given.strip("/"):
        bases.append(given)
        parent = given.rsplit("/", 1)[0]
        if parent and parent != given:
            bases.append(parent)
    bases.append("")  # the origin itself

    paths = [p for p in (list(extra_paths or []) + list(CANDIDATE_PATHS)) if p]
    for cand in paths:
        leaf = "/" + str(cand).strip("/")
        for b in bases:
            out.append(origin + b + leaf)
    out.append(origin + "/")

    seen, ranked = set(), []
    for u in out:
        if u not in seen:
            seen.add(u)
            ranked.append(u)
    return ranked[:max(1, limit)]


def default_shapes(method: Optional[str] = None,
                   bodies: Optional[Sequence[Any]] = None,
                   extra_body: Optional[Dict[str, Any]] = None) -> List[Shape]:
    """Ranked request shapes; caller-supplied ``bodies`` are tried first.

    When ``method`` is pinned we only emit shapes for that verb — a caller who
    knows it is a GET API should not have us POST at their target.

    ``extra_body`` is merged into EVERY dict-shaped body. Some agents carry their credential
    and/or a tenant selector in the request body rather than a header, so without this the probe
    would 401/400 on every shape and report the target as unreachable when it is simply gated.
    """
    want = (method or "").upper() or None
    shapes: List[Shape] = []

    for i, b in enumerate(bodies or []):
        if isinstance(b, str):
            shapes.append(Shape(f"caller[{i}]", want or "POST", raw=b, body=None,
                                content_type="text/plain"))
        else:
            shapes.append(Shape(f"caller[{i}]", want or "POST", body=b))

    if want in (None, "POST", "PUT", "PATCH"):
        verb = want or "POST"
        json_shapes = [Shape(label, verb, body=tpl) for label, tpl in BODY_SHAPES]
        # Second, right after the plainest JSON shape: an intranet bot bolted onto an existing
        # form-posting app takes `application/x-www-form-urlencoded` and answers every JSON body
        # with a 4xx — and three of those in a row trip the politeness abort, so a form shape
        # placed last was never reached. Extra --body-field values merge in like any dict body.
        shapes.extend(json_shapes[:1])
        shapes.append(Shape("form_message", verb, body={"message": _P},
                            content_type="application/x-www-form-urlencoded"))
        shapes.extend(json_shapes[1:])
    if want in (None, "GET"):
        shapes.extend(Shape(f"query:{name}", "GET", body=None, query_param=name,
                            content_type=None) for name in QUERY_PARAM_NAMES)
    if want in (None, "POST"):
        # Last resort: some targets take the bare prompt as the request body.
        shapes.append(Shape("raw_text", "POST", raw=PROMPT_TOKEN, content_type="text/plain"))

    if extra_body:
        merged: List[Shape] = []
        for s in shapes:
            if isinstance(s.body, dict):
                merged.append(replace(s, body={**s.body, **extra_body}))
            else:
                merged.append(s)          # raw/query shapes can't carry body fields
        return merged
    return shapes


def _reorder_for_path(url: str, shapes: List[Shape]) -> List[Shape]:
    """Move the shape a path name *suggests* to the front of the queue.

    This is an ordering optimisation only — it saves requests against an
    OpenAI-compatible or Gemini-style path. It never decides the outcome; the
    target still has to accept the body.
    """
    low = url.lower()
    preferred: List[str] = []
    if "completions" in low or low.rstrip("/").endswith("/v1/chat"):
        preferred = ["openai_messages", "openai_messages_model"]
    elif "generatecontent" in low or "gemini" in low or "aiplatform" in low:
        preferred = ["gemini_contents"]
    elif low.rstrip("/").endswith("/generate") or "huggingface" in low or "/models/" in low:
        preferred = ["hf_inputs", "prompt"]
    elif low.rstrip("/").endswith(("/predict", "/invoke", "/run")):
        preferred = ["input", "prompt"]
    if not preferred:
        return list(shapes)
    front = [s for s in shapes if s.label in preferred]
    front.sort(key=lambda s: preferred.index(s.label))
    return front + [s for s in shapes if s.label not in preferred]


def _shapes_from_error(body_text: str, parsed: Any) -> List[Shape]:
    """Synthesize body shapes from the target's OWN validation error.

    A 400/422 that names the field it wanted ("field required: 'question'", or a
    FastAPI ``detail[].loc``) is the target telling us its contract — far better
    evidence than any guess, so those shapes jump the queue.
    """
    fields: List[str] = []

    detail = parsed.get("detail") if isinstance(parsed, dict) else None
    if isinstance(detail, list):
        for item in detail:
            loc = item.get("loc") if isinstance(item, dict) else None
            if isinstance(loc, list) and loc and str(loc[0]).lower() == "body" and len(loc) > 1:
                seg = [str(x) for x in loc[1:] if not str(x).isdigit()]
                if seg:
                    fields.append(".".join(seg))

    for pat in (r"['\"`]([A-Za-z_][A-Za-z0-9_]{1,30})['\"`][^.]{0,40}(?:is )?required",
                r"required (?:property|field|parameter)[: ]+['\"`]?([A-Za-z_][A-Za-z0-9_]{1,30})",
                r"missing (?:required )?(?:field|parameter|property)[: ]+['\"`]?([A-Za-z_][A-Za-z0-9_]{1,30})"):
        for m in re.finditer(pat, body_text or "", re.I):
            fields.append(m.group(1))

    out, seen = [], set()
    for f in fields:
        if f.lower() in ("model", "stream", "temperature") or f in seen:
            continue
        seen.add(f)
        body: Any = PROMPT_TOKEN
        for key in reversed(f.split(".")):
            body = {key: body}
        out.append(Shape(f"error_hint:{f}", "POST", body=body))
        if len(out) >= 3:
            break
    return out


# --------------------------------------------------------------------------- #
# Response understanding                                                       #
# --------------------------------------------------------------------------- #
def score_answer(path: str, value: str, prompt: str) -> float:
    """Score how much ``value`` looks like a bot's natural-language answer.

    Returns a negative score for anything disqualified: an echo of our own
    prompt, an id/timestamp/status token, a URL, markup, or an empty string.
    Higher is better; :data:`MIN_ANSWER_SCORE` is the acceptance bar.
    """
    v = (value or "").strip()
    if len(v) < 2:
        return -1.0
    nv, np_ = _norm(v), _norm(prompt)
    if nv == np_ or (np_ and nv in np_):
        return -1.0                                   # echo / fragment of our prompt
    if nv in _NON_ANSWER_TOKENS:
        return -1.0
    if _UUID_RE.match(v) or _HEXY_RE.match(v) or _TS_RE.match(v) or _NUMERIC_RE.match(v):
        return -1.0
    if _URLISH_RE.match(v) or _MIME_RE.match(v) or _MARKUP_RE.match(v):
        return -1.0

    leaf = (path.rsplit(".", 1)[-1] if path else "").lower()
    if leaf in _ID_LEAF_KEYS and len(v) < 80:
        return -1.0

    score = min(len(v), 400) / 100.0
    if " " in v:
        score += 1.5
    if len(v.split()) >= 4:
        score += 0.5
    if v[-1:] in ".!?":
        score += 0.5
    if leaf in _ANSWER_LEAF_KEYS:
        score += 1.5 - 0.05 * _ANSWER_LEAF_KEYS.index(leaf)
    if np_ and np_ in nv:
        score -= 1.0                                  # quotes us back, plus extra

    # --- STABILITY -----------------------------------------------------------------
    # A path is only useful if it points at the same thing on the NEXT call. Debug/trace
    # envelopes are the trap: an agent that returns {"message": …, "trace": [85 steps]} often
    # contains longer prose deep inside the trace, which used to outscore the real field and
    # produce a config keyed to something like `trace.92.messages.1.content` — an index that
    # does not exist on the next request, so the config validates once and then breaks.
    parts = [p for p in (path or "").split(".") if p]
    if any(p.lower() in _VOLATILE_CONTAINERS for p in parts):
        score -= 4.0                                  # inside a debug/trace/log envelope
    deep_index = sum(1 for p in parts if p.isdigit())
    score -= 0.75 * deep_index                        # every array index is a stability risk
    score -= 0.25 * max(0, len(parts) - 1)            # prefer shallow, top-level fields
    return score


def _is_error_envelope(parsed: Any) -> Optional[str]:
    """Return a reason string when the JSON body is an error envelope."""
    if not isinstance(parsed, dict):
        return None
    err = parsed.get("error") or parsed.get("errors")
    if err:
        if isinstance(err, dict):
            msg = err.get("message") or err.get("detail") or json.dumps(err)[:160]
        else:
            msg = str(err)[:160]
        return f"error envelope: {msg}"
    for key in ("success", "ok", "isSuccess"):
        if parsed.get(key) is False:
            return f"envelope reports {key}=false"
    if isinstance(parsed.get("detail"), (str, list)) and len(parsed) <= 2:
        return f"error envelope: {json.dumps(parsed.get('detail'))[:160]}"
    return None


def _split_sse_payloads(body: str) -> List[str]:
    """Pull the ``data:`` payloads out of an SSE body (one entry per event).

    Per the SSE spec, consecutive ``data:`` lines belong to ONE event and are
    joined with a newline; a blank line terminates the event.
    """
    payloads, cur = [], []
    for line in (body or "").splitlines():
        if not line.strip():
            if cur:
                payloads.append("\n".join(cur))
                cur = []
            continue
        if line.startswith(":"):          # comment / keepalive
            continue
        if line.startswith("data:"):
            cur.append(line[5:].lstrip())
    if cur:
        payloads.append("\n".join(cur))
    return payloads


def _expand_payloads(payloads: List[str]) -> List[str]:
    """Split a blob that is really several frames back into individual frames.

    Not every server emits the blank line between SSE events. Without this, a
    whole stream collapses into one un-parseable payload and gets mistaken for a
    single bare-text delta — so a payload that is not JSON, but whose lines each
    ARE JSON, is expanded back into one payload per line.
    """
    out: List[str] = []
    for p in payloads:
        s = (p or "").strip()
        if not s:
            continue
        try:
            json.loads(s)
            out.append(s)
            continue
        except (ValueError, TypeError, RecursionError):
            pass
        lines = [l.strip() for l in s.splitlines() if l.strip()]
        if len(lines) > 1:
            expanded = []
            for l in lines:
                try:
                    json.loads(l)
                except (ValueError, TypeError):
                    expanded = []
                    break
                expanded.append(l)
            if expanded:
                out.extend(expanded)
                continue
        out.append(s)
    return out


def _frame_text(frame: Any) -> Tuple[Optional[str], Optional[str]]:
    """Best (text, dot_path) inside one stream frame, or ``(None, None)``."""
    if isinstance(frame, str):
        return (frame, None) if frame.strip() else (None, None)
    best: Optional[Tuple[int, str, str]] = None
    for path, val in string_paths(frame):
        leaf = path.rsplit(".", 1)[-1].lower()
        if leaf in _ID_LEAF_KEYS and leaf not in ("text", "content", "message", "delta"):
            continue
        if leaf not in _STREAM_TEXT_KEYS:
            continue
        rank = _STREAM_TEXT_KEYS.index(leaf)
        if val == "":
            continue
        if best is None or rank < best[0]:
            best = (rank, path, val)
    return (best[2], best[1]) if best else (None, None)


def _assemble_stream(payloads: List[str], fmt: str) -> Tuple[str, Dict[str, Any]]:
    """Concatenate a stream's token frames into one answer + adapter hints.

    Returns ``(text, hints)`` where hints are ready for ``sse_stream``'s
    ``stream`` block (format/text_path/token_types/done_when) — derived from what
    the frames actually contained, not from a vendor guess.
    """
    chunks: List[str] = []
    text_paths: Dict[str, int] = {}
    token_types: List[str] = []
    done_when: Optional[Dict[str, Any]] = None

    for payload in _expand_payloads(payloads):
        p = payload.strip()
        if not p:
            continue
        if p in _DONE_SENTINELS:
            done_when = {"contains": p}
            break
        try:
            frame = json.loads(p)
        except (ValueError, TypeError):
            chunks.append(payload)          # bare text delta
            continue
        ftype = frame.get("type") if isinstance(frame, dict) else None
        if isinstance(ftype, str) and ftype.lower() in _DONE_TYPES:
            done_when = {"path": "type", "equals": ftype}
            break
        text, path = _frame_text(frame)
        if text:
            chunks.append(text)
            if path:
                text_paths[path] = text_paths.get(path, 0) + 1
            if isinstance(ftype, str) and ftype not in token_types:
                token_types.append(ftype)

    hints: Dict[str, Any] = {"format": fmt}
    if text_paths:
        hints["text_path"] = max(text_paths.items(), key=lambda kv: kv[1])[0]
    if token_types:
        hints["token_types"] = token_types
    if done_when:
        hints["done_when"] = done_when
    return "".join(chunks), hints


# Conversation/job-oriented ids — a bare "id" is intentionally NOT here (too generic; a
# completed {"status":"ok","id":<uuid>} ack is not an async agent). Bare id counts only
# alongside a pending status (below).
_ACK_ID_KEYS = ("conversationid", "conversation_id", "messageid", "message_id",
                "threadid", "thread_id", "jobid", "job_id", "requestid", "request_id",
                "runid", "run_id", "taskid", "task_id")
_PENDING_STATES = {"queued", "processing", "pending", "running", "accepted",
                   "in_progress", "in-progress", "started", "submitted"}


def _looks_like_async_ack(parsed: Any) -> Optional[str]:
    """A POST that returns just an id/ack (and no answer prose) is an async POST-then-GET
    agent: the reply is fetched from a follow-up history/result GET (the session_poll pattern).
    Returns the id string when it looks like an ack, else None."""
    if not isinstance(parsed, dict):
        return None
    lower = {str(k).lower(): v for k, v in parsed.items()}
    longest = max((len(s) for _, s in string_paths(parsed)), default=0)
    if longest >= 40:                      # a real answer is longer prose, not just ids/statuses
        return None
    for k in _ACK_ID_KEYS:
        v = lower.get(k)
        if isinstance(v, (str, int)) and str(v).strip():
            return str(v)
    # a bare id only counts when paired with a pending status
    status = str(lower.get("status") or lower.get("state") or "").lower()
    idv = lower.get("id")
    if isinstance(idv, (str, int)) and str(idv).strip() and status in _PENDING_STATES:
        return str(idv)
    return None


def _understand_response(body: str, content_type: str, prompt: str
                         ) -> Tuple[Optional[str], Optional[str], Optional[str], Dict[str, Any], str]:
    """Work out WHERE the answer is in a 2xx body.

    Returns ``(transport, response_path, answer, stream_hints, reason)``.
    ``answer`` is None when the body is not a chat answer at all — ``reason``
    then says why (empty / echo / error envelope / no answer-like value), which
    is what keeps a 200 from being mistaken for success.
    """
    ct = (content_type or "").lower()
    raw = body or ""
    if not raw.strip():
        return None, None, None, {}, "empty body"

    # --- streamed transports -------------------------------------------------
    is_sse = "text/event-stream" in ct or raw.lstrip().startswith("data:")
    lines = [l for l in raw.splitlines() if l.strip()]
    is_ndjson = ("ndjson" in ct or "jsonlines" in ct or "x-ndjson" in ct)
    if not is_sse and not is_ndjson and len(lines) >= 2:
        parsed_ok = 0
        for l in lines[:5]:
            try:
                json.loads(l)
                parsed_ok += 1
            except (ValueError, TypeError):
                parsed_ok = 0
                break
        is_ndjson = parsed_ok >= 2

    if is_sse or is_ndjson:
        fmt = "sse" if is_sse else "ndjson"
        payloads = _split_sse_payloads(raw) if is_sse else lines
        text, hints = _assemble_stream(payloads, fmt)
        if not text.strip():
            return fmt, None, None, hints, f"{fmt} stream carried no text frames"
        if score_answer(hints.get("text_path", ""), text, prompt) < 0:
            return fmt, None, None, hints, f"{fmt} stream only echoed the prompt / status frames"
        return fmt, hints.get("text_path"), text, hints, ""

    # --- single JSON body ----------------------------------------------------
    parsed: Any = None
    if raw.lstrip()[:1] in ("{", "["):
        try:
            parsed = json.loads(raw)
        except (ValueError, TypeError):
            parsed = None

    if parsed is not None:
        env = _is_error_envelope(parsed)
        candidates = [(score_answer(p, v, prompt), p, v) for p, v in string_paths(parsed)]
        candidates = [c for c in candidates if c[0] >= MIN_ANSWER_SCORE]
        if not candidates:
            ack = _looks_like_async_ack(parsed)
            if ack and not env:
                return "rest_json", None, None, {"async_ack": ack}, (
                    f"the POST was accepted (id {ack!r}) but carried no answer — this is an "
                    "async POST-then-GET agent; fetch the reply from the history/result "
                    "endpoint with the session_poll adapter")
            return "rest_json", None, None, {}, env or "no answer-like string in the JSON body"
        if env:
            # An envelope that says error=… but also carries prose: trust the flag.
            return "rest_json", None, None, {}, env
        best = max(candidates, key=lambda c: c[0])
        # `max` picks ONE string, so a multi-block answer comes back as whichever block happens to
        # score highest and the rest is silently discarded on every request. Generalize the index
        # to a `*` when the siblings are parts of the same message. This IMPORTS the rule rather
        # than restating it: probing and classification already derive the answer path separately,
        # and every place those two have disagreed this release has produced a config that passed
        # every gate and measured nothing.
        from .classify import _generalize_block_index
        rpath = _generalize_block_index(parsed, best[1]) if best[1] else best[1]
        if rpath != best[1]:
            from adapters.direct_api import _extract as _x
            joined = _x(parsed, rpath)
            if isinstance(joined, str) and joined.strip():
                return "rest_json", rpath, joined, {}, ""
        return "rest_json", best[1], best[2], {}, ""

    # --- plain text ----------------------------------------------------------
    if _MARKUP_RE.match(raw) or "text/html" in ct:
        return None, None, None, {}, "HTML page, not an API response"
    if score_answer("", raw.strip(), prompt) < 0:
        return "text", None, None, {}, "plain body is an echo/status token, not an answer"
    return "text", None, raw.strip(), {}, ""


# --------------------------------------------------------------------------- #
# HTTP plumbing (lazy import so nothing hits the network at import time)        #
# --------------------------------------------------------------------------- #
def _classify_transport_error(exc: Exception) -> Tuple[str, str]:
    """Map a ``requests`` exception to ``(outcome, human detail)``.

    Telling DNS from refused from TLS is the whole point of the failure path —
    "host is down" and "path is wrong" need completely different next steps.
    """
    import requests  # lazy

    text = f"{type(exc).__name__}: {exc}"
    low = text.lower()
    if isinstance(exc, requests.exceptions.SSLError) or "certificate" in low or "ssl" in low:
        return "tls", text
    dns_markers = ("name or service not known", "nodename nor servname",
                   "getaddrinfo failed", "nameresolutionerror", "failed to resolve",
                   "temporary failure in name resolution", "no address associated")
    if any(m in low for m in dns_markers):
        return "dns", text
    if isinstance(exc, (requests.exceptions.Timeout,)) or "timed out" in low:
        return "unreachable", text
    if isinstance(exc, requests.exceptions.ConnectionError) or "refused" in low:
        return "unreachable", text
    return "transport", text


def _read_body(resp: Any, deadline: float) -> str:
    """Read a (possibly streaming) response body up to a hard cap.

    Streamed line-by-line so an endless SSE stream cannot hang the probe, with a
    ``.text`` fallback for response objects that do not stream.
    """
    try:
        it = resp.iter_lines(decode_unicode=False)
    except (AttributeError, TypeError):
        it = None
    if it is None:
        return str(getattr(resp, "text", "") or "")

    lines: List[str] = []
    total = 0
    try:
        for raw in it:
            if raw is None:
                line = ""
            elif isinstance(raw, (bytes, bytearray)):
                line = raw.decode("utf-8", "replace")
            else:
                line = str(raw)
            lines.append(line)
            total += len(line) + 1
            if total >= _BODY_CAP_BYTES or time.monotonic() > deadline:
                break
    except Exception:  # noqa: BLE001 - a half-read body is still evidence
        pass
    finally:
        try:
            resp.close()
        except Exception:  # noqa: BLE001
            pass
    if not lines:
        # A real requests.Response has already consumed its content once iter_lines()
        # ran to exhaustion, so .text raises RuntimeError. probe_api documents that it
        # never raises for a target-side problem, so an empty 200 must read as an empty
        # body (a diagnosis), not an exception.
        try:
            return str(getattr(resp, "text", "") or "")
        except Exception:
            return ""
    return "\n".join(lines)


def _resp_headers(resp: Any) -> Tuple[Dict[str, str], List[Dict[str, str]]]:
    """Response headers as ``(lowercased dict, HAR-style list)``."""
    raw = getattr(resp, "headers", None) or {}
    try:
        items = list(raw.items())
    except AttributeError:
        items = []
    lower = {str(k).lower(): str(v) for k, v in items}
    har = [{"name": str(k), "value": str(v)} for k, v in items]
    return lower, har


# --------------------------------------------------------------------------- #
# Probe state machine                                                          #
# --------------------------------------------------------------------------- #
class _State:
    """Mutable bookkeeping for one probe run (budget, manners, evidence)."""

    def __init__(self, prompt: str, headers: Dict[str, str], timeout_s: float,
                 max_attempts: int, rate_limit_s: float, verify_tls: bool):
        self.prompt = prompt
        self.headers = dict(headers or {})
        self.timeout_s = float(timeout_s)
        self.max_attempts = int(max_attempts)
        self.rate_limit_s = max(0.0, float(rate_limit_s))
        self.verify_tls = bool(verify_tls)

        self.attempts: List[Attempt] = []
        self.pairs: List[Dict[str, Any]] = []          # normalized evidence pairs
        self.successes: List[Dict[str, Any]] = []      # winning candidates
        self.endpoint_status: Dict[str, List[int]] = {}
        # The target's own rejection body, per exact endpoint. This is the best
        # shape evidence there is ("field required: 'question'"), so it is kept
        # keyed by the exact URL — prefix matching would attribute one path's
        # error to another path that merely shares its prefix.
        self.error_bodies: Dict[str, str] = {}
        self.fivexx: Dict[str, int] = {}
        self.consecutive_auth = 0
        self.async_ack: Optional[str] = None   # POST-then-GET id seen (session_poll pattern)
        self.rate_limited = 0
        self.dns_errors = 0
        self.conn_errors = 0
        self.tls_errors = 0
        self.saw_http = False
        self.aborted: Optional[str] = None
        self._last_call = 0.0

    # -- budget / manners ---------------------------------------------------
    @property
    def exhausted(self) -> bool:
        return self.aborted is not None or len(self.attempts) >= self.max_attempts

    def _be_polite(self) -> None:
        """Sleep out the remainder of ``rate_limit_s`` since the last call."""
        if self.rate_limit_s <= 0 or self._last_call == 0.0:
            return
        wait = self.rate_limit_s - (time.monotonic() - self._last_call)
        if wait > 0:
            time.sleep(wait)

    def should_skip(self, url: str) -> bool:
        """True when this endpoint already burned its 5xx retry budget."""
        return self.fivexx.get(url, 0) >= _MAX_5XX_PER_ENDPOINT

    # -- the single request -------------------------------------------------
    def try_candidate(self, url: str, shape: Shape, *, retried: bool = False) -> Attempt:
        """Send ONE benign request and record everything we learned from it."""
        import requests  # lazy: keeps this module import-time network-free

        target = url
        params = None
        json_body = None
        data_body = None
        if shape.query_param:
            params = {shape.query_param: self.prompt}
        elif shape.raw is not None:
            data_body = shape.raw.replace(PROMPT_TOKEN, self.prompt)
        elif (shape.content_type or "").startswith("application/x-www-form-urlencoded"):
            data_body = shape.render(self.prompt)          # requests form-encodes a mapping
        else:
            json_body = shape.render(self.prompt)

        headers = dict(self.headers)
        if shape.content_type and not any(k.lower() == "content-type" for k in headers):
            headers["Content-Type"] = shape.content_type
        headers.setdefault("Accept", "application/json, text/event-stream, text/plain, */*")

        self._be_polite()
        started = time.monotonic()
        deadline = started + self.timeout_s
        try:
            resp = requests.request(
                shape.method, target, headers=headers, params=params,
                json=json_body, data=data_body, timeout=self.timeout_s,
                verify=self.verify_tls, stream=True, allow_redirects=True,
            )
        except Exception as exc:  # noqa: BLE001 - every transport failure is a diagnosis
            self._last_call = time.monotonic()
            outcome, detail = _classify_transport_error(exc)
            if outcome == "dns":
                self.dns_errors += 1
            elif outcome == "tls":
                self.tls_errors += 1
            else:
                self.conn_errors += 1
            return self._record(Attempt(url=target, method=shape.method, shape=shape.label,
                                        outcome=outcome, detail=detail,
                                        elapsed_ms=int((time.monotonic() - started) * 1000)))

        status = int(getattr(resp, "status_code", 0) or 0)
        body = _read_body(resp, deadline)
        self._last_call = time.monotonic()
        self.saw_http = True
        lower_h, har_h = _resp_headers(resp)
        ctype = lower_h.get("content-type", "")
        elapsed = int((self._last_call - started) * 1000)
        self.endpoint_status.setdefault(target, []).append(status)

        att = Attempt(url=target, method=shape.method, shape=shape.label,
                      status=status, elapsed_ms=elapsed)

        # --- status triage ----------------------------------------------------
        # A redirect that landed on an HTML sign-in page is an auth wall, not an answer. requests
        # followed it (allow_redirects=True), so the status here is the page's 200 — and that read
        # as "rejected every body shape", which sent the operator to --curl instead of to
        # credentials. Seen live against a target that answered every unauthenticated POST with
        # a 302 to /signin.
        hist = getattr(resp, "history", None) or []
        if hist and status == 200 and "text/html" in ctype and _looks_like_signin(body):
            self.consecutive_auth += 1
            landed = getattr(resp, "url", target)
            if not getattr(self, "auth_scheme", None):
                self.auth_scheme = f"a redirect to a sign-in page at {landed}"
            att.status = int(getattr(hist[0], "status_code", 302) or 302)
            att.outcome, att.detail = "auth", f"redirected to {landed} — an HTML sign-in page"
            if self.consecutive_auth >= _MAX_CONSECUTIVE_AUTH:
                self.aborted = "auth"
            return self._record(att, target, shape, json_body, data_body, params,
                                headers, status, har_h, body, ctype)
        if status in (401, 403, 407):
            self.consecutive_auth += 1
            wa = lower_h.get("www-authenticate")
            if wa and not getattr(self, "auth_scheme", None):
                # Name the actual scheme (Bearer/Basic/Negotiate + realm) instead of guessing.
                self.auth_scheme = wa.split(",")[0].strip()
            att.outcome, att.detail = "auth", f"HTTP {status} — credentials required/rejected"
            if self.consecutive_auth >= _MAX_CONSECUTIVE_AUTH:
                # Stop. Probing a wall of 401s is indistinguishable from guessing
                # credentials, and we do not do that.
                self.aborted = "auth"
            return self._record(att, target, shape, json_body, data_body, params,
                                headers, status, har_h, body, ctype)
        self.consecutive_auth = 0

        if status == 429:
            self.rate_limited += 1
            att.outcome, att.detail = "rate_limited", "HTTP 429 — target is rate limiting us"
            if self.rate_limited >= _MAX_RATE_LIMITED:
                self.aborted = "rate_limited"
            self._record(att, target, shape, json_body, data_body, params,
                         headers, status, har_h, body, ctype)
            # One 429 on the real endpoint sent the probe on to nineteen other paths and a
            # "not found" verdict. Wait what the target asked (bounded) and try THIS candidate
            # once more; a second 429 stands and counts toward the abort.
            if not retried and not self.aborted:
                try:
                    wait = min(max(float(lower_h.get("retry-after") or 2), 0.5), 10.0)
                except ValueError:
                    wait = 2.0
                time.sleep(wait)
                return self.try_candidate(url, shape, retried=True)
            return att

        if status >= 500:
            self.fivexx[target] = self.fivexx.get(target, 0) + 1
            att.outcome = "server_error"
            att.detail = f"HTTP {status} — {body.strip()[:160] or 'no body'}"
            return self._record(att, target, shape, json_body, data_body, params,
                                headers, status, har_h, body, ctype)

        if status in (404, 410):
            att.outcome, att.detail = "not_found", f"HTTP {status} — no such path"
            return self._record(att, target, shape, json_body, data_body, params,
                                headers, status, har_h, body, ctype)

        if status in (405, 501):
            att.outcome = "method_not_allowed"
            att.detail = f"HTTP {status} — path exists but not for {shape.method}"
            return self._record(att, target, shape, json_body, data_body, params,
                                headers, status, har_h, body, ctype)

        if 400 <= status < 500:
            att.outcome = "shape_rejected"
            att.detail = f"HTTP {status} — path exists, body rejected: {body.strip()[:160]}"
            self.error_bodies[target] = body[:4000]
            return self._record(att, target, shape, json_body, data_body, params,
                                headers, status, har_h, body, ctype)

        if not (200 <= status < 300):
            att.outcome, att.detail = "no_answer", f"HTTP {status}"
            return self._record(att, target, shape, json_body, data_body, params,
                                headers, status, har_h, body, ctype)

        # --- 2xx: does it actually contain an ANSWER? -------------------------
        transport, rpath, answer, hints, reason = _understand_response(body, ctype, self.prompt)
        att.transport = transport
        if answer is None:
            att.outcome = "no_answer"
            att.detail = f"HTTP {status} but {reason}"
            if hints.get("async_ack") and not self.async_ack:
                self.async_ack = hints["async_ack"]
            self.error_bodies[target] = body[:4000]
            return self._record(att, target, shape, json_body, data_body, params,
                                headers, status, har_h, body, ctype)

        att.ok = True
        att.outcome = "answer"
        att.response_path = rpath
        att.answer_preview = answer[:_ANSWER_PREVIEW]
        att.detail = f"HTTP {status} — answered {len(answer)} chars"
        rec = self._record(att, target, shape, json_body, data_body, params,
                           headers, status, har_h, body, ctype)
        self.successes.append({
            "url": target, "shape": shape, "method": shape.method,
            "transport": transport, "response_path": rpath, "answer": answer,
            "stream_hints": hints, "score": score_answer(rpath or "", answer, self.prompt),
            "pair": self.pairs[-1] if self.pairs else None,
            "headers": headers,
        })
        return rec

    # -- evidence -----------------------------------------------------------
    def _record(self, att: Attempt, url: Optional[str] = None, shape: Optional[Shape] = None,
                json_body: Any = None, data_body: Optional[str] = None,
                params: Optional[Dict[str, str]] = None, headers: Optional[Dict[str, str]] = None,
                status: Optional[int] = None, resp_headers: Optional[List[Dict[str, str]]] = None,
                body: str = "", ctype: str = "") -> Attempt:
        """Append the attempt and, when there was a real exchange, an evidence pair."""
        self.attempts.append(att)
        if url is None or status is None:
            return att
        full = url
        if params:
            qs = "&".join(f"{k}={quote(str(v), safe='')}" for k, v in params.items())
            full = url + ("&" if "?" in url else "?") + qs
        raw_req = None
        if json_body is not None:
            raw_req = json.dumps(json_body)
        elif data_body is not None:
            raw_req = data_body
        resp_h = list(resp_headers or [])
        if ctype and not any(h["name"].lower() == "content-type" for h in resp_h):
            resp_h.append({"name": "Content-Type", "value": ctype})
        self.pairs.append({
            "request": {
                "method": (shape.method if shape else att.method),
                "url": full,
                "headers": [{"name": k, "value": v} for k, v in (headers or {}).items()],
                "raw_body": raw_req,
            },
            "response": {
                "status": status,
                "headers": resp_h,
                "raw_body": body,
            },
        })
        return att


# --------------------------------------------------------------------------- #
# Diagnosis                                                                    #
# --------------------------------------------------------------------------- #
def _live_score(statuses: List[int]) -> int:
    """How strongly an endpoint's statuses say "this path is real"."""
    best = -1
    for s in statuses:
        if s in (400, 409, 413, 415, 422):
            best = max(best, 100)      # it parsed our request and disliked the BODY
        elif 200 <= s < 300:
            best = max(best, 80)       # answered, just not with an answer
        elif s in (405, 501):
            best = max(best, 70)       # wrong verb
        elif s in (401, 403, 407):
            best = max(best, -1)       # auth wall: more shapes will not help
        elif s >= 500:
            best = max(best, 10)
    return best


def _diagnose(state: _State, host: str, tried: List[str]) -> Tuple[str, str, str]:
    """Turn the attempt log into ``(diagnosis, message, hint)``.

    Every branch answers two questions: what happened, and what do I do next.
    """
    tried_str = ", ".join(tried[:8]) + (f" (+{len(tried) - 8} more)" if len(tried) > 8 else "")

    if state.aborted == "rate_limited" or state.rate_limited >= _MAX_RATE_LIMITED:
        return ("rate_limited",
                f"{host} returned HTTP 429 {state.rate_limited}x — the probe stopped to avoid "
                f"hammering a rate-limited target.",
                "Re-run with a slower rate (rate_limit_s=2.0 or more) and a smaller "
                "max_attempts, or ask the owner to allow-list the probe source IP.")

    if not state.saw_http:
        if state.tls_errors:
            return ("tls",
                    f"TLS handshake to {host} failed (certificate not trusted or hostname mismatch).",
                    "Confirm with verify_tls=False (CLI: --insecure). If that works it is a cert "
                    "problem, not a bot problem: install the corporate CA "
                    "(REQUESTS_CA_BUNDLE=/path/ca.pem) or use the hostname on the certificate.")
        if state.dns_errors >= max(1, state.conn_errors):
            return ("dns",
                    f"Hostname {host!r} does not resolve from this machine.",
                    f"Check the spelling, then `nslookup {host}`. If it is an internal host, "
                    "connect the VPN / run the probe from inside the customer network.")
        return ("unreachable",
                f"{host} resolves but refused or timed out on every connection attempt.",
                "Check egress to that host:port (firewall/SASE), any proxy "
                "(HTTPS_PROXY / TLS interception), and that the service is actually listening. "
                "A `curl -v` from the same machine will confirm.")

    if state.aborted == "auth":
        scheme = getattr(state, "auth_scheme", None)
        scheme_line = f" The server asked for: {scheme}." if scheme else ""
        if scheme and scheme.lower().startswith("basic"):
            rerun = "re-run with --basic '<user>:<pass>'"
        elif scheme and scheme.lower().startswith("bearer"):
            rerun = "re-run with --bearer '<token>'"
        else:
            rerun = ("re-run with --bearer '<token>' | --api-key 'x-api-key:<key>' | "
                     "--basic '<user>:<pass>' | --cookie '<name>=<value>'")
        # Every flag named below now exists on `target add` as well as `adapter build`. It did
        # not: this hint recommended --basic, --cookie and --login-* while `target add`'s parser
        # registered none of them, so following the CLI's own printed advice on the command the
        # docs make step one returned `unrecognized arguments`.
        return ("auth_required",
                f"{host} is up and the paths exist, but every request was rejected with "
                f"401/403.{scheme_line} The probe stopped rather than keep knocking.",
                f"Supply credentials and {rerun}.\n"
                "  a login that mints a token:  --login-url URL --login-body "
                "'grant_type=client_credentials&client_id=…' --token-path access_token\n"
                "  a page that sets a session:  --login-url URL --login-method GET\n"
                "  a CSRF token in the HTML:    --login-url URL --login-method GET "
                "--token-regex 'csrf-token\" content=\"([^\"]+)' --token-header X-CSRF-Token\n"
                "  (--header 'Authorization: Bearer <token>' also works.)\n"
                "  If the target SIGNS each request (HMAC / X-Signature) or needs a fresh nonce, "
                "no flag can express that — the credential is computed per request. Write a small "
                "adapter instead:  ascend target add <url> --scaffold mybot.py")

    statuses = [s for lst in state.endpoint_status.values() for s in lst]
    auth_hits = [s for s in statuses if s in (401, 403, 407)]
    live = {u: _live_score(v) for u, v in state.endpoint_status.items()}
    alive = [u for u, sc in live.items() if sc >= 70]

    if getattr(state, "async_ack", None):
        return ("async_poll",
                f"{host} accepted the POST and returned an id ({state.async_ack!r}) but no "
                "inline answer — an async POST-then-GET agent.",
                "The reply is fetched from a history/result endpoint. Use the session_poll "
                "adapter: create -> send -> poll the transcript URL (watermark on new turns). "
                "Capture one full round-trip (send + the GET that returns the reply) with "
                "--har, or point --api at the history endpoint.")

    if statuses and all(s >= 500 for s in statuses):
        return ("server_error",
                f"Every request to {host} returned 5xx — the target is failing, not the probe.",
                "Nothing to fix on our side: send the owner the timestamps and one of the 5xx "
                "bodies from result.attempts, then re-run once it is healthy.")

    if auth_hits and not alive:
        scheme = getattr(state, "auth_scheme", None)
        scheme_line = f" The server asked for: {scheme}." if scheme else ""
        return ("auth_required",
                f"{host} answered {len(auth_hits)} request(s) with "
                f"{sorted(set(auth_hits))} — the endpoint is behind auth.{scheme_line}",
                "Supply credentials and re-run with --bearer '<token>' | "
                "--api-key 'x-api-key:<key>' | --basic '<user>:<pass>' | "
                "--cookie '<name>=<value>'. For an access code or passcode in a header, use "
                "--header 'x-demo-key: <code>'; for one the target expects in the request BODY, "
                "use --body-field 'apiKey=<key>' (repeatable, and it can be combined with the "
                "others — a gated target commonly wants one credential in a header AND another "
                "in the body). For a login flow, use --login-url + --login-body + --token-path.")

    if alive:
        worst = sorted(alive, key=lambda u: -live[u])[0]
        last = next((a for a in reversed(state.attempts)
                     if a.url == worst and a.detail), None)
        detail = (last.detail if last else "") or ""
        graphql = (worst.rstrip("/").endswith("/graphql") or 'Variable "$' in detail
                   or "GraphQL" in detail)
        hint = ("Send one working request example — `--curl 'curl -X POST … -d {…}'` — or the "
                "field name it expects. The probe replays it verbatim and derives the rest.")
        if graphql:
            hint = ("This is a GraphQL endpoint, and the probe cannot guess the operation. Paste "
                    "one working query as a curl with the prompt in the variables, for example "
                    "--curl \"curl -X POST <url> -H 'content-type: application/json' -d "
                    "'{\\\"query\\\":\\\"mutation($input:MessageInput!){send(input:$input){reply}}\\\","
                    "\\\"variables\\\":{\\\"input\\\":{\\\"message\\\":\\\"hello\\\"}}}'\"; "
                    "the reply field becomes the answer path.")
        return ("bad_shape",
                f"{worst} is a real endpoint (it responded, it is not a 404) but rejected every "
                f"request body shape tried. Last response: {detail[:200]}", hint)

    # A path that answered 2xx WITHOUT an answer is the signature of a create-then-message
    # contract (POST /conversations -> id, then message that id). A single URL cannot express
    # it, and the generic "give the full path" advice sends the operator in circles.
    created = [a for a in state.attempts
               if a.status in (200, 201, 202) and a.outcome in ("no_answer", "empty", "error_envelope")]
    if created:
        return ("not_found",
                f"{host} is UP and {created[0].url} answered HTTP {created[0].status} without an "
                f"answer — that is what a create-then-message contract looks like (create a "
                f"conversation or session first, then send the prompt to it).",
                "Export a HAR of one real exchange from the browser and pass --har <file> — the "
                "two-step contract is derived from it — or write the two calls yourself: "
                "`ascend target add --scaffold ./my_adapter.py`, then `--module ./my_adapter.py`.")
    limited = [a.url for a in state.attempts if a.outcome == "rate_limited"]
    if limited:
        return ("rate_limited",
                f"{limited[0]} answered HTTP 429 — the target is rate limiting this client, and "
                f"no other candidate path answered.",
                "Wait, then re-run; or ask the owner for the probe's allow-list / a higher limit. "
                "The probe already retried once after Retry-After.")
    return ("not_found",
            f"{host} is UP (it answered {len(statuses)} request(s)) but none of the "
            f"{len(tried)} candidate paths behaved like a chat endpoint. Tried: {tried_str}",
            "Give the FULL endpoint path instead of the base URL, or paste a working `curl` "
            "example. If the bot is only reachable through its web UI, fall back to "
            "`discover --url` (browser capture) or a HAR.")


# --------------------------------------------------------------------------- #
# The probe                                                                    #
# --------------------------------------------------------------------------- #
def probe_api(url: str,
              *,
              prompt: str = DEFAULT_PROMPT,
              headers: Optional[Dict[str, str]] = None,
              method: Optional[str] = None,
              timeout_s: float = 20.0,
              max_attempts: int = 40,
              rate_limit_s: float = 0.3,
              verify_tls: bool = True,
              paths: Optional[Sequence[str]] = None,
              bodies: Optional[Sequence[Any]] = None,
              extra_body: Optional[Dict[str, Any]] = None) -> ProbeResult:
    """Find a chat API's contract from a URL alone, by trying it.

    Two bounded phases, both sequential and rate-limited:

    1. **Path sweep** — one request per candidate URL (caller's URL first) using
       the single most likely body shape for that path. This answers "which path
       is real?" and simultaneously separates "host down" from "path wrong".
       It short-circuits as soon as the caller's OWN url either answers or
       proves it is a real handler (400/415/422/405) — they told us the endpoint,
       so there is nothing left to disambiguate. Otherwise the sweep runs to
       completion, so that two endpoints answering can be reported as
       ``ambiguous`` instead of silently picking one.
    2. **Shape discovery** — only if nothing answered: for the endpoints that
       proved they exist (400/422/415 = "your body is wrong", 405 = "wrong
       verb", 2xx-without-an-answer), walk the remaining body templates, putting
       any field name the target's own error message revealed at the front.

    Args:
        url: full endpoint, or a base/parent URL to search under.
        prompt: the one benign prompt to send. Keep it innocuous.
        headers: auth and any other headers, sent on every request as given.
        method: pin the HTTP verb (default: POST shapes, plus GET query shapes).
        timeout_s: per-request budget.
        max_attempts: hard ceiling on total requests sent to the target.
        rate_limit_s: minimum spacing between requests.
        verify_tls: set False only to *diagnose* a suspected cert problem.
        paths: extra candidate paths, tried before the built-in list.
        bodies: extra body templates (dicts with ``{{PROMPT}}``, or a raw string),
            tried before the built-in list.

    Returns:
        :class:`ProbeResult`. ``ok`` is True only when a real answer came back;
        otherwise ``diagnosis``/``message``/``hint`` say what to do next.
        Never raises for a target-side problem — a failure is a diagnosis.

    Note:
        ``result.evidence`` is written for :func:`classify.classify_evidence`,
        which finds the chat call by looking for the prompt in the request BODY.
        For a GET/query-parameter target the prompt is in the URL instead, so
        prefer :func:`build_config` for those (the probe already knows the whole
        contract; the classifier adds nothing it can see).
    """
    result = ProbeResult(prompt=prompt, headers=dict(headers or {}), timeout_s=timeout_s)
    try:
        _origin, given_path, _q, host = _split_url(url)
    except ValueError as exc:
        result.diagnosis = "dns"
        result.message = f"{exc}. A probe needs an absolute URL like https://host/path."
        result.hint = "Pass the URL the customer gave you, including scheme and host."
        return result

    state = _State(prompt, headers or {}, timeout_s, max_attempts, rate_limit_s, verify_tls)
    shapes = default_shapes(method, bodies, extra_body=extra_body)

    # Leave room for phase 2: half the budget for breadth, half for depth.
    sweep_cap = max(6, max_attempts // 2)
    endpoints = candidate_endpoints(url, paths, limit=sweep_cap)
    caller_url = endpoints[0] if given_path.strip("/") else None
    result.tried_urls = list(endpoints)

    # ---------------- phase 1: which path is real? ----------------
    for ep in endpoints:
        if state.exhausted:
            break
        if state.should_skip(ep):
            continue
        ordered = _reorder_for_path(ep, shapes)
        if not ordered:
            break
        att = state.try_candidate(ep, ordered[0])
        # The caller's own URL is the strongest signal there is. When it refuses the plainest JSON
        # body, try the form-encoded one on it BEFORE sweeping other paths: three 403s across the
        # sweep trip the politeness abort, and a form-posting target then never got its one
        # chance (phase 2, where shapes are tried, is never reached).
        if (ep == caller_url and not state.successes and not state.exhausted
                and att.outcome == "auth"):
            form = next((sh for sh in ordered if sh.label == "form_message"), None)
            if form is not None:
                state.try_candidate(ep, form)
        if ep == caller_url:
            if att.ok:
                break                  # they gave us the endpoint and it works
            if att.outcome in ("shape_rejected", "method_not_allowed"):
                # The server parsed our request against a REAL handler and told us
                # the body/verb is wrong. The path question is settled — stop
                # knocking on 20 other doors and go straight to shape discovery.
                break
        if len(state.successes) >= 3:
            break                      # enough to declare ambiguity; stop knocking

    # ---------------- phase 2: which body shape does it want? ----------------
    if not state.successes and not state.exhausted:
        live = sorted(
            ((u, _live_score(s)) for u, s in state.endpoint_status.items()),
            key=lambda kv: -kv[1],
        )
        live = [(u, sc) for u, sc in live if sc >= 70][:_MAX_PHASE2_ENDPOINTS]
        for ep, _sc in live:
            if state.exhausted or state.successes:
                break
            tried_labels = {a.shape for a in state.attempts if a.url == ep}
            # The target's own validation error is better evidence than our list.
            body_text = state.error_bodies.get(ep, "")
            try:
                parsed = json.loads(body_text) if body_text else None
            except (ValueError, TypeError):
                parsed = None
            hinted: List[Shape] = _shapes_from_error(body_text, parsed)
            queue = hinted + [s for s in _reorder_for_path(ep, shapes)
                              if s.label not in tried_labels]
            seen_labels = set()
            for shape in queue:
                if state.exhausted or state.successes:
                    break
                if shape.label in seen_labels or state.should_skip(ep):
                    continue
                seen_labels.add(shape.label)
                state.try_candidate(ep, shape)

    result.attempts = state.attempts

    # ---------------- outcome ----------------
    if state.successes:
        best = max(state.successes, key=lambda s: (s["url"] == caller_url, s["score"]))
        shape: Shape = best["shape"]
        distinct = sorted({s["url"] for s in state.successes})

        result.endpoint = best["url"]
        result.method = best["method"]
        result.request_body = shape.body if shape.body is not None else shape.raw
        if (shape.body is not None and shape.content_type
                and not shape.content_type.startswith("application/json")):
            # The adapter encodes the body from the config's Content-Type, so the winning
            # shape's encoding has to travel with the template or the run sends JSON.
            result.headers = {**(result.headers or {}), "Content-Type": shape.content_type}
        result.shape_label = shape.label
        result.response_path = best["response_path"]
        result.response_text = best["answer"]
        result.transport = best["transport"]
        result.stream_hints = best["stream_hints"]
        result.alternatives = [u for u in distinct if u != best["url"]]
        # Success evidence is JUST the winning exchange: classify picks its chat
        # pair by "the request whose body contains the prompt", and every failed
        # attempt contains it too — feeding them all in would invite a wrong pick.
        result.evidence = {
            "pairs": [best["pair"]] if best["pair"] else [],
            "ws_messages": [],
            "prompt_sent": prompt,
            "reply_text": best["answer"],
            "url": best["url"],
        }

        if len(distinct) > 1 and best["url"] != caller_url:
            result.ok = False
            result.diagnosis = "ambiguous"
            result.message = (
                f"{len(distinct)} endpoints answered the same prompt: {', '.join(distinct)}. "
                f"The best-scoring one ({best['url']}) is reported above, but only you can say "
                "which is the system under test.")
            result.hint = ("Re-run the probe with the exact endpoint URL (or paths=['<path>']) "
                           "to pin it, then validate before assessing.")
        else:
            result.ok = True
            result.diagnosis = "ok"
            where = f"response_path={result.response_path!r}" if result.response_path else "body is the answer"
            result.message = (
                f"{result.method} {result.endpoint} answered with "
                f"{len(result.response_text or '')} chars ({result.transport}, {where}) "
                f"using the {shape.label!r} body shape, after {len(state.attempts)} attempt(s).")
            result.hint = ("Validate before assessing: build_config(result) -> "
                           "validate_config(cfg['adapter'], cfg, prompt). Or feed "
                           "result.evidence to classify_evidence() for full six-layer "
                           "classification (auth/session/rate).")
        return result

    diagnosis, message, hint = _diagnose(state, host, result.tried_urls)
    result.diagnosis, result.message, result.hint = diagnosis, message, hint
    # On failure the evidence is the whole attempt log — forensics, not a config.
    result.evidence = {
        "pairs": state.pairs[:20],
        "ws_messages": [],
        "prompt_sent": prompt,
        "reply_text": None,
        "url": url,
    }
    return result


# --------------------------------------------------------------------------- #
# Config emission                                                              #
# --------------------------------------------------------------------------- #
def _sentinel_of(result):
    """Is this response a marker-framed stream? Returns the classification, or None.

    Reuses discovery.classify._detect_sentinel — the same detector the HAR path uses — so a
    target produces the same adapter whether it was discovered from a capture or probed live.
    """
    text = getattr(result, "response_text", None)
    if not text or (result.transport or "") in ("sse", "ndjson"):
        return None
    try:
        from . import classify
        sent = classify._detect_sentinel(text)
    except Exception:
        return None
    if not sent:
        return None
    # Pull the reply path out of a frame so the adapter extracts the ANSWER, not the frame.
    try:
        sent["extract"] = _sentinel_extract(text, sent["params"]["begin_marker"],
                                            sent["params"]["end_marker"])
    except Exception:
        pass
    return sent


def _sentinel_extract(text, begin, end):
    """Best-effort map of where the agent's text sits inside the framed JSON."""
    import re as _re
    frames = _re.findall(_re.escape(begin) + r"(.*?)" + _re.escape(end), text, _re.S)
    for f in frames:
        try:
            obj = json.loads(f.strip())
        except Exception:
            continue
        # look for a list of events carrying {author, text}-ish entries
        for key, val in (obj.items() if isinstance(obj, dict) else []):
            if isinstance(val, dict):
                for k2, v2 in val.items():
                    if isinstance(v2, list) and v2 and isinstance(v2[0], dict):
                        keys = set(v2[0])
                        if {"text"} & keys or {"message"} & keys:
                            return {"events_path": f"{key}.{k2}",
                                    "message_path": "message" if "message" in keys else "",
                                    "text_field": "text"}
            if isinstance(val, list) and val and isinstance(val[0], dict):
                keys = set(val[0])
                if {"text"} & keys or {"message"} & keys:
                    return {"events_path": key,
                            "message_path": "message" if "message" in keys else "",
                            "text_field": "text"}
    return {}


def build_config(result: ProbeResult, *, timeout_ms: Optional[int] = None) -> Dict[str, Any]:
    """Turn a successful probe into a runnable adapter config.

    Shortcut around :func:`classify.classify_evidence`: the probe already proved
    the endpoint, verb, body template and answer path, so for a single-shot REST
    or streaming target there is nothing left to infer. Use the classifier
    instead when you need the other five layers (auth lifecycle, session,
    identity, rate) resolved from richer evidence.

    Raises:
        ValueError: if the probe never got an answer — an unvalidated config is
            worse than no config.
    """
    if result.diagnosis == "ambiguous":
        raise ValueError(
            "probe was ambiguous: more than one endpoint answered, so only an operator "
            "can say which is the system under test. Re-run with the exact endpoint URL.")
    if not result.endpoint or result.response_text is None:
        raise ValueError(
            f"probe did not find a working contract (diagnosis={result.diagnosis}): "
            f"{result.message} | next: {result.hint}")

    headers = dict(result.headers or {})
    # Do NOT bake a timeout into a generated config. `result.timeout_s` is the DISCOVERY timeout —
    # how long we were willing to wait while working out the contract — and says nothing about how
    # long the target takes under assessment; pinning it is what made a slow target fail every
    # probe. But pinning the runtime default instead is no better: any value written here
    # permanently overrides the derived per-probe timeout for this config, disabling the knob that
    # exists to tune it. So emit `timeout_ms` only when the operator asked for a specific ceiling,
    # and otherwise leave it out and let the runtime default (and its env override) apply.
    tmo = int(timeout_ms) if timeout_ms is not None else None

    if result.transport in ("sse", "ndjson"):
        parts = urlsplit(result.endpoint)
        base = f"{parts.scheme}://{parts.netloc}"
        path = parts.path or "/"
        if parts.query:
            path = f"{path}?{parts.query}"
        stream: Dict[str, Any] = {"format": result.transport}
        stream.update(result.stream_hints or {})
        stream.setdefault("idle_ms", 20000)
        cfg: Dict[str, Any] = {
            "adapter": "sse_stream",
            "base_url": base,
            "chat_path": path,
            "method": result.method or "POST",
            "request_template": result.request_body if isinstance(result.request_body, dict)
            else {"message": PROMPT_TOKEN},
            "stream": stream,
            "timeout_ms": tmo,
        }
    elif _sentinel_of(result):
        # A marker-framed stream (BOT_CHAT_EVENT_BEGIN{...}BOT_CHAT_EVENT_END). The detector for
        # this already existed but only ran on the HAR path, so a live probe against a real
        # marker-framed bot fell through to direct_api and captured the RAW FRAMES as the answer —
        # a config that "validates" while handing the scorer wire protocol instead of the reply.
        sent = _sentinel_of(result)
        cfg = {
            "adapter": "sentinel_stream",
            "url": result.endpoint,
            "method": result.method or "POST",
            "begin_marker": sent["params"]["begin_marker"],
            "end_marker": sent["params"]["end_marker"],
            "message": {"body": result.request_body if isinstance(result.request_body, dict)
                        else {"message": PROMPT_TOKEN}},
            "timeout_ms": tmo,
        }
        extract = sent.get("extract")
        if extract:
            cfg["extract"] = extract
    else:
        body = result.request_body
        if isinstance(body, str):
            # direct_api JSON-encodes a string template (the target therefore sees
            # a quoted JSON string). Flagged so an operator can hand-edit if the
            # target really wanted bare text/plain.
            headers.setdefault("Content-Type", "text/plain")
        cfg = {
            "adapter": "direct_api",
            "endpoint": result.endpoint,
            "method": result.method or "POST",
            "body": body if body is not None else {},
            "timeout_ms": tmo,
        }
        if result.response_path:
            cfg["response_path"] = result.response_path

    if cfg.get("timeout_ms") is None:
        cfg.pop("timeout_ms", None)      # absent => the runtime default and its env knob apply
    if headers:
        cfg["headers"] = headers
    secretish = [k for k in headers
                 if k.lower() in ("authorization", "x-api-key", "api-key", "apikey",
                                  "cookie", "x-auth-token", "x-access-token")]
    cfg["_probe"] = {
        "prompt": result.prompt,
        "verified_answer": (result.response_text or "")[:_ANSWER_PREVIEW],
        "shape": result.shape_label,
        "attempts": len(result.attempts),
        "diagnosis": result.diagnosis,
    }
    if secretish:
        # The caller supplied these, so they are echoed back verbatim — but say so,
        # loudly, before this file lands in a repo.
        cfg["_probe"]["inline_secret_headers"] = secretish
    return cfg


__all__ = [
    "DEFAULT_PROMPT", "PROMPT_TOKEN", "CANDIDATE_PATHS", "BODY_SHAPES",
    "QUERY_PARAM_NAMES", "MIN_ANSWER_SCORE",
    "Shape", "Attempt", "ProbeResult",
    "probe_api", "build_config",
    "candidate_endpoints", "default_shapes", "score_answer",
    "string_paths", "dot_get",
]


# --------------------------------------------------------------------------- #
# WebSocket probing                                                           #
# --------------------------------------------------------------------------- #
# `websocket_direct` shipped as an adapter and as an example config, but nothing could DERIVE
# one: probe.py spoke only HTTP, and classify.py reached `websocket_direct` solely from a HAR
# containing a WebSocket entry. So `ascend target add ws://host/chat` did not even parse -- it
# died with "is not a URL, a file, or a known config" -- and `--url wss://...` was worse, routing
# a socket endpoint into the browser driver, which reported "the capture never delivered the
# prompt". A customer with a WebSocket bot and no HAR had no path at all.
#
# A socket IS probeable: connect, send a frame, read what comes back. That is what this does,
# reusing the same answer scoring as the HTTP path so "which field is the reply" is decided the
# same way everywhere.

# Ordered by how often they appear in the wild. A plain-text frame goes last: it "succeeds"
# against servers that echo, so trying it early would mask a real JSON contract.
WS_SEND_CANDIDATES: List[Any] = [
    {"message": PROMPT_TOKEN},
    {"type": "message", "text": PROMPT_TOKEN},
    {"prompt": PROMPT_TOKEN},
    {"text": PROMPT_TOKEN},
    {"query": PROMPT_TOKEN},
    {"input": PROMPT_TOKEN},
    {"action": "message", "data": {"text": PROMPT_TOKEN}},
    PROMPT_TOKEN,
]

_WS_DONE_VALUES = {"done", "complete", "completed", "end", "finished", "final", "stop", "eos"}


def _ws_render(template: Any, prompt: str) -> str:
    if isinstance(template, str):
        return template.replace(PROMPT_TOKEN, prompt)
    return json.dumps(template).replace(PROMPT_TOKEN, _json_escape(prompt))


def _ws_done_marker(frames: List[Any]) -> Optional[Dict[str, str]]:
    """Spot a terminal frame, so the adapter can stop on it instead of waiting out idle_ms.

    Waiting for silence works but costs the idle window on every single probe. Across a few
    thousand probes that is the difference between an assessment finishing and timing out.
    """
    for frame in reversed(frames):
        if not isinstance(frame, dict):
            continue
        for key in ("type", "event", "status", "state", "kind"):
            val = frame.get(key)
            if isinstance(val, str) and val.strip().lower() in _WS_DONE_VALUES:
                return {"path": key, "equals": val}
    return None


def _ws_unreachable(exc: Exception) -> bool:
    """Did we fail to get a socket at all, as opposed to failing to get an ANSWER?

    The distinction decides whether trying another frame shape can possibly help.
    """
    if isinstance(exc, (ConnectionRefusedError, TimeoutError, asyncio.TimeoutError, OSError)):
        return True
    text = f"{type(exc).__name__}: {exc}".lower()
    return any(k in text for k in (
        "refused", "unreachable", "timed out", "timeout", "name or service not known",
        "nodename nor servname", "no route to host", "getaddrinfo", "connect call failed",
        "invalid handshake", "server rejected", "403", "404", "certificate"))


def probe_ws(url: str, *, prompt: str, headers: Optional[Dict[str, str]] = None,
             timeout_s: float = 30.0, idle_ms: int = 1500,
             subprotocols: Optional[List[str]] = None) -> Dict[str, Any]:
    """Connect to a WebSocket target, work out its frame contract, and report it.

    Returns a dict with ``ok`` plus, on success, everything a websocket_direct config needs.
    Never raises: a probe that explodes is indistinguishable from a target that is down, and the
    operator needs to be told which.
    """
    try:
        import websockets            # noqa: F401  (import here: only the ws path needs it)
    except ImportError:
        return {"ok": False, "diagnosis": "dependency",
                "message": "the `websockets` package is required to probe a WebSocket target",
                "hint": "pip install websockets"}

    async def _attempt(template: Any) -> Dict[str, Any]:
        import websockets
        rendered = _ws_render(template, prompt)
        frames: List[Any] = []
        raw_frames: List[str] = []
        kwargs: Dict[str, Any] = {"open_timeout": min(10.0, timeout_s)}
        if headers:
            kwargs["additional_headers"] = headers
        if subprotocols:
            kwargs["subprotocols"] = subprotocols
        async with websockets.connect(url, **kwargs) as sock:
            await sock.send(rendered)
            deadline = time.time() + timeout_s
            while time.time() < deadline:
                try:
                    raw = await asyncio.wait_for(sock.recv(), timeout=idle_ms / 1000.0)
                except asyncio.TimeoutError:
                    break                      # idle gap: the turn is over
                except Exception:
                    break                      # closed by the server
                text = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else str(raw)
                raw_frames.append(text)
                try:
                    frames.append(json.loads(text))
                except (ValueError, TypeError):
                    frames.append(text)
        return {"frames": frames, "raw": raw_frames, "template": template}

    best: Optional[Dict[str, Any]] = None
    errors: List[str] = []
    for template in WS_SEND_CANDIDATES:
        try:
            got = asyncio.run(_attempt(template))
        except Exception as e:                            # noqa: BLE001 - reported, not raised
            errors.append(f"{type(e).__name__}: {e}")
            # Trying the next frame shape only makes sense if we got a socket at all. A refused
            # or unroutable endpoint fails identically for all eight candidates, so retrying
            # multiplies the wait by eight for no information -- ~24s of dead time before the
            # operator is told the URL is simply wrong, and the same cost in the test suite.
            if _ws_unreachable(e):
                break
            continue
        frames = got["frames"]
        if not frames:
            continue
        # Score every string in every frame the same way the HTTP path does.
        scored: List[Tuple[float, str, str]] = []
        for frame in frames:
            if isinstance(frame, str):
                scored.append((score_answer("", frame, prompt), "", frame))
                continue
            for path, value in string_paths(frame):
                scored.append((score_answer(path, value, prompt), path, value))
        scored.sort(key=lambda t: t[0], reverse=True)
        if not scored or scored[0][0] < MIN_ANSWER_SCORE:
            continue
        score, path, value = scored[0]
        # Several frames each carrying text at the same path is a delta stream -> concat.
        same_path = [v for s, p, v in scored if p == path and s >= MIN_ANSWER_SCORE]
        cand = {
            "ok": True, "diagnosis": "ok", "ws_url": url,
            "send_template": template,
            "response_path": path or None,
            "aggregate": "concat" if len(same_path) > 1 else "last",
            "done_when": _ws_done_marker(frames),
            "idle_ms": idle_ms,
            "answer": value,
            "frames_seen": len(frames),
            "score": score,
        }
        if best is None or cand["score"] > best["score"]:
            best = cand
        break            # first template that produces a real answer wins
    if best:
        return best
    return {"ok": False, "diagnosis": "no_answer",
            "message": (f"connected to {url} but no frame looked like an answer"
                        if not errors else f"could not talk to {url}"),
            "hint": ("send one turn in a browser and export a .har, then "
                     "`ascend target add session.har` — or copy "
                     "configs/example-websocket_direct.json and set ws_url"),
            "errors": errors[:3]}


def build_ws_config(res: Dict[str, Any], *, timeout_ms: Optional[int] = None) -> Dict[str, Any]:
    """Turn a probe_ws result into a websocket_direct config."""
    cfg: Dict[str, Any] = {
        "adapter": "websocket_direct",
        "ws_url": res["ws_url"],
        "send_template": res["send_template"],
        "idle_ms": res.get("idle_ms", 1500),
        "aggregate": res.get("aggregate", "concat"),
    }
    if res.get("response_path"):
        cfg["response_path"] = res["response_path"]
    if res.get("done_when"):
        cfg["done_when"] = res["done_when"]
    if timeout_ms:
        cfg["timeout_ms"] = int(timeout_ms)
    return cfg
