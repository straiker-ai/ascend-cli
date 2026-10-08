"""
discovery.classify — the deterministic per-layer classifiers.

Input is *evidence*: a parsed HAR (dict) and/or a list of captured
request/response pairs. For each of the six adapter layers
(``transport``, ``auth``, ``auth_lifecycle``, ``session``, ``identity``,
``rate``) a bounded classifier emits::

    {"value": <chosen>, "params": {...}, "confidence": 0.0-1.0, "evidence": "why"}

:func:`compose` folds the six results into a runnable adapter config, choosing
the closest of the existing adapters and its known knobs (see
``docs/CAPABILITY_MATRIX.md``). :func:`classify_evidence` runs the whole thing and
reports which layers still need a human (``unresolved``).

Purity
------
Nothing here performs network I/O — every function is a deterministic transform
over evidence dicts, so the whole module is unit-testable offline. Secrets that
appear in evidence are **never** copied into the emitted config; auth params
carry an ``env:`` ``value_ref`` placeholder instead, and record only the header
*name* that carried the secret.
"""
from __future__ import annotations

import json
import re
import statistics
from typing import Any, Dict, List, Optional, Tuple

_SSE_ID_FIELDS = {"turn_id", "trace_id", "response_id", "id", "state",
                  "conversation_id", "message_id", "session_id"}

LAYER_NAMES = ("transport", "auth", "auth_lifecycle", "session", "identity", "rate")

# Confidence below this marks a layer "unresolved" (needs operator/agent input).
LOW_CONF = 0.5

# Header names that, if present on the chat request, carry an auth secret.
_SECRET_HEADERS = {
    "authorization", "x-api-key", "api-key", "apikey", "x-auth-token",
    "x-authentication", "authentication", "x-access-token", "cookie",
}
_CSRF_HEADERS = {"x-csrf-token", "x-xsrf-token", "csrf-token", "x-csrftoken"}

# `_SECRET_HEADERS` above is a fixed list of nine names, and it drove BOTH "is this auth?" and
# "is this safe to bake into the config?". So a custom-named credential -- X-Tenant-Key,
# X-Subscription-Key, X-Nonce, X-Session-Token -- was neither recognised as auth NOR dropped, and
# landed in the config on disk in cleartext beside `auth: none`. This module's own docstring
# promises the opposite: secrets "carry an `env:` `value_ref` placeholder instead, and record
# only the header". Recognition has to be open-ended, because the whole point is that the name
# is one we have not seen before.
_SECRETISH_NAME = re.compile(
    r"(api[-_]?key|access[-_]?key|secret|token|signature|^x-sig|hmac|nonce|"
    r"credential|password|passwd|pwd|bearer|session[-_]?(id|key|token)|"
    r"subscription[-_]?key|tenant[-_]?key|client[-_]?(id|secret))", re.I)
# Headers that routinely carry long opaque values and are NOT credentials. Without this an
# entropy rule would strip the very headers a target needs to answer at all.
_NEVER_SECRET = {
    "user-agent", "accept", "accept-language", "accept-encoding", "content-type",
    "content-length", "referer", "origin", "host", "connection", "cache-control",
    "sec-fetch-mode", "sec-fetch-site", "sec-fetch-dest", "sec-ch-ua", "sec-ch-ua-platform",
    "sec-ch-ua-mobile", "pragma", "dnt", "te", "upgrade-insecure-requests", "priority",
    "x-requested-with", "traceparent", "x-request-id", "x-correlation-id", "x-trace-id",
}
_OPAQUE_VALUE = re.compile(r"^[A-Za-z0-9_.\-=+/]{20,}$")


def _looks_secret_header(name_lower: str, value: str) -> bool:
    """Would baking this header into a config on disk leak a credential?

    Name first, because a name is deliberate and a value is circumstantial. The entropy rule is
    the backstop for a name we cannot anticipate, and it is scoped to `x-*` so an ordinary
    long-but-public header (a User-Agent, a trace id) is not stripped from a config that needs it.
    """
    if name_lower in _NEVER_SECRET:
        return False
    if name_lower in _SECRET_HEADERS or name_lower in _CSRF_HEADERS:
        return True
    if _SECRETISH_NAME.search(name_lower):
        return True
    v = (value or "").strip()
    if name_lower.startswith("x-") and _OPAQUE_VALUE.match(v):
        # long, opaque, and on a non-standard header: treat as a credential rather than risk it
        classes = sum(bool(re.search(p, v)) for p in (r"[a-z]", r"[A-Z0-9]", r"[_.\-=+/]"))
        return classes >= 2
    return False
_ID_FIELDS = (
    "id", "sessionId", "session_id", "conversationId", "conversation_id",
    "threadId", "thread_id", "chatId", "chat_id", "ticketId", "ticket_id",
    "requestId", "request_id", "jobId", "job_id",
)
_PROMPT_FIELDS = ("prompt", "message", "input", "text", "query", "content", "question", "msg")
# Keys and values that name a record rather than say anything. An id is never a chatbot's answer,
# but it is often the LONGEST string in an acknowledgement body (`{"id": "<uuid>", "status":
# "queued"}`), so "longest string anywhere" picked it — and because a fresh id comes back per
# request, two different test questions got two different "answers", which is exactly what the
# constant-reply guard accepts as a live bot. A false pass the guard cannot see.
_ID_KEYS_LOWER = frozenset(k.lower() for k in (
    "id", "sessionId", "session_id", "conversationId", "conversation_id", "threadId", "thread_id",
    "chatId", "chat_id", "ticketId", "ticket_id", "requestId", "request_id", "jobId", "job_id",
    "conversationEntryId", "entryId", "messageId", "message_id", "eventId", "event_id",
    "correlationId", "correlation_id", "traceId", "trace_id", "uuid", "guid",
))
_ID_VALUE_RE = re.compile(
    r"^(?:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
    r"|[0-9a-fA-F]{16,}|[A-Za-z0-9_\-]{24,})$")


def _is_identifier_leaf(path: str, value: str) -> bool:
    """True when a string leaf is an identifier — by its key or by its shape — never an answer."""
    if str(path).rsplit(".", 1)[-1].lower() in _ID_KEYS_LOWER:
        return True
    v = (value or "").strip()
    return bool(v) and not any(c.isspace() for c in v) and bool(_ID_VALUE_RE.match(v))


def _is_bare_ack(resp_json: Any) -> bool:
    """A JSON reply that names a record and says nothing: an id, maybe a status, no answer text.

    The send half of an ack-then-poll contract, whose answer arrives on a later call. When the
    capture stopped before that call, this body was wired as a plain JSON endpoint at 0.85 and the
    acknowledgement was scored as the reply. Requires an id AND no prose anywhere, so a terse real
    answer under a known key (`"answer": "4"`) is never mistaken for one.
    """
    if not isinstance(resp_json, (dict, list)) or _first_id(resp_json) is None:
        return False
    for path in _RESPONSE_PATH_GUESSES:
        val = _dot(resp_json, path)
        if isinstance(val, str) and val.strip() and not _is_identifier_leaf(path, val):
            return False
    for path, val in _paths_to_strings(resp_json):
        if not _is_identifier_leaf(path, val) and len(val.split()) >= 3:
            return False
    return True


_RESPONSE_PATH_GUESSES = (
    "response", "message", "text", "content", "answer", "output", "reply",
    "data.text", "data.message", "data.content", "result", "completion",
    "choices.0.message.content", "messages.0.message", "messages.0.text",
    "candidates.0.content.parts.0.text",
)
_ASSET_RE = re.compile(r"\.(js|css|png|jpe?g|gif|svg|ico|woff2?|ttf|map|webp)(\?|$)", re.I)
_GREETINGS = {"hi", "hello", "hey", "hola", "start", "begin"}


class ClassifyError(ValueError):
    """Raised when evidence cannot be parsed into the normalized form."""


# --------------------------------------------------------------------------- #
# Evidence ingestion / normalization                                          #
# --------------------------------------------------------------------------- #
def _headers_to_dict(headers: Any) -> Dict[str, str]:
    """Normalize headers (HAR list or dict) to a lowercased-key dict.

    Drops HTTP/2 pseudo-headers (`:authority`, `:method`, `:path`, `:scheme`). Chrome writes these
    into every HAR of an HTTP/2 site — which today is nearly all of them — but they are protocol
    internals, not real headers: sending one over the wire raises
    "Invalid ... character(s) in header name: ':authority'" and the whole request fails. They carry
    nothing the URL and method don't already have.
    """
    out: Dict[str, str] = {}
    if isinstance(headers, list):
        for h in headers:
            if isinstance(h, dict) and "name" in h:
                name = str(h["name"])
                if name.startswith(":"):
                    continue
                out[name.lower()] = str(h.get("value", ""))
    elif isinstance(headers, dict):
        for k, v in headers.items():
            if str(k).startswith(":"):
                continue
            out[str(k).lower()] = str(v)
    return out


def _maybe_json(text: Optional[str]) -> Any:
    if not text or not isinstance(text, str):
        return None
    t = text.strip()
    if not t:
        return None
    try:
        return json.loads(t)
    except (ValueError, TypeError):
        return None


def _query_from_url(url: str) -> Dict[str, str]:
    from urllib.parse import urlparse, parse_qsl
    return dict(parse_qsl(urlparse(url).query))


def _strip_query(url: str) -> str:
    return url.split("?", 1)[0]


# Query-string parameters that are credentials. Dropping the whole query string was the previous
# behaviour, and it broke two common shapes at once: an endpoint whose query is REQUIRED and
# public (Azure OpenAI's `?api-version=`, Vertex's `?alt=sse`) registered without it and 4xx'd on
# every probe; and an access code or API key carried as `?code=` / `?key=` was dropped silently,
# so the derived config 401'd for no visible reason. The rule now is the same one the headers
# follow: a public parameter stays on the endpoint; a credential-shaped one is withheld from the
# config, its value goes to the 0600 store, and the config carries an `env:` reference that
# `layers/auth.py` folds back into the query string at send time (`mode: api_key, in: query`).
_SECRET_PARAM_NAMES = frozenset({
    "code", "key", "apikey", "api_key", "api-key", "token", "access_token", "access-token",
    "auth", "authorization", "sig", "signature", "secret", "password", "passwd", "pwd", "jwt",
    "bearer", "session", "sid", "session_id", "sessionid", "session-id", "client_secret",
    "subscription-key", "subscription_key", "x-api-key", "apikey", "appkey", "app_key",
})
_PLAIN_PARAM_NAMES = frozenset({
    "api-version", "api_version", "version", "v", "alt", "format", "lang", "locale", "stream",
    "model", "deployment", "id", "page", "limit", "offset", "q", "query", "type", "mode",
})


def _looks_secret_param(name: str, value: str) -> bool:
    """Would baking this query parameter into a config on disk leak a credential?

    Name first (a name is deliberate), then the entropy backstop for a name we did not
    anticipate — scoped the same way `_looks_secret_header` scopes it, so an ordinary long public
    value (a model id, a locale) is not withheld from a config that needs it.
    """
    n = (name or "").strip().lower()
    if not n or n in _PLAIN_PARAM_NAMES:
        return False
    if n in _SECRET_PARAM_NAMES or _SECRETISH_NAME.search(n):
        return True
    v = (value or "").strip()
    if _OPAQUE_VALUE.match(v) and len(v) >= 24:
        classes = sum(bool(re.search(p, v)) for p in (r"[a-z]", r"[A-Z0-9]", r"[_.\-=+/]"))
        return classes >= 2
    return False


def _split_query(url: str) -> Tuple[List[Tuple[str, str]], Dict[str, str]]:
    """(public parameters in order, {credential parameter: value}) of a URL's query string."""
    from urllib.parse import urlsplit, parse_qsl
    plain: List[Tuple[str, str]] = []
    secret: Dict[str, str] = {}
    try:
        pairs = parse_qsl(urlsplit(url).query, keep_blank_values=True)
    except (ValueError, AttributeError):
        return [], {}
    for k, v in pairs:
        if _looks_secret_param(k, v):
            secret[k] = v
        else:
            plain.append((k, v))
    return plain, secret


def _endpoint_keeping(url: str, plain: List[Tuple[str, str]]) -> str:
    """The endpoint with only its PUBLIC query parameters, in their original order."""
    from urllib.parse import urlencode
    base = _strip_query(url)
    return f"{base}?{urlencode(plain)}" if plain else base


def _norm_entry(request: Dict[str, Any], response: Dict[str, Any],
                started: Optional[float] = None) -> Dict[str, Any]:
    """Normalize one request/response pair into the internal shape."""
    req_headers = _headers_to_dict(request.get("headers"))
    url = request.get("url", "")
    raw_body = request.get("body")
    if isinstance(raw_body, (dict, list)):
        req_json = raw_body
        raw_body_str = json.dumps(raw_body)
    else:
        raw_body_str = raw_body if isinstance(raw_body, str) else request.get("raw_body")
        req_json = _maybe_json(raw_body_str)

    resp_headers = _headers_to_dict(response.get("headers"))
    resp_body = response.get("body")
    if isinstance(resp_body, (dict, list)):
        resp_json = resp_body
        resp_body_str = json.dumps(resp_body)
    else:
        resp_body_str = resp_body if isinstance(resp_body, str) else response.get("raw_body")
        resp_json = _maybe_json(resp_body_str)

    query = request.get("query") or _query_from_url(url)
    content_type = resp_headers.get("content-type", "")
    return {
        "request": {
            "method": str(request.get("method", "GET")).upper(),
            "url": url,
            "headers": req_headers,
            "query": {str(k).lower(): str(v) for k, v in dict(query).items()},
            "json": req_json,
            "raw_body": raw_body_str or "",
        },
        "response": {
            "status": int(response.get("status", 0) or 0),
            "headers": resp_headers,
            "json": resp_json,
            "raw_body": resp_body_str or "",
            "content_type": content_type,
        },
        "started_ms": started,
    }


def _normalize_pairs(pairs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for p in pairs:
        if "request" in p and "response" in p:
            out.append(_norm_entry(p["request"], p["response"], p.get("started_ms")))
        else:  # flat shape
            out.append(_norm_entry(p, p.get("response", {}), p.get("started_ms")))
    return out


def load_har(path: str, prompt_sent: Optional[str] = None) -> Dict[str, Any]:
    """Parse a HAR file at ``path`` into normalized evidence.

    ``prompt_sent`` is the text the operator actually typed into the chat during the session the
    HAR captured. A browser export contains dozens of requests; without knowing what was typed,
    the classifier has to GUESS which one is the chat turn, and on a noisy real page it guesses
    wrong. With it, the chat request is simply the one whose body contains that exact string —
    ground truth that beats every heuristic. Pass it whenever you can.

    Returns ``{"pairs": [...], "ws_messages": [...], "prompt_sent": ...}`` ready for
    :func:`classify_evidence`. Pure/offline — just file + JSON parsing.
    """
    with open(path, "r", encoding="utf-8") as fh:
        har = json.load(fh)
    # A saved browser/HAR capture (`--save-evidence`, or the default persisted by `target add`)
    # is ALREADY normalized evidence — {pairs, ws_messages} — not a raw .har with .log.entries.
    # Accept it directly so a capture can be re-wired without re-driving the browser: the whole
    # point of keeping it is that it is the source of truth, reusable for adapter-building and
    # re-analysis. A real .har (no top-level `pairs`) goes through the converter as before.
    if isinstance(har, dict) and isinstance(har.get("pairs"), list):
        if prompt_sent and not har.get("prompt_sent"):
            har = {**har, "prompt_sent": prompt_sent}
        return har
    return har_to_evidence(har, prompt_sent=prompt_sent)


def har_to_evidence(har: Dict[str, Any], prompt_sent: Optional[str] = None) -> Dict[str, Any]:
    """Convert an in-memory parsed HAR dict into normalized evidence."""
    entries = (((har or {}).get("log") or {}).get("entries")) or []
    pairs: List[Dict[str, Any]] = []
    ws_messages: List[Dict[str, Any]] = []
    for e in entries:
        req = e.get("request", {}) or {}
        resp = e.get("response", {}) or {}
        request = {
            "method": req.get("method", "GET"),
            "url": req.get("url", ""),
            "headers": req.get("headers", []),
            "query": {q.get("name", "").lower(): q.get("value", "")
                      for q in (req.get("queryString") or [])},
            "raw_body": (req.get("postData") or {}).get("text"),
        }
        response = {
            "status": resp.get("status", 0),
            "headers": resp.get("headers", []),
            "raw_body": (resp.get("content") or {}).get("text"),
        }
        started = _har_started_ms(e)
        pair = _norm_entry(request, response, started)
        # Carry the HAR mimeType even when there is no body text.
        if not pair["response"]["content_type"]:
            pair["response"]["content_type"] = (resp.get("content") or {}).get("mimeType", "")
        pairs.append(pair)
        for m in e.get("_webSocketMessages", []) or []:
            ws_messages.append({"url": req.get("url", ""), **m})
    ev = {"pairs": pairs, "ws_messages": ws_messages}
    if prompt_sent:
        ev["prompt_sent"] = prompt_sent.strip()
    return ev


def _har_started_ms(entry: Dict[str, Any]) -> Optional[float]:
    ts = entry.get("startedDateTime")
    if not ts:
        return None
    try:
        from datetime import datetime
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp() * 1000.0
    except (ValueError, TypeError):
        return None


_REPLY_TEXT: Dict[str, Any] = {"v": None}
# The prompt the operator actually sent during the capture. Ground truth beats every
# heuristic, and its absence is what let a GraphQL body freeze the real prompt (below).
_PROMPT_SENT: Dict[str, Any] = {"v": None}


def _evidence(evidence: Dict[str, Any]) -> Dict[str, Any]:
    """Accept either normalized evidence, a raw HAR, or a bare pairs list."""
    if isinstance(evidence, list):
        return {"pairs": _normalize_pairs(evidence), "ws_messages": []}
    if not isinstance(evidence, dict):
        raise ClassifyError(f"evidence must be dict/list, got {type(evidence).__name__}")
    if "log" in evidence and "pairs" not in evidence:
        return har_to_evidence(evidence)
    pairs = evidence.get("pairs")
    if pairs is None:
        raise ClassifyError("evidence dict has no 'pairs' (or 'log') key")
    # Re-normalize in case caller passed raw pairs.
    if pairs and "request" in pairs[0] and "headers" in (pairs[0]["request"] or {}) \
            and isinstance(pairs[0]["request"].get("headers"), dict):
        norm = pairs  # already normalized
    else:
        norm = _normalize_pairs(pairs)
    # carry the capture ground-truth through — the classifiers use it to pick the
    # request that actually carried our prompt (beats every heuristic).
    _REPLY_TEXT["v"] = evidence.get("reply_text")
    _PROMPT_SENT["v"] = evidence.get("prompt_sent")
    return {"pairs": norm, "ws_messages": evidence.get("ws_messages", []),
            "prompt_sent": evidence.get("prompt_sent"),
            "reply_text": evidence.get("reply_text")}


# --------------------------------------------------------------------------- #
# Chat-pair selection                                                         #
# --------------------------------------------------------------------------- #
def _is_asset(url: str) -> bool:
    return bool(_ASSET_RE.search(url or ""))


def _pick_chat_index(pairs: List[Dict[str, Any]], known_prompt: Optional[str] = None) -> Optional[int]:
    """Heuristically pick the pair that carries the scored prompt/answer.

    Prefers non-asset POST/PUT requests whose response looks like a chat answer,
    scored by response size and a prompt-like request body. Falls back to the
    largest non-asset response.
    """
    # GROUND TRUTH: during a live capture we know exactly what we typed, so the chat
    # call is the request whose body literally contains that prompt. This beats every
    # heuristic and prevents picking an analytics/personalization vendor's traffic.
    if known_prompt:
        needle = known_prompt.strip()
        exact = [i for i, p in enumerate(pairs)
                 if needle and needle in (p["request"].get("raw_body") or "")]
        if exact:
            # if several carry it, prefer the one with the biggest response (the answer)
            return max(exact, key=lambda i: len(pairs[i]["response"].get("raw_body") or ""))

    best_idx, best_score = None, -1.0
    for i, p in enumerate(pairs):
        req, resp = p["request"], p["response"]
        if _is_asset(req["url"]):
            continue
        ct = resp["content_type"]
        score = 0.0
        if req["method"] in ("POST", "PUT", "PATCH"):
            score += 2.0
        if "event-stream" in ct or "ndjson" in ct or "application/json" in ct:
            score += 2.0
        if _request_has_prompt(req) is not None:
            score += 3.0
        score += min(len(resp["raw_body"] or "") / 500.0, 4.0)
        if score > best_score:
            best_idx, best_score = i, score
    return best_idx


# A GraphQL document, not a question. `query` is in _PROMPT_FIELDS because plenty of REST bots
# call their field that, but in a GraphQL body it holds the OPERATION.
_GQL_DOC = re.compile(r"^\s*(?:query|mutation|subscription)\b|^\s*\{[^\"]*\{", re.S)


def _looks_like_graphql_doc(value: str) -> bool:
    return bool(value) and "{" in value and bool(_GQL_DOC.match(value))


def _find_exact(obj: Any, needle: str) -> bool:
    """Is `needle` present verbatim as a string leaf anywhere in this body?"""
    if isinstance(obj, str):
        return obj == needle
    if isinstance(obj, dict):
        return any(_find_exact(v, needle) for v in obj.values())
    if isinstance(obj, list):
        return any(_find_exact(v, needle) for v in obj)
    return False


def _nested_prompt_field(obj: Any, depth: int = 0) -> Optional[str]:
    """Find a prompt-named string field below the top level (GraphQL `variables`, DTO wrappers)."""
    if depth > 6 or not isinstance(obj, (dict, list)):
        return None
    if isinstance(obj, dict):
        for f in _PROMPT_FIELDS:
            v = obj.get(f)
            if isinstance(v, str) and v.strip() and not _looks_like_graphql_doc(v):
                return v
        for v in obj.values():
            got = _nested_prompt_field(v, depth + 1)
            if got is not None:
                return got
        return None
    for v in obj:
        got = _nested_prompt_field(v, depth + 1)
        if got is not None:
            return got
    return None


def _request_has_prompt(req: Dict[str, Any]) -> Optional[str]:
    """Return the prompt-like string in a request body, if any.

    Ground truth first. When the operator told us what they typed, an exact match anywhere in
    the body beats field-name order outright -- and that ordering caused the worst possible
    failure on a GraphQL target. The body is
    `{"query": "<graphql document>", "variables": {"input": {"message": "<real prompt>"}}}`,
    `query` is in _PROMPT_FIELDS, so the DOCUMENT was returned as the prompt, templated to
    {{PROMPT}}, and the real question was frozen as a literal in `variables`. The config then
    validated green while every probe re-asked the capture-time question -- a false pass, which
    is worse than a failure because nothing looks wrong.
    """
    body = req.get("json")
    known = (_PROMPT_SENT.get("v") or "").strip()
    if known and isinstance(body, (dict, list)) and _find_exact(body, known):
        return known
    if isinstance(body, dict):
        for f in _PROMPT_FIELDS:
            v = body.get(f)
            if isinstance(v, str):
                if f == "query" and _looks_like_graphql_doc(v):
                    continue      # the operation, not the question
                return v
        # Nothing at the top level. A GraphQL body carries the question one level down, in
        # `variables`, so look for a prompt-named field anywhere before falling back.
        nested = _nested_prompt_field(body)
        if nested is not None:
            return nested
        # Deepest / longest string fallback -- but never a GraphQL document. Skipping it above
        # and then handing it back here was the actual bug: the guard fired and the fallback
        # undid it, so the document still became {{PROMPT}}.
        longest = _longest_string(body)
        if longest and len(longest) >= 3 and not _looks_like_graphql_doc(longest):
            return longest
    elif isinstance(body, str) and body.strip():
        return body
    return None


def _longest_string(obj: Any) -> Optional[str]:
    best = None
    stack = [obj]
    while stack:
        cur = stack.pop()
        if isinstance(cur, str):
            if best is None or len(cur) > len(best):
                best = cur
        elif isinstance(cur, dict):
            stack.extend(cur.values())
        elif isinstance(cur, list):
            stack.extend(cur)
    return best


# --------------------------------------------------------------------------- #
# Layer 1 — transport                                                         #
# --------------------------------------------------------------------------- #
def classify_transport(ev: Dict[str, Any], chat_idx: Optional[int]) -> Dict[str, Any]:
    pairs = ev["pairs"]
    # A WebSocket is only the transport if it ACTUALLY carried the conversation.
    # Pages routinely open sockets for analytics/personalization; picking those
    # produces a confidently-wrong config. Require evidence of real traffic, and
    # if we know the prompt we typed, require the socket to have carried it.
    known_prompt = (ev.get("prompt_sent") or "").strip()
    ws_live = []
    for w in (ev.get("ws_messages") or []):
        sent = w.get("sent") or []
        recv = w.get("received") or []
        if not sent and not recv:
            continue          # handshake only — not the chat channel
        if known_prompt and not any(known_prompt in str(f) for f in sent):
            continue          # this socket never carried our prompt
        ws_live.append(w)
    if ws_live:
        return {
            "value": "websocket", "confidence": 0.9,
            "evidence": f"{len(ws_live)} WebSocket channel(s) carried the conversation",
            "params": _ws_params({**ev, "ws_messages": ws_live}),
        }
    if chat_idx is None:
        return {"value": None, "confidence": 0.0, "evidence": "no chat pair found", "params": {}}

    p = pairs[chat_idx]
    req, resp = p["request"], p["response"]
    ct = (resp["content_type"] or "").lower()
    body = resp["raw_body"] or ""

    # Upgrade / 101 -> websocket (no captured frames but a handshake).
    if resp["status"] == 101 or req["headers"].get("upgrade", "").lower() == "websocket":
        return {"value": "websocket", "confidence": 0.75,
                "evidence": "HTTP 101 / Upgrade: websocket handshake",
                "params": _ws_params(ev)}

    if "text/event-stream" in ct or (body.lstrip().startswith("data:")):
        return {"value": "sse", "confidence": 0.9,
                "evidence": f"content-type={ct or 'n/a'}, SSE data: frames",
                "params": _http_params(req, resp, stream="sse")}

    # Sentinel-framed streams: MARKER_BEGIN{json}MARKER_END repeated in a text/plain body.
    sent = _detect_sentinel(body)
    if sent is not None:
        sent["params"] = {**_http_params(req, resp, stream=None), **sent["params"]}
        return sent

    if "ndjson" in ct or _looks_ndjson(body):
        return {"value": "ndjson", "confidence": 0.8,
                "evidence": f"content-type={ct or 'n/a'}, newline-delimited json",
                "params": _http_params(req, resp, stream="ndjson")}

    # poll: submit returns an id, a later GET on a URL containing that id returns a transcript.
    poll = _detect_poll(pairs, chat_idx)
    if poll is not None:
        return poll

    if "application/json" in ct or resp["json"] is not None:
        if _is_bare_ack(resp["json"]):
            # Below LOW_CONF on purpose: the layer is reported unresolved instead of wired with
            # false certainty, and the validation gate — not this guess — decides.
            return {"value": "rest_json", "confidence": 0.35,
                    "evidence": ("the reply to the message is an acknowledgement — an id and "
                                 "status fields, no answer text. The answer most likely arrives on "
                                 "a later call (a poll or a stream) that the capture did not "
                                 "include; capture the whole exchange, through the answer"),
                    "params": _http_params(req, resp, stream=None)}
        return {"value": "rest_json", "confidence": 0.85,
                "evidence": f"content-type={ct or 'n/a'}, single JSON body",
                "params": _http_params(req, resp, stream=None)}

    # Reachable-only-in-page style responses (html) => browser_dom, but we have no
    # dedicated generic-DOM adapter registered; flag low confidence.
    return {"value": "rest_json", "confidence": 0.3,
            "evidence": f"ambiguous content-type={ct or 'n/a'}; defaulting to rest_json",
            "params": _http_params(req, resp, stream=None)}


def _detect_sentinel(body: str) -> Optional[Dict[str, Any]]:
    """Detect a MARKER_BEGIN{json}MARKER_END framed body (sentinel_stream transport).

    Generic: finds a repeated <NAME>_BEGIN ... <NAME>_END pair wrapping JSON. Returns a
    transport classification with the discovered markers, or None.
    """
    if not body or "{" not in body:
        return None
    # The name must not run across a preceding `_END`. Real streams concatenate frames with no
    # separator (`..._ENDNAME_BEGIN`), and an unanchored match captured
    # `BOT_CHAT_EVENT_ENDBOT_CHAT_EVENT` as a second "name". Both candidates then had count 1, so
    # `max(set(...), key=count)` picked between them by SET ORDERING — the detector recognised the
    # same payload or not depending on hash order.
    names = re.findall(r"(?:^|[^A-Z0-9_])([A-Z][A-Z0-9_]{2,}?)_BEGIN", body)
    if not names:
        return None
    # Choose by what actually WORKS — the name whose markers bracket the most parseable JSON —
    # rather than by frequency, which cannot distinguish a real marker from a lucky substring.
    best = None
    for name in dict.fromkeys(names):
        begin, end = f"{name}_BEGIN", f"{name}_END"
        if end not in body:
            continue
        parsed = 0
        for f in re.findall(re.escape(begin) + r"(.*?)" + re.escape(end), body, re.S):
            try:
                json.loads(f.strip())
                parsed += 1
            except Exception:
                pass
        if parsed and (best is None or parsed > best[0]):
            best = (parsed, begin, end)
    if best is None:
        return None
    parsed, begin, end = best
    return {
        "value": "sentinel_stream",
        "confidence": 0.9,
        "evidence": f"{parsed} JSON frame(s) delimited by {begin}/{end}",
        "params": {"begin_marker": begin, "end_marker": end, "_sentinel": True},
    }


def _looks_ndjson(body: str) -> bool:
    lines = [l for l in (body or "").splitlines() if l.strip()]
    if len(lines) < 2:
        return False
    ok = 0
    for l in lines[:5]:
        try:
            json.loads(l)
            ok += 1
        except (ValueError, TypeError):
            return False
    return ok >= 2


def _http_params(req: Dict[str, Any], resp: Dict[str, Any], stream: Optional[str]) -> Dict[str, Any]:
    plain_q, secret_q = _split_query(req["url"])
    params: Dict[str, Any] = {
        "endpoint": _endpoint_keeping(req["url"], plain_q),
        "method": req["method"],
        "headers": _nonsecret_headers(req["headers"]),
        "body": _body_template(req),
    }
    held = dropped_secret_headers(req["headers"])
    if held:
        params["withheld_headers"] = held
        # The values travel beside the names so `compose` can turn them into references and the
        # CLI can store them. `classify_evidence` lifts this key out of the layers before it
        # returns, so a caller that dumps its result cannot print a credential by accident.
        params["secret_header_values"] = captured_secret_headers(req["headers"])
        params["secret_header_url"] = req.get("url") or ""
    if secret_q:
        # Same arrangement for a credential in the query string (`?code=`, `?key=`): names in the
        # layer, values lifted out by `classify_evidence`, an `env:` reference in the config.
        params["withheld_query"] = sorted(secret_q)
        params["secret_query_values"] = dict(secret_q)
        params["secret_header_url"] = params.get("secret_header_url") or (req.get("url") or "")
    if stream:
        # Derive the field mapping from the captured body rather than emitting a bare
        # {"format": "sse"}. Without text_path/token_types the adapter collects no frames and
        # the operator has to reverse-engineer the stream by hand — and the obvious guess
        # (whichever field appears most often) is the progress chatter, not the answer.
        params["stream"] = {"format": stream}
        hints = _sse_stream_hints(resp.get("raw_body") or "") if stream in ("sse", "ndjson") else {}
        if hints.get("text_path"):
            params["stream"].update({k: v for k, v in hints.items() if k != "format"})
    else:
        # Only claim a response_path when the body actually parsed as JSON. For a plain-text
        # bot, `_guess_response_path` still returns its "response" fallback, and that single
        # key turns a working config into a broken one: direct_api sees a response_path, demands
        # JSON, and fails with "expected JSON for response_path 'response' but got non-JSON".
        # With the key ABSENT the same adapter treats the raw text as the answer and works --
        # which test_direct_api_non_json_response_no_path_is_text has always asserted. So the
        # capture path was the only thing standing between a text/plain target and a valid
        # config, and it was inventing the obstacle.
        if resp.get("json") is not None:
            params["response_path"] = _guess_response_path(resp["json"], _REPLY_TEXT.get("v"))
        else:
            stop = _detect_stop_marker(resp.get("raw_body") or "")
            if stop:
                params["stop_marker"] = stop
    return params


# A streaming terminator on a plain-text body: `<<<END>>>`, `[DONE]`, `<EOS>`, `--END--`.
_STOP_WORDS = ("done", "end", "eos", "eof", "stop", "fin", "finish", "complete", "completed")


def _detect_stop_marker(body: str) -> Optional[str]:
    """Find the terminator a chunked text/plain body closes with.

    Without this the marker is simply the last few characters of the answer, and the scorer
    reads it as the agent's words -- on every single turn, quietly, which is worse than failing
    once. Same class as SSE progress chatter arriving as the reply.

    Deliberately narrow: the final non-empty line must be short, contain no whitespace, and
    either be wrapped in bracket/angle/dash punctuation or be one of a few terminator words.
    A target whose answer genuinely ends in a short word must not lose it, so ambiguity means
    no marker rather than a guess.
    """
    lines = [l.strip() for l in (body or "").splitlines() if l.strip()]
    if len(lines) < 2:
        return None
    last = lines[-1]
    if len(last) > 32 or " " in last or "\t" in last:
        return None
    core = last.strip("<>[](){}|-_*=.: ").lower()
    if not core:
        return None
    bracketed = last[0] in "<[({|-*=" and last[-1] in ">])}|-*="
    if bracketed or core in _STOP_WORDS:
        return last
    return None


_WS_DONE_VALUES = {"done", "complete", "completed", "end", "finished", "final", "stop", "eos"}
_WS_ID_FIELDS = {"id", "conversation_id", "conversationId", "session_id", "sessionId", "message_id",
                 "messageId", "request_id", "requestId", "connectionId", "type", "event", "status",
                 "state", "kind", "role", "timestamp", "ts"}


def _ws_frame(raw: Any) -> Any:
    """A captured frame as the adapter will see it: JSON when it parses, else the raw text."""
    if isinstance(raw, (dict, list)):
        return raw
    if not isinstance(raw, str):
        return raw
    t = raw.strip()
    if t.startswith(("{", "[")):
        try:
            return json.loads(t)
        except (ValueError, TypeError):
            return raw
    return raw


def _ws_done_marker(frames: List[Any]) -> Optional[Dict[str, str]]:
    """The terminal frame the socket sends when the answer is complete, as the adapter's
    `done_when` rule (same rule the socket-onboarding path in probe.py derives)."""
    for frame in reversed(frames):
        if not isinstance(frame, dict):
            continue
        for key in ("type", "event", "status", "state", "kind"):
            val = frame.get(key)
            if isinstance(val, str) and val.strip().lower() in _WS_DONE_VALUES:
                return {"path": key, "equals": val}
    return None


def _ws_reply_field(frames: List[Any]) -> Optional[str]:
    """The string field that carried the most answer text across the received frames."""
    totals: Dict[str, int] = {}
    for f in frames:
        if not isinstance(f, dict):
            continue
        for k, v in f.items():
            if isinstance(v, str) and v.strip() and k not in _WS_ID_FIELDS:
                totals[k] = totals.get(k, 0) + len(v)
            elif isinstance(v, dict):
                for kk, vv in v.items():
                    if isinstance(vv, str) and vv.strip() and kk not in _WS_ID_FIELDS:
                        totals[f"{k}.{kk}"] = totals.get(f"{k}.{kk}", 0) + len(vv)
    if not totals:
        return None
    return max(totals.items(), key=lambda kv: kv[1])[0]


def _ws_send_template(sent: List[Any], prompt: str) -> Any:
    """The frame the page sent carrying the prompt, with the prompt replaced by {{PROMPT}}.

    The page's own frame IS the contract; the old fixed guess ({"type": "message", "text": …})
    happened to work on a target that only read `text` and would send every other socket a
    message it ignores — read back as "no frames" a probe later.
    """
    def _sub(obj: Any) -> Any:
        if isinstance(obj, str):
            return obj.replace(prompt, "{{PROMPT}}") if prompt and prompt in obj else obj
        if isinstance(obj, dict):
            return {k: _sub(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [_sub(v) for v in obj]
        return obj
    if prompt:
        for raw in sent:
            if prompt in str(raw):
                return _sub(_ws_frame(raw))
    return None


def _ws_params(ev: Dict[str, Any]) -> Dict[str, Any]:
    """The websocket_direct contract, read off the frames the page exchanged.

    Before: only the socket URL came from the capture; the send frame, the reply field and the
    terminal frame were fixed guesses and a 1.5 s silence rule did the rest. MEASURED on a
    Lambda-backed socket: the capture held {"type":"token","text":…} frames and a {"type":"done"}
    terminator, the derived config carried none of it, and 25 of 26 probes came back empty.
    """
    url = ""
    sent: List[Any] = []
    received: List[Any] = []
    prompt = (ev.get("prompt_sent") or "").strip()
    for m in ev.get("ws_messages", []):
        url = m.get("url", url)
        sent.extend(m.get("sent") or [])
        received.extend(m.get("received") or [])
        data = m.get("data")             # legacy single-frame shape
        if isinstance(data, str):
            received.append(data)
    if url.startswith("http"):
        url = "ws" + url[len("http"):]  # http->ws, https->wss
    frames = [_ws_frame(r) for r in received]
    framing = "json" if any(isinstance(f, (dict, list)) for f in frames) or \
        any(isinstance(_ws_frame(x), (dict, list)) for x in sent) else "text"
    params: Dict[str, Any] = {"ws_url": url, "framing": framing,
                              "send_template": _ws_send_template(sent, prompt)
                              or {"type": "message", "text": "{{PROMPT}}"}}
    reply = _ws_reply_field(frames)
    if reply:
        params["response_path"] = reply
    done = _ws_done_marker(frames)
    if done:
        params["done_when"] = done
    # With a terminal frame the idle gap is only a fallback; without one it is the completion
    # rule and must outlast a normal pause between tokens.
    params["idle_ms"] = 1500 if done else 5000
    return params


def _guess_transcript(obj: Any) -> Dict[str, Any]:
    """Work out how to read a bot turn out of a transcript response.

    `session_poll` walks `list_path` for turns, filters on `role_field` against `bot_roles`, and
    reads the text at `text_path`. Those four were previously hardcoded to
    messages/role/[assistant,bot,agent]/text, which is right for maybe half of real transcript
    endpoints and silently wrong for the rest. Derived from the evidence instead.
    """
    out = {"list_path": "messages", "role_field": "role", "text_path": "text",
           "bot_roles": ["assistant", "bot", "agent", "ai", "system"]}
    best: Tuple[int, str, List[Any]] = (0, "", [])
    def walk(o: Any, prefix: str = "") -> None:
        nonlocal best
        if isinstance(o, list):
            dicts = [x for x in o if isinstance(x, dict)]
            if len(dicts) > best[0] and prefix:
                best = (len(dicts), prefix, dicts)
        elif isinstance(o, dict):
            for k, v in o.items():
                walk(v, f"{prefix}.{k}" if prefix else k)
    walk(obj)
    count, path, turns = best
    if not count:
        return out
    out["list_path"] = path
    sample = turns[0]
    # role: a short string field whose values look like speaker labels
    for k, v in sample.items():
        if isinstance(v, str) and len(v) <= 24 and k.lower() in (
                "role", "sender", "author", "from", "speaker", "type", "direction"):
            out["role_field"] = k
            break
    # text: the longest string field across the sampled turns, which is the message body
    longest = (0, "text")
    for turn in turns[:8]:
        for k, v in turn.items():
            if isinstance(v, str) and len(v) > longest[0] and k != out["role_field"]:
                longest = (len(v), k)
    if longest[0]:
        out["text_path"] = longest[1]
    # bot roles: any observed role value that is not the human side
    seen = {str(t.get(out["role_field"], "")).lower() for t in turns}
    seen.discard("")
    bots = sorted(seen - {"user", "human", "customer", "me", "client", "you", "in", "inbound"})
    if bots:
        out["bot_roles"] = bots
    return out


def _detect_poll(pairs: List[Dict[str, Any]], chat_idx: int) -> Optional[Dict[str, Any]]:
    """Find an ACK-only contract: (create) -> send-returns-ack -> poll a transcript.

    Rewritten because the params this emitted and the keys the composer read were two different
    schemas that were never connected: it published `submit`/`poll.endpoint_template`, while
    `_session_poll_from_poll` looked for `create_url`/`send_url`/`poll_url`. Every lookup missed,
    so the composed config carried three EMPTY urls and the adapter refused with "session_poll
    needs create.url, send.url and poll.url" -- unconditionally, for any evidence. The shape
    session_poll's own example calls "the most common enterprise web-chat contract" could
    therefore never be derived at all; it had to be hand-written every time.

    Two further fixes fall out of doing it properly:
      - the conversation id is often in the send URL (`/chat/{id}/message`), not just in the
        response body, so both are searched;
      - the CREATE call happens BEFORE the pair carrying the prompt, so it is found by looking
        backward. Only looking forward meant create was never captured even when present.
    """
    send = pairs[chat_idx]
    send_url_raw = _strip_query(send["request"]["url"])
    # the id may be in the send response, or already in the send URL
    sid = _first_id(send["response"]["json"])
    id_in_url = None
    if not sid:
        for cand in re.findall(r"/([0-9a-fA-F]{8,}|\d{3,})(?=/|$)", send_url_raw):
            id_in_url = cand
            break
        sid = id_in_url
    if not sid:
        return None
    sid = str(sid)

    # Take the LAST matching poll, not the first. A real capture contains the whole polling
    # loop, and the early responses are by definition incomplete -- the first GET fires before
    # the bot has answered, so sampling it derives the transcript shape from a transcript
    # containing only the user's turn. That is how `bot_roles` silently fell back to defaults
    # instead of being read from the evidence. The last response is the finished one.
    poll_pair = None
    for j in range(chat_idx + 1, len(pairs)):
        later = pairs[j]
        if later["request"]["method"] in ("GET", "POST") and sid in later["request"]["url"]:
            poll_pair = later
    if poll_pair is None:
        return None

    # The create step precedes the prompt-carrying pair. Its response mints the id.
    create = None
    for j in range(chat_idx - 1, -1, -1):
        prior = pairs[j]
        if prior["request"]["method"] != "POST":
            continue
        if sid in json.dumps(prior["response"]["json"] or ""):
            create = {"url": _strip_query(prior["request"]["url"]),
                      "method": prior["request"]["method"],
                      "body": _body_template(prior["request"]),
                      "extract": _id_field_of(prior["response"]["json"], sid) or "id"}
            break

    transcript = _guess_transcript(poll_pair["response"]["json"])
    poll_url = _strip_query(poll_pair["request"]["url"]).replace(sid, "{{CONV}}")
    q = _query_from_url(poll_pair["request"]["url"])
    if q:
        qs = "&".join(f"{k}={'{{CONV}}' if v == sid else v}" for k, v in q.items())
        poll_url = f"{poll_url}?{qs}"

    return {"value": "poll", "confidence": 0.8 if create else 0.6,
            "evidence": (f"send returned/carried id={sid!r}; "
                         f"{poll_pair['request']['method']} "
                         f"{_strip_query(poll_pair['request']['url'])} reads the transcript"
                         + ("" if create else "; no create call seen in the capture")),
            "params": {
                "create": create,
                "send": {"url": send_url_raw.replace(sid, "{{CONV}}"),
                         "method": send["request"]["method"],
                         "body": _body_template(send["request"])},
                "poll": {"url": poll_url,
                         "method": poll_pair["request"]["method"], **transcript},
                "id": sid,
                # kept for _session_api_from_poll, which reads the older schema
                "submit": {"endpoint": send_url_raw,
                           "method": send["request"]["method"],
                           "body": _body_template(send["request"])},
                "response_path": _guess_response_path(poll_pair["response"]["json"],
                                                      _REPLY_TEXT.get("v")),
            }}


# --------------------------------------------------------------------------- #
# Layer 2 — auth                                                              #
# --------------------------------------------------------------------------- #
def classify_auth(ev: Dict[str, Any], chat_idx: Optional[int]) -> Dict[str, Any]:
    if chat_idx is None:
        return {"value": "none", "confidence": 0.2, "evidence": "no chat pair", "params": {}}
    pairs = ev["pairs"]
    req = pairs[chat_idx]["request"]
    headers = req["headers"]
    query = req["query"]
    own = _registrable_host(req.get("url", ""))

    # Values produced by earlier responses (login/token/csrf), for reuse detection.
    prior_values = _collect_prior_values(pairs, chat_idx)

    # 1) Authorization header.
    authz = headers.get("authorization")
    if authz:
        low = authz.lower()
        if low.startswith("bearer "):
            token = authz.split(" ", 1)[1]
            origin = _reuse_origin(token, prior_values, own_host=own)
            if origin is not None:
                oi, ofield, ourl = origin
                if _looks_token_endpoint(ourl) and _has_access_token(pairs[oi]["response"]["json"]):
                    return _auth_oauth2(pairs[oi], ourl)
                return _auth_derived(pairs, chat_idx, oi, ofield, ourl)
            return {"value": "static", "confidence": 0.85,
                    "evidence": "constant 'Authorization: Bearer' on chat request",
                    "params": {"mode": "bearer", "name": "Authorization",
                               "value_ref": "env:DISCOVERED_TOKEN"}}
        if low.startswith("basic "):
            return {"value": "static", "confidence": 0.85,
                    "evidence": "HTTP Basic auth on chat request",
                    "params": {"mode": "basic", "username_ref": "env:BASIC_USER",
                               "password_ref": "env:BASIC_PASS"}}
        # custom scheme
        return {"value": "static", "confidence": 0.6,
                "evidence": f"custom Authorization scheme {authz.split(' ',1)[0]!r}",
                "params": {"mode": "custom", "name": "Authorization",
                           "template": authz.split(" ", 1)[0] + " {{VALUE}}",
                           "value_ref": "env:DISCOVERED_TOKEN"}}

    # 2) CSRF header echoed from a prior bootstrap.
    for h in _CSRF_HEADERS:
        if h in headers:
            origin = _reuse_origin(headers[h], prior_values, own_host=own)
            if origin is not None:
                oi, ofield, ourl = origin
                return {"value": "csrf", "confidence": 0.8,
                        "evidence": f"'{h}' echoes a token from GET {_strip_query(ourl)}",
                        "params": {"bootstrap_url": _strip_query(ourl),
                                   "extract": {"path": ofield} if ofield else {"regex": "TOKEN=([A-Za-z0-9_-]+)"},
                                   "into_header": _orig_header_name(pairs[chat_idx], h)}}
            # The token usually lives in the PAGE, not in a JSON response -- a <meta> tag, a
            # hidden input, or an inline JS assignment. `_collect_prior_values` only walks JSON
            # string leaves, so an HTML-borne token was invisible to it and this fell through to
            # the branch below, which emitted bootstrap_url:"" -- a config the auth layer refuses
            # outright ("csrf auth requires 'bootstrap_url'"). The auth layer has always been
            # able to regex a token out of an HTML bootstrap body; only the finding was missing.
            html = _html_token_origin(pairs, chat_idx, headers[h])
            if html is not None:
                hurl, hregex, hwhere = html
                return {"value": "csrf", "confidence": 0.75,
                        "evidence": f"'{h}' echoes the {hwhere} token in GET {_strip_query(hurl)}",
                        "params": {"bootstrap_url": _strip_query(hurl),
                                   "extract": {"regex": hregex},
                                   "into_header": _orig_header_name(pairs[chat_idx], h)}}
            # Origin genuinely not in the capture. Emitting a csrf block with an empty
            # bootstrap_url guarantees a hard failure at validate time and reads like a capture
            # problem, so say what is actually missing instead.
            return {"value": "csrf", "confidence": 0.5,
                    "evidence": f"CSRF-style header '{h}' present (origin not in capture)",
                    "params": {"bootstrap_url": "", "extract": {},
                               "into_header": _orig_header_name(pairs[chat_idx], h),
                               "_incomplete": (
                                   f"The request sends '{h}', but nothing in this capture shows "
                                   f"where that token comes from. Set bootstrap_url to the page "
                                   f"or endpoint that issues it and extract.regex/path to pull it "
                                   f"out -- or re-capture starting from the first page load, "
                                   f"which is usually what is missing.")}}

    # 3) API-key style headers.
    for name_lower, value in headers.items():
        if name_lower in _SECRET_HEADERS and name_lower not in ("authorization", "cookie"):
            return {"value": "static", "confidence": 0.8,
                    "evidence": f"API-key header '{name_lower}' on chat request",
                    "params": {"mode": "api_key", "in": "header",
                               "name": _orig_header_name(pairs[chat_idx], name_lower),
                               "value_ref": "env:DISCOVERED_API_KEY"}}

    # 4) API-key in query string.
    for qn in ("api_key", "apikey", "key", "token", "access_token"):
        if qn in query:
            return {"value": "static", "confidence": 0.7,
                    "evidence": f"API-key query param '{qn}'",
                    "params": {"mode": "api_key", "in": "query", "name": qn,
                               "value_ref": "env:DISCOVERED_API_KEY"}}

    # 5) Cookie session (possibly derived from a login).
    if "cookie" in headers:
        origin = _reuse_origin(headers["cookie"], prior_values, substring=True, own_host=own)
        if origin is not None:
            oi, ofield, ourl = origin
            return _auth_derived(pairs, chat_idx, oi, ofield, ourl, kind_hint="cookie")
        return {"value": "static", "confidence": 0.6,
                "evidence": "session Cookie on chat request",
                "params": {"mode": "cookie", "name": _cookie_name(headers["cookie"]),
                           "value_ref": "env:DISCOVERED_COOKIE"}}

    return {"value": "none", "confidence": 0.8,
            "evidence": "no secret observed on the chat request", "params": {}}


def _auth_oauth2(login_pair: Dict[str, Any], url: str) -> Dict[str, Any]:
    return {"value": "oauth2", "confidence": 0.75,
            "evidence": f"token endpoint {_strip_query(url)} precedes chat; access_token reused downstream",
            "params": {"grant": "client_credentials", "token_url": _strip_query(url),
                       "client_id_ref": "env:OAUTH_CLIENT_ID",
                       "client_secret_ref": "env:OAUTH_CLIENT_SECRET"}}


def _dot_value(data: Any, path: Optional[str]) -> Any:
    """Dot-path lookup used when checking where a derived value reappears."""
    if not path or data is None:
        return None
    cur = data
    for part in str(path).split("."):
        if isinstance(cur, list):
            try:
                cur = cur[int(part)]
                continue
            except (ValueError, IndexError):
                return None
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def _auth_derived(pairs: List[Dict[str, Any]], chat_idx: int, origin_idx: int,
                  field: Optional[str], url: str, kind_hint: str = "bearer") -> Dict[str, Any]:
    login = pairs[origin_idx]["request"]
    step = {
        "method": login["method"],
        "url": _strip_query(login["url"]),
        "extract": [{"path": field, "var": "AUTH_VALUE"}] if field
                   else [{"regex": "\"[^\"]*token[^\"]*\"\\s*:\\s*\"([^\"]+)\"", "var": "AUTH_VALUE"}],
    }
    if login.get("json") is not None:
        step["json"] = login["json"]
    # ATTACH IT WHERE IT WAS SEEN. This guessed `Cookie` or `Authorization` from a hint, and a
    # value that a target actually wants in a custom header — `X-Session-Token`, `X-CSRF-Token`,
    # the double-submit pattern, which is ordinary — was attached to the wrong one. MEASURED: a
    # bootstrap token that the capture shows being echoed in `X-Session-Token` was attached as a
    # Cookie, so every probe came back 403 and the derivation looked wrong rather than
    # mis-aimed. The evidence says where it goes; there is no need to guess.
    attach_header, attach_val = None, None
    try:
        observed = _dot_value(pairs[origin_idx]["response"].get("json"), field) if field else None
    except Exception:  # noqa: BLE001
        observed = None
    if observed:
        token = str(observed)
        for hname, hval in (pairs[chat_idx]["request"].get("headers") or {}).items():
            if hname.startswith(":") or not isinstance(hval, str) or token not in hval:
                continue
            attach_header = _canonical_header(hname)
            # Keep whatever wrapper the real request used — "Bearer x", "x", "k=x" — so a
            # prefix the target requires is not dropped on the way through.
            attach_val = hval.replace(token, "{{AUTH_VALUE}}")
            break
    if not attach_header:
        attach_header = "Cookie" if kind_hint == "cookie" else "Authorization"
        attach_val = "{{AUTH_VALUE}}" if kind_hint == "cookie" else "Bearer {{AUTH_VALUE}}"
    return {"value": "derived_multihop", "confidence": 0.7,
            "evidence": f"value from {login['method']} {_strip_query(login['url'])} reappears on the chat request",
            "params": {"steps": [step], "attach": {"headers": {attach_header: attach_val}},
                       "inputs": {}}}


# --------------------------------------------------------------------------- #
# Layer 3 — auth lifecycle                                                    #
# --------------------------------------------------------------------------- #
def classify_auth_lifecycle(ev: Dict[str, Any], chat_idx: Optional[int],
                            auth: Dict[str, Any]) -> Dict[str, Any]:
    pairs = ev["pairs"]

    # 401/403 -> re-auth -> retry pattern.
    for i, p in enumerate(pairs):
        if p["response"]["status"] in (401, 403):
            # a later successful request to the same endpoint = reauth+retry
            for j in range(i + 1, len(pairs)):
                if _same_endpoint(pairs[j]["request"], p["request"]) and pairs[j]["response"]["status"] < 400:
                    return {"value": "reauth_on_401", "confidence": 0.75,
                            "evidence": f"{p['response']['status']} then a successful retry on the same endpoint",
                            "params": {"challenge_statuses": [p["response"]["status"]]}}
            return {"value": "reauth_on_401", "confidence": 0.55,
                    "evidence": f"{p['response']['status']} challenge observed",
                    "params": {"challenge_statuses": [p["response"]["status"]]}}

    # JWT exp on the bearer token.
    if chat_idx is not None:
        authz = pairs[chat_idx]["request"]["headers"].get("authorization", "")
        if authz.lower().startswith("bearer "):
            claims = _jwt_claims(authz.split(" ", 1)[1])
            if claims and "exp" in claims:
                ttl = None
                if "iat" in claims:
                    ttl = int(claims["exp"]) - int(claims["iat"])
                return {"value": "refresh_on_ttl", "confidence": 0.7,
                        "evidence": f"bearer token is a JWT with exp{' (ttl≈%ss)' % ttl if ttl else ''}",
                        "params": {"ttl_s": ttl} if ttl else {}}

    # Set-Cookie churn -> cookie rotation.
    cookie_setters = sum(1 for p in pairs if any(
        k == "set-cookie" for k in p["response"]["headers"]))
    if cookie_setters >= 2:
        return {"value": "cookie_rotation", "confidence": 0.55,
                "evidence": f"Set-Cookie observed on {cookie_setters} responses",
                "params": {}}

    if auth.get("value") in ("oauth2", "csrf", "derived_multihop"):
        return {"value": "reauth_on_401", "confidence": 0.4,
                "evidence": "dynamic auth without an observed challenge; default to reauth_on_401",
                "params": {"challenge_statuses": [401]}}

    return {"value": "static", "confidence": 0.7,
            "evidence": "no expiry/challenge/cookie-churn observed", "params": {}}


# --------------------------------------------------------------------------- #
# Layer 4 — session / conversation                                            #
# --------------------------------------------------------------------------- #
def _host_of(url: str) -> str:
    """Hostname of a URL, lowercased. '' when it cannot be parsed."""
    try:
        from urllib.parse import urlsplit
        return (urlsplit(str(url)).netloc or "").lower()
    except Exception:
        return ""


def classify_session(ev: Dict[str, Any], chat_idx: Optional[int]) -> Dict[str, Any]:
    pairs = ev["pairs"]
    if chat_idx is None:
        return {"value": "stateless", "confidence": 0.3, "evidence": "no chat pair", "params": {}}

    # id-flow: an id produced by an earlier response reappears in a later request.
    #
    # Constrained to the CHAT endpoint's own host and to ids the chat call actually uses. Without
    # that, a real page's third-party traffic supplies the match by coincidence: on one live site
    # an Adobe Target (omtrdc.net) response id happened to recur later, so the classifier declared
    # the chat needed a session created at an analytics vendor and validation died there. A session
    # the chat request never uses is not the chat's session.
    chat_req = pairs[chat_idx]["request"]
    chat_host = _host_of(chat_req["url"])

    def _probe_turn(rid: Any) -> Optional[Dict[str, Any]]:
        # The turn to template the scored probe from is the SCORED PROMPT turn (chat_idx), which
        # carries prompt_sent — NOT the first id-using turn, which on a create-then-send target is
        # a session init/resume with no real message. MEASURED on a Sierra-hosted bot: the init
        # turn froze clientEvent.type="resume-session", left userMessageText empty, and mismapped
        # {{PROMPT}} into memory.variables.VisitorID, so every probe scored the greeting. Because
        # `_body_template` templates {{PROMPT}} BY VALUE (prompt_sent), sourcing the body from
        # chat_idx places {{PROMPT}} in the real message field and sets clientEvent.type="message"
        # automatically. Falls back to `later` only when chat_idx does not carry the flowed id.
        cr = pairs[chat_idx]["request"]
        if str(rid) in (cr.get("raw_body") or "") or str(rid) in cr.get("url", ""):
            return cr
        return None

    def _opener_before_scored(rid: Any) -> Optional[str]:
        # A create-then-send target mints a FRESH conversation per probe, so the scored probe is the
        # conversation's first message — and greeting-first bots (Sierra voice/IVR bots, for
        # one) answer only from the SECOND turn. When the capture shows a message-endpoint turn
        # before the scored prompt that carries the session but no real message (a session
        # init/resume), the probe would score the verbatim greeting, so a throwaway opener has to
        # go first. Returns the opener text, or None. Generic: keyed on the shape (a distinct init
        # turn to the message endpoint), no host names. PROVEN on a Sierra-hosted bot: with it, an sp_leak probe
        # returns the bot's real reply instead of the greeting.
        scored = pairs[chat_idx]["request"]
        for k in range(chat_idx):
            q = pairs[k]["request"]
            if _host_of(q["url"]) != chat_host:
                continue
            if (_same_endpoint(q, scored) and str(rid) in (q.get("raw_body") or "")
                    and _request_has_prompt(q) is None):
                return "hi"
        return None

    for i, p in enumerate(pairs):
        if _host_of(p["request"]["url"]) != chat_host:
            continue                      # a session for THIS chat comes from THIS service
        rid, rfield = _session_first_id(p["response"]["json"]), None
        if not rid:
            continue
        rfield = _id_field_of(p["response"]["json"], rid)
        for j in range(i + 1, len(pairs)):
            later = pairs[j]["request"]
            if _host_of(later["url"]) != chat_host:
                continue
            in_url = str(rid) in later["url"]
            in_body = str(rid) in (later["raw_body"] or "")
            # An id that lands in the message body must land in a CONVERSATION/SESSION-named field
            # to be the session. On a real page several minted values reach the chat body — a
            # static auth `token`, a `releaseHash` — and only the one in a conversation-shaped
            # field is the per-turn session. MEASURED on a Sierra-hosted bot: `token` (from
            # embedChatQuery) reached the chat body first and was wired as the session, so the
            # create call minted a token instead of the conversationID and no probe answered.
            if in_body and not in_url:
                try:
                    _lbody = json.loads(later["raw_body"] or "{}")
                except Exception:
                    _lbody = {}
                _field = (_id_field_of(_lbody, str(rid)) or "").split(".")[-1].lower()
                if _field not in ("conversationid", "conversation_id", "sessionid", "session_id",
                                  "threadid", "thread_id", "session", "conversation"):
                    continue              # lands in an auth/other field, not the session — keep looking
            if in_url or in_body:
                # The scored probe is templated from the SCORED PROMPT turn (chat_idx), not the
                # first id-using turn — see `_probe_turn`. A greeting-first target needs a throwaway
                # opener before the probe — see `_opener_before_scored`.
                msg_req = _probe_turn(rid) or later
                warmup = _opener_before_scored(rid)
                if in_url and re.search(rf"/[^/]*/{re.escape(str(rid))}(/|$)", later["url"]):
                    return {"value": "create_conversation", "confidence": 0.8,
                            "evidence": f"id {rfield}={rid!r} from step {i} appears in the URL path of step {j}",
                            "params": {"create_req": {"endpoint": _strip_query(p["request"]["url"]),
                                                      "method": p["request"]["method"],
                                                      "body": _body_template(p["request"])},
                                       "id_field": rfield,
                                       # The OBSERVED id, published so the body can be templated
                                       # from the same value the URL is. Without it the body kept
                                       # the recorded conversation's id forever.
                                       "id_value": str(rid),
                                       "warmup_message": warmup,
                                       "send_url_template": later["url"].replace(str(rid), "{{SESSION_ID}}")}}
                return {"value": "create_session", "confidence": 0.75,
                        "evidence": f"id {rfield}={rid!r} from step {i} injected into step {j}'s body",
                        "params": {"session_endpoint": _strip_query(p["request"]["url"]),
                                   "session_method": p["request"].get("method", "POST"),
                                   "session_body": _body_template(p["request"]),
                                   "session_extract": rfield,
                                   # the create response is JSON when the id came from a parsed body
                                   "session_response": "json" if isinstance(p["response"].get("json"), (dict, list)) else "frames",
                                   # a session key minted ALONGSIDE the id (Sierra: encryptionKey)
                                   "key_path": _key_path_in(p["response"].get("json")),
                                   "id_value": str(rid),
                                   # a throwaway opener for greeting-first bots, so the scored probe
                                   # is not the bot's verbatim first reply (None when not needed)
                                   "warmup_message": warmup,
                                   # the probe body comes from the SCORED turn, so {{PROMPT}} lands
                                   # in the real message field, not a session-init/tracking field
                                   "message_endpoint": _strip_query(msg_req["url"]),
                                   "message_body": _body_template(msg_req)}}

    # warmup: an early greeting turn distinct from the scored prompt.
    chat_prompt = _request_has_prompt(pairs[chat_idx]["request"])
    for i, p in enumerate(pairs):
        if i == chat_idx:
            continue
        pr = _request_has_prompt(p["request"])
        if pr and pr.strip().lower() in _GREETINGS and pr != chat_prompt:
            return {"value": "warmup", "confidence": 0.45,
                    "evidence": f"greeting turn {pr!r} precedes the scored prompt",
                    "params": {"warmup_message": pr}}

    # multiple turns to the same chat endpoint => multi_turn context server-side.
    same = sum(1 for p in pairs
               if _same_endpoint(p["request"], pairs[chat_idx]["request"])
               and _request_has_prompt(p["request"]))
    if same >= 2:
        return {"value": "multi_turn", "confidence": 0.55,
                "evidence": f"{same} prompt turns to the same endpoint (context held server-side)",
                "params": {}}

    return {"value": "stateless", "confidence": 0.7,
            "evidence": "each request independent; no id-flow or warmup", "params": {}}


# --------------------------------------------------------------------------- #
# Layer 5 — identity                                                          #
# --------------------------------------------------------------------------- #
def classify_identity(ev: Dict[str, Any], chat_idx: Optional[int]) -> Dict[str, Any]:
    pairs = ev["pairs"]
    # Per-user rate-limit hints or 429s suggest rotation *may* be warranted, but
    # identity is an operator decision, so default to fixed and note the hints.
    hints = []
    for p in pairs:
        rh = p["response"]["headers"]
        if any(k.startswith("x-ratelimit") or k == "ratelimit-remaining" for k in rh):
            hints.append("per-response rate-limit headers")
            break
    if any(p["response"]["status"] == 429 for p in pairs):
        hints.append("HTTP 429 observed")

    if hints:
        return {"value": "fixed", "confidence": 0.4,
                "evidence": "identity is an operator choice; rotation may help (" + "; ".join(sorted(set(hints))) + ")",
                "params": {"mode": "fixed", "per_user_ratelimit": True}}
    return {"value": "fixed", "confidence": 0.5,
            "evidence": "identity is an operator choice; defaulting to a single fixed identity",
            "params": {"mode": "fixed"}}


# --------------------------------------------------------------------------- #
# Layer 6 — rate / concurrency                                                #
# --------------------------------------------------------------------------- #
def classify_rate(ev: Dict[str, Any], session: Dict[str, Any]) -> Dict[str, Any]:
    pairs = ev["pairs"]
    stateful = session.get("value") in (
        "create_session", "create_conversation", "warmup", "multi_turn")
    max_workers = 1 if stateful else 10

    times = [p["started_ms"] for p in pairs if p.get("started_ms") is not None]
    times = sorted(times)
    qpm: Optional[int] = None
    evidence = "no request timing in capture; qpm left unset"
    if len(times) >= 2:
        gaps = [t2 - t1 for t1, t2 in zip(times, times[1:]) if t2 > t1]
        if gaps:
            median_gap = statistics.median(gaps)
            if median_gap > 0:
                qpm = max(1, int(60000.0 / median_gap))
                evidence = f"median inter-request gap {median_gap:.0f}ms -> ~{qpm} qpm observed"
    conf = 0.6 if qpm is not None else 0.5
    return {"value": "rate", "confidence": conf, "evidence": evidence,
            "params": {"qpm": qpm, "max_workers": max_workers}}


# --------------------------------------------------------------------------- #
# Compose                                                                      #
# --------------------------------------------------------------------------- #
# Host/URL substrings that map to a purpose-built preset adapter (integration
# TYPES, not customer names).
_PRESET_HOST_HINTS = (
    ("salesforce-scrt", "scrt2_direct"),
    ("einstein/ai-agent", "agentforce"),
    ("directline", "copilot_studio"),
    ("powerplatform", "copilot_studio"),
    ("direct.botframework", "copilot_studio"),
    ("slack.com", "slack_direct"),
    ("reasoningengines", "vertex_ai"),
    (":streamquery", "vertex_ai"),
    ("connectparticipant", "amazon_connect"),
    ("api.openai.com", "openai_compatible"),
    ("openai.azure.com", "openai_compatible"),
    ("dialogflow.googleapis.com", "dialogflow_cx"),
    (":detectintent", "dialogflow_cx"),
)


def _preset_for_url(url: str) -> Optional[str]:
    low = (url or "").lower()
    for hint, adapter in _PRESET_HOST_HINTS:
        if hint in low:
            return adapter
    return None


def _origin_of(url: str) -> str:
    m = re.match(r"(https?://[^/]+)", url or "")
    return m.group(1) if m else ""


def _field_from(text: str, keys) -> Optional[str]:
    """A config value out of a request body, whether it was JSON or form/query encoded."""
    from urllib.parse import unquote
    for k in keys:
        m = re.search(r'"%s"\s*:\s*"([^"]+)"' % re.escape(k), text or "")
        if m:
            return m.group(1)
        m = re.search(r'(?:^|[&?])%s=([^&\s]+)' % re.escape(k), text or "")
        if m:
            return unquote(m.group(1))
    return None


def _scrt2_config_from_evidence(ev: Dict[str, Any], endpoint: str) -> Dict[str, Any]:
    """Derive the Salesforce Embedded Messaging (SCRT2) adapter's four config fields FROM THE
    CAPTURE, so the agent wires the widget itself instead of reporting them "missing" and leaving
    the operator to hand-fill them. This is the whole class of `*.my.salesforce-scrt.com` chat
    widgets. scrt_base = the scrt host; org_id / developer_name / capabilities_ver = the
    authorization (accessToken) call body; widget_origin = the Origin those calls carried.
    Only fields it can actually derive are set; anything it cannot is left for validate to name."""
    pairs = ev.get("pairs", []) if isinstance(ev, dict) else []
    out: Dict[str, Any] = {}
    urls = [endpoint] + [str((p.get("request") or {}).get("url", "")) for p in pairs]
    for u in urls:
        if "salesforce-scrt.com" in (u or "").lower():
            out["scrt_base"] = _origin_of(u)
            break
    for p in pairs:
        req = p.get("request") or {}
        u = str(req.get("url", "")).lower()
        if "iamessage" in u and ("authorization" in u or "accesstoken" in u):
            body = req.get("json") if isinstance(req.get("json"), dict) else {}
            raw = req.get("raw_body") or ""
            oid = body.get("orgId") or body.get("org_id") or _field_from(raw, ("orgId", "org_id"))
            dev = (body.get("developerName") or body.get("esDeveloperName") or body.get("eswConfigDevName")
                   or _field_from(raw, ("developerName", "esDeveloperName", "eswConfigDevName")))
            cap = body.get("capabilitiesVersion") or _field_from(raw, ("capabilitiesVersion",))
            if oid:
                out["org_id"] = str(oid)
            if dev:
                out["developer_name"] = str(dev)
            if cap:
                out["capabilities_ver"] = str(cap)
            break
    for p in pairs:
        req = p.get("request") or {}
        if "salesforce-scrt.com" in str(req.get("url", "")).lower():
            origin = (req.get("headers") or {}).get("origin")
            if origin:
                out["widget_origin"] = origin.rstrip("/")
                break
    return out


# How each preset adapter fills its own config from the capture. A preset with no filler keeps the
# old behaviour (endpoint hint only); the ones here derive what they saw so the agent wires them
# without asking the operator for values already in the traffic.
def _chat_request_json(ev: Dict[str, Any], endpoint: str) -> Dict[str, Any]:
    """The JSON body of the captured request to `endpoint` (or the chat pair), {} when none."""
    pairs = ev.get("pairs") or []
    idx = ev.get("chat_pair_index")
    ordered = ([pairs[idx]] if isinstance(idx, int) and 0 <= idx < len(pairs) else []) + list(pairs)
    want = _strip_query(endpoint or "")
    for p in ordered:
        req = p.get("request") or {}
        if want and _strip_query(str(req.get("url") or "")) != want:
            continue
        body = req.get("json")
        if body is None:
            raw = req.get("raw_body") or req.get("body")
            if isinstance(raw, (dict, list)):
                body = raw
            elif isinstance(raw, str) and raw.strip().startswith("{"):
                try:
                    body = json.loads(raw)
                except ValueError:
                    body = None
        if isinstance(body, dict):
            return body
    return {}


def _openai_config_from_evidence(ev: Dict[str, Any], endpoint: str) -> Dict[str, Any]:
    """An OpenAI-compatible chat completions config from the capture: the endpoint, the model the
    page used, its system message when it carried one, and max_tokens. Credentials are handled
    by the captured-header path like any other target."""
    body = _chat_request_json(ev, endpoint)
    cfg: Dict[str, Any] = {"endpoint": endpoint}
    if isinstance(body.get("model"), str) and body["model"].strip():
        cfg["model"] = body["model"].strip()
    msgs = body.get("messages")
    if isinstance(msgs, list):
        for m in msgs:
            if isinstance(m, dict) and m.get("role") == "system" and isinstance(m.get("content"), str) and len(m["content"]) < 4000:
                cfg["system_prompt"] = m["content"]
                break
    if isinstance(body.get("max_tokens"), int):
        cfg["max_tokens"] = body["max_tokens"]
    return cfg


def _dialogflow_config_from_evidence(ev: Dict[str, Any], endpoint: str) -> Dict[str, Any]:
    body = _chat_request_json(ev, endpoint)
    cfg: Dict[str, Any] = {"endpoint": endpoint}
    qi = body.get("queryInput") if isinstance(body.get("queryInput"), dict) else {}
    if isinstance(qi.get("languageCode"), str):
        cfg["language_code"] = qi["languageCode"]
    return cfg


_PRESET_FILLERS = {"scrt2_direct": _scrt2_config_from_evidence,
                   "openai_compatible": _openai_config_from_evidence,
                   "dialogflow_cx": _dialogflow_config_from_evidence}


def compose(classified: Dict[str, Any]) -> Dict[str, Any]:
    """Fold the six classified layers into a runnable adapter config.

    Chooses the closest existing adapter for the detected transport (honouring
    platform host hints), then attaches the auth/identity/lifecycle/rate blocks.
    Secrets are referenced via ``env:`` placeholders, never inlined.
    """
    layers = classified["layers"] if "layers" in classified else classified
    ev = classified.get("evidence") if isinstance(classified, dict) else None
    transport = layers["transport"]
    auth = layers["auth"]
    lifecycle = layers["auth_lifecycle"]
    session = layers["session"]
    identity = layers["identity"]
    rate = layers["rate"]

    tp = transport.get("value")
    tparams = transport.get("params", {})
    endpoint = tparams.get("endpoint", "")

    # Preset host override (e.g. salesforce/slack/vertex) takes precedence.
    adapter = _preset_for_url(endpoint)

    config: Dict[str, Any] = {}
    if adapter is None:
        if tp == "sse":
            adapter = "sse_stream"
            base, path = _split_base_path(endpoint)
            config.update({"base_url": base, "chat_path": path,
                           "request_template": tparams.get("body", {"message": "{{PROMPT}}"}),
                           "stream": tparams.get("stream", {"format": "sse"})})
            if session.get("value") in ("create_session", "create_conversation"):
                config.update(_sse_create_from_session(session, config.get("chat_path", "")))
        elif tp == "ndjson":
            adapter = "sse_stream"
            base, path = _split_base_path(endpoint)
            stream = dict(tparams.get("stream", {})); stream["format"] = "ndjson"
            config.update({"base_url": base, "chat_path": path,
                           "request_template": tparams.get("body", {"message": "{{PROMPT}}"}),
                           "stream": stream})
            if session.get("value") in ("create_session", "create_conversation"):
                config.update(_sse_create_from_session(session, config.get("chat_path", "")))
        elif tp == "websocket":
            adapter = "websocket_direct"
            config.update({"ws_url": tparams.get("ws_url", ""),
                           "send_template": tparams.get("send_template", {"type": "message", "text": "{{PROMPT}}"}),
                           "idle_ms": tparams.get("idle_ms", 1500)})
            if tparams.get("framing"):
                config["framing"] = tparams["framing"]
            # the reply field and the terminal frame read off the captured frames
            if tparams.get("response_path"):
                config["response_path"] = tparams["response_path"]
            if tparams.get("done_when"):
                config["done_when"] = tparams["done_when"]
        elif tp == "sentinel_stream":
            adapter = "sentinel_stream"
            sess = session or {}
            sp = sess.get("params") or {}
            if sess.get("value") in ("create_session", "create_conversation") and sp.get("session_endpoint"):
                # CREATE-THEN-SEND. The target mints a fresh conversation id (and often a session
                # key) per turn; freezing them replays a dead session and scores nothing. Wire the
                # create call as a `start` step so the adapter mints a fresh one per probe, and
                # template the per-conversation values in the message body. MEASURED + PROVEN
                # against a Sierra-hosted support bot: create graphql -> {conversationID,
                # encryptionKey} -> chat answers.
                config.update({
                    "url": sp.get("message_endpoint") or endpoint,
                    "method": tparams.get("method", "POST"),
                    "begin_marker": tparams.get("begin_marker", "BOT_CHAT_EVENT_BEGIN"),
                    "end_marker": tparams.get("end_marker", "BOT_CHAT_EVENT_END"),
                    "start": {
                        "url": sp.get("session_endpoint"),
                        "method": sp.get("session_method", "POST"),
                        "body": sp.get("session_body", {}),
                        "response": sp.get("session_response", "json"),
                        "conv_path": sp.get("session_extract", "conversationID"),
                        "key_path": sp.get("key_path") or "encryptionKey",
                    },
                    "message": {"body": _template_session_fields(
                        sp.get("message_body") or tparams.get("body", {"message": "{{PROMPT}}"}))},
                })
                # A throwaway opener for greeting-first bots (Sierra voice/IVR): the adapter sends
                # it once per conversation before the scored probe, so the probe is not the bot's
                # verbatim first reply. Set only when discovery saw a session-init turn.
                if sp.get("warmup_message"):
                    config["warmup"] = sp["warmup_message"]
                # Each Ascend probe is scored independently, so the adapter re-mints the
                # conversation (fresh conversationID + encryptionKey) per probe rather than
                # accumulating probes in one conversation a bot would eventually end. Explicit in
                # the config so `target inspect` shows it and the operator can flip it off for a
                # genuinely multi-turn target.
                config["session_per_probe"] = True
            else:
                config.update({
                    "url": endpoint,
                    "method": tparams.get("method", "POST"),
                    "begin_marker": tparams.get("begin_marker", "BOT_CHAT_EVENT_BEGIN"),
                    "end_marker": tparams.get("end_marker", "BOT_CHAT_EVENT_END"),
                    "message": {"body": tparams.get("body", {"message": "{{PROMPT}}"})},
                })
        elif tp == "poll":
            # Generic watermark/transcript polling (create -> send -> GET-poll).
            adapter = "session_poll"
            config.update(_session_poll_from_poll(tparams))
        elif session.get("value") in ("create_session", "create_conversation"):
            adapter = "session_api"
            config.update(_session_api_from_session(session, tparams))
        else:  # rest_json (default)
            adapter = "direct_api"
            config.update({"endpoint": endpoint, "method": tparams.get("method", "POST"),
                           "body": tparams.get("body", {"prompt": "{{PROMPT}}"})})
            # Same trap as in _http_params, and it had to be fixed in both places: defaulting
            # response_path to "response" for a target that answered in plain text makes
            # direct_api demand JSON and fail, when omitting the key entirely makes the same
            # adapter treat the raw body as the answer. Only carry a path that was derived
            # from a body that really was JSON.
            if tparams.get("response_path"):
                config["response_path"] = tparams["response_path"]
            if tparams.get("stop_marker"):
                # the streaming terminator is transport, not the agent's words
                config["stop_marker"] = tparams["stop_marker"]
        # Session upgrade for a rest_json transport that actually has id-flow.
        if adapter == "direct_api" and session.get("value") in ("create_session", "create_conversation"):
            adapter = "session_api"
            config = _session_api_from_session(session, tparams)
    else:
        # Preset adapter: derive its own config from the capture where we know how, so the agent
        # wires it itself. A filler that cannot find a field leaves it out; validate names what is
        # still missing rather than the derivation guessing.
        config["_preset_endpoint"] = endpoint
        filler = _PRESET_FILLERS.get(adapter)
        if filler and isinstance(ev, dict):
            config.update({k: v for k, v in filler(ev, endpoint).items() if v})

    # Non-secret request headers.
    if tparams.get("headers"):
        config.setdefault("headers", {}).update(tparams["headers"])
    # Record the NAMES of any credential-shaped headers that were withheld, so the CLI can tell
    # the operator what to re-supply. Names only -- the values are exactly what must not persist.
    _held = tparams.get("withheld_headers")
    if _held:
        config["_withheld_headers"] = _held

    # Warmup preset support.
    if session.get("value") == "warmup":
        config["warmup_message"] = session["params"].get("warmup_message", "Hello")

    # Layer blocks (auth secrets always via env refs).
    if auth.get("value") and auth["value"] != "none":
        config["auth"] = _auth_block(auth)
    # THE CREDENTIAL THE CAPTURE ACTUALLY SAW.
    #
    # Everything above this line describes auth the classifier INFERRED. What the browser really
    # presented is `secret_header_values`, and until now it was discarded — so a target behind
    # any authentication at all, which is every target worth testing, was registered with a
    # config that could not authenticate. `classify_auth` emitted `env:DISCOVERED_TOKEN` for the
    # bearer case, a variable name that appears nowhere else in this repository except the docs.
    #
    # Replaying the header VERBATIM is deliberate, and it is why this is one block rather than a
    # mode per scheme. `Authorization: Bearer eyJ…`, `Cookie: sid=…`, `X-Window-Token: …` are all
    # just headers the target accepted thirty seconds ago. Reconstructing them from a parsed
    # scheme plus a token is a second chance to get the prefix wrong for no benefit.
    #
    # A DYNAMIC block is left alone. oauth2 / csrf / derived_multihop re-acquire credentials
    # during the run, which a captured value cannot do, so replacing one of those with a frozen
    # header would trade a working mechanism for an expiring one.
    _values = tparams.get("secret_header_values") or {}
    _dynamic = isinstance(config.get("auth"), dict) and \
        config["auth"].get("type") in ("oauth2", "csrf", "derived_multihop")
    _pairs = (ev or {}).get("pairs") if isinstance(ev, dict) else None
    _minted = minted_credentials(_values, _pairs or [], (ev or {}).get("chat_pair_index")
                                 if isinstance(ev, dict) else None,
                                 chat_url=tparams.get("secret_header_url") or endpoint or "") \
        if _values and not _dynamic else {}
    if _values and not _dynamic and _minted:
        # A credential the session MINTED (its value came back from an earlier call) is re-minted
        # before every probe; whatever else was captured stays static and rides along.
        _url = tparams.get("secret_header_url") or endpoint or ""
        static_refs = {name: f"env:{secret_var_name(_url, name)}" for name in sorted(_values) if name not in _minted}
        config["auth"] = _minted_auth_block(_minted, _pairs, static_refs)
        config["auth_lifecycle"] = {"type": "refresh_on_ttl", "ttl_s": 0}   # already stale = re-mint per probe
        config["_captured_credentials"] = sorted(static_refs)
        config["_minted_credentials"] = {name: {"from": _pairs[spec["pair"]]["request"].get("url", ""), "path": spec["path"]}
                                         for name, spec in _minted.items()}
    elif _values and not _dynamic:
        _url = tparams.get("secret_header_url") or endpoint or ""
        refs = {name: f"env:{secret_var_name(_url, name)}" for name in sorted(_values)}
        config["auth"] = {"type": "static", "mode": "headers", "headers": refs}
        # Not a lost cause, just not this mechanism's job — say so where it will be read.
        config["_captured_credentials"] = sorted(refs)
    elif _values and _dynamic:
        config["_captured_credentials_unused"] = {
            "headers": sorted(_values),
            "why": (f"the capture also saw {len(_values)} credential header(s), but this target "
                    f"authenticates with '{config['auth'].get('type')}', which re-acquires "
                    f"credentials during a run. A frozen header would expire mid-run; the live "
                    f"mechanism is kept instead."),
        }

    # THE CREDENTIAL THE CAPTURE SAW IN THE QUERY STRING. `?code=`, `?key=`, `?token=` — carried
    # by the chat request itself, previously stripped with the rest of the query and never
    # mentioned. Each becomes a static `api_key` part with `in: query`, which `layers/auth.py`
    # folds back into the endpoint at send time, so the value lives in the store and the config
    # holds a reference, exactly like a captured header. A live mechanism (oauth2 / csrf /
    # multihop / minted) is left alone for the same reason as above.
    _qvalues = tparams.get("secret_query_values") or {}
    if _qvalues and not _dynamic and not config.get("_minted_credentials"):
        _url = tparams.get("secret_header_url") or endpoint or ""
        qparts = [{"type": "static", "mode": "api_key", "in": "query", "name": name,
                   "value_ref": f"env:{secret_var_name(_url, 'query:' + name)}"}
                  for name in sorted(_qvalues)]
        existing = config.get("auth")
        if isinstance(existing, list):
            config["auth"] = [b for b in existing if _is_captured_static(b)] + qparts
        elif _is_captured_static(existing):
            config["auth"] = [existing] + qparts
        else:
            # Nothing captured beside it — including an INFERRED block whose reference nothing
            # sets (`env:DISCOVERED_TOKEN`), which would fail the whole list at materialize time.
            config["auth"] = qparts[0] if len(qparts) == 1 else qparts
        config["_captured_credentials"] = sorted(set(config.get("_captured_credentials") or [])
                                                 | {f"query:{n}" for n in _qvalues})
    # A minted credential already set its lifecycle (re-mint before every probe); the classified
    # lifecycle layer describes the static case and must not overwrite it.
    if not (config.get("_minted_credentials") and config.get("auth_lifecycle")):
        config["auth_lifecycle"] = _lifecycle_block(lifecycle)
    config["identity"] = {"mode": identity.get("params", {}).get("mode", "fixed")}

    # Rate / concurrency.
    rparams = rate.get("params", {})
    if rparams.get("qpm"):
        config["qpm"] = rparams["qpm"]
    # Only pin max_workers when the capture actually justified it. Writing a default of
    # 10 here overrode the relay's stateful=1 safety rule (recommended_workers knows the
    # full STATEFUL_ADAPTERS set, which classify_rate does not), so a discovered websocket/
    # sentinel/session_poll config would run 10 concurrent conversations and corrupt every
    # multi-turn chain. Leave it unset and let recommended_workers() decide.
    if "max_workers" in rparams and rparams["max_workers"] == 1:
        config["max_workers"] = 1

    config["adapter"] = adapter
    config["_discovery"] = {name: {"value": layers[name]["value"],
                                   "confidence": round(layers[name]["confidence"], 3)}
                            for name in LAYER_NAMES}
    return config


def _auth_block(auth: Dict[str, Any]) -> Dict[str, Any]:
    value, params = auth["value"], dict(auth.get("params", {}))
    block: Dict[str, Any] = {"type": value}
    block.update(params)
    return block


def _lifecycle_block(lifecycle: Dict[str, Any]) -> Dict[str, Any]:
    block: Dict[str, Any] = {"type": lifecycle["value"]}
    block.update(lifecycle.get("params", {}))
    return block


def _sse_stream_hints(body: str) -> Dict[str, Any]:
    """Derive `stream` hints (text_path / token_types / done_when) from a captured SSE body.

    Event-AWARE on purpose. These streams interleave the answer with progress chatter, and the
    two are told apart by the SSE ``event:`` name, not by a field inside the payload:

        event: status     data: {"message": "Analyzing query..."}       <- progress
        event: response   data: {"text": "the actual answer ..."}       <- the answer
        event: end        data: {...}                                   <- terminator

    Counting payload fields alone picks the field that appears MOST, which on a real stream is
    the progress chatter (three status frames beat two answer frames). A config built that way
    validates green and then feeds the scorer "Analyzing query... Searching resources..." for
    every probe — answered, complete, and measuring nothing. So the answer event is chosen by the
    volume of TEXT it carries, not by how often it fires.
    """
    if not body or "data:" not in body:
        return {}
    events: Dict[str, Dict[str, int]] = {}
    order: List[str] = []
    cur = None
    for line in str(body).splitlines():
        line = line.strip()
        if line.startswith("event:"):
            cur = line.split(":", 1)[1].strip()
            if cur and cur not in order:
                order.append(cur)
        elif line.startswith("data:"):
            raw = line.split(":", 1)[1].strip()
            try:
                obj = json.loads(raw)
            except Exception:
                continue
            if not isinstance(obj, dict):
                continue
            name = cur or "_"
            bucket = events.setdefault(name, {})
            for k, v in obj.items():
                if isinstance(v, str) and v.strip() and k not in _SSE_ID_FIELDS:
                    bucket[k] = bucket.get(k, 0) + len(v)
    if not events:
        return {}
    # the (event, field) pair carrying the most text is the answer
    best = None
    for ev, fields in events.items():
        for field, total in fields.items():
            if best is None or total > best[2]:
                best = (ev, field, total)
    if not best:
        return {}
    ev, field, _ = best
    hints: Dict[str, Any] = {"format": "sse", "text_path": field}
    if ev != "_":
        hints["token_types"] = [ev]
        for term in ("end", "done", "complete", "turn.done", "stream.end"):
            if term in events or term in order:
                hints["done_when"] = {"event": term}
                break
        return hints
    # No named events: the frames may carry the discriminator in a `type` field instead
    # ({"type":"token","content":…} … {"type":"done"}). Read it the same way — the type on the
    # frames that carried the answer text, and a terminal type — so the config says what the
    # stream does instead of leaning on the adapter's defaults. MEASURED on the SSE lab widget.
    types_text: Dict[str, int] = {}
    terminal = None
    for line in str(body).splitlines():
        line = line.strip()
        if not line.startswith("data:"):
            continue
        try:
            obj = json.loads(line.split(":", 1)[1].strip())
        except Exception:
            continue
        if not isinstance(obj, dict) or not isinstance(obj.get("type"), str):
            continue
        t = obj["type"]
        if t.strip().lower() in _WS_DONE_VALUES:
            terminal = t
        elif isinstance(obj.get(field), str):
            types_text[t] = types_text.get(t, 0) + len(obj[field])
    if types_text:
        hints["token_types"] = [max(types_text.items(), key=lambda kv: kv[1])[0]]
    if terminal:
        hints["done_when"] = {"path": "type", "equals": terminal}
    return hints


def _sse_create_from_session(session: Dict[str, Any], chat_path: str) -> Dict[str, Any]:
    """Turn a detected create-then-stream session into `sse_stream`'s `create` block.

    compose() picks ONE branch by transport, and the `sse` branch never consulted the session
    layer — only `direct_api` got a "session upgrade". So a create-then-stream target (create a
    thread, then stream the turn) was composed as a plain SSE POST to the captured path, which
    still contains the conversation id from the capture. Every probe then posted into that one
    dead conversation from whenever the evidence was recorded, and the create step vanished even
    though the classifier had detected it at 0.8 confidence.
    """
    p = session.get("params", {}) or {}
    create_req = p.get("create_req") or {}
    url = create_req.get("endpoint") or p.get("session_endpoint") or ""
    if not url:
        return {}
    out: Dict[str, Any] = {"create": {
        "url": url,
        "method": create_req.get("method", "POST"),
        "body": create_req.get("body") or {},
        "id_path": p.get("id_field", "id"),
        "id_mode": "server",
        # A fresh conversation per probe: the prompt is frequently part of the CREATE call too
        # (a thread named after the question), and reusing one conversation would both stale that
        # and let probes read each other's turns as their own context.
        "per_prompt": True,
    }}
    # Replace the captured conversation id in the chat path with {{CONV}}, which sse_stream
    # substitutes per prompt. The send-url template tells us where the id sits.
    tmpl, marker = p.get("send_url_template") or "", "{{SESSION_ID}}"
    if tmpl and marker in tmpl and chat_path:
        from urllib.parse import urlsplit
        prefix = urlsplit(tmpl.split(marker)[0]).path
        if prefix and chat_path.startswith(prefix):
            rest = chat_path[len(prefix):]
            seg, _, suffix = rest.partition("/")
            if seg and seg != "{{CONV}}":
                out["chat_path"] = prefix + "{{CONV}}" + (("/" + suffix) if suffix else "")
    return out


def _template_session_id(body: Any, observed_id: Any, variable: str = "SESSION_ID") -> Any:
    """Replace the id captured during the recording with `{{SESSION_ID}}` wherever it appears.

    The URL was templated and the BODY was not, so a derived session_api config sent the id of
    the conversation that happened to be open when the capture was taken — forever. MEASURED on
    a target documented as wanting the id "in URL AND body": the adapter created a fresh thread,
    addressed it correctly in the path, and posted the OLD id in the body. Every probe came back
    400, which reads as a broken target rather than a broken config.

    Worth stating plainly: a stale id in a body is the kind of defect that survives a green
    wire-time check on some targets and fails only under a real run, because the recorded
    conversation is often still alive when the check runs and dead by the time probes start.
    """
    if not observed_id:
        return body
    token = str(observed_id)
    placeholder = "{{%s}}" % variable
    if isinstance(body, str):
        return body.replace(token, placeholder)
    if isinstance(body, dict):
        return {k: _template_session_id(v, token, variable) for k, v in body.items()}
    if isinstance(body, list):
        return [_template_session_id(v, token, variable) for v in body]
    return body


def _session_api_from_session(session: Dict[str, Any], tparams: Dict[str, Any]) -> Dict[str, Any]:
    p = session.get("params", {})
    if session["value"] == "create_conversation":
        create = p.get("create_req", {})
        return {
            "session_endpoint": create.get("endpoint", ""),
            "session_body": create.get("body", {}),
            "session_extract": p.get("id_field", "id"),
            "session_variable": "SESSION_ID",
            "message_endpoint": p.get("send_url_template", ""),
            "message_body": _template_session_id(
                tparams.get("body", {"message": "{{PROMPT}}"}), p.get("id_value")),
            "response_path": tparams.get("response_path", "messages.0.message"),
        }
    return {
        "session_endpoint": p.get("session_endpoint", ""),
        "session_extract": p.get("session_extract", "sessionId"),
        "session_variable": "SESSION_ID",
        "message_endpoint": p.get("message_endpoint", ""),
        "message_body": _template_session_id(
            p.get("message_body", tparams.get("body", {"message": "{{PROMPT}}"})),
            p.get("id_value") or p.get("session_id_value")),
        "response_path": tparams.get("response_path", "messages.0.message"),
    }


def _session_poll_from_poll(tparams: Dict[str, Any]) -> Dict[str, Any]:
    """Build a session_poll config from the create/send/poll blocks `_detect_poll` publishes.

    This used to read `create_url`, `send_url`, `poll_url`, `id_path`, `list_path`, `text_path` --
    none of which the detector has ever emitted. Every `.get()` fell through to its default, so
    the result was always three empty URLs plus plausible-looking guesses
    (`extract: conversation_id`, `text_path: text`), and the adapter refused it. Reads the real
    schema now, and carries the detector's derived transcript shape rather than re-guessing it.
    """
    create = tparams.get("create") or {}
    send = tparams.get("send") or {}
    poll = tparams.get("poll") or {}
    cfg: Dict[str, Any] = {
        "create": {"url": create.get("url", ""),
                   "method": create.get("method", "POST"),
                   "body": create.get("body", {}),
                   "extract": create.get("extract", "conversation_id")},
        "send": {"url": send.get("url", ""),
                 "method": send.get("method", "POST"),
                 "body": send.get("body", {"message": "{{PROMPT}}"})},
        "poll": {"url": poll.get("url", ""),
                 "method": poll.get("method", "GET"),
                 "list_path": poll.get("list_path", "messages"),
                 "role_field": poll.get("role_field", "role"),
                 "bot_roles": poll.get("bot_roles", ["assistant", "bot", "agent"]),
                 "text_path": poll.get("text_path", "text"),
                 "interval_ms": 1000, "timeout_ms": 30000},
    }
    if not create:
        # A two-step job API (submit -> GET status until done) has no create call to find, and
        # session_poll requires one -- it models create/send/poll-a-transcript, not a job. Say so
        # in the config rather than emitting an empty url and letting the adapter fail with a
        # message that reads like a capture problem.
        cfg["_note"] = (
            "No create call was found in the capture. session_poll models "
            "create-conversation -> send -> poll-a-transcript (the ACK-only web-chat contract). "
            "If this target is instead a two-step job API (POST returns a job id, GET polls its "
            "status until done), no shipped adapter covers that shape: set create.url to the "
            "submit endpoint and send.url to the same, or use --module for a custom adapter.")
    return cfg


def _session_api_from_poll(tparams: Dict[str, Any]) -> Dict[str, Any]:
    submit = tparams.get("submit", {})
    poll = tparams.get("poll", {})
    return {
        "session_endpoint": submit.get("endpoint", ""),
        "session_body": submit.get("body", {}),
        "session_extract": poll.get("id_field", "id"),
        "session_variable": "ID",
        "message_endpoint": poll.get("endpoint_template", ""),
        "message_body": {},
        "response_path": tparams.get("response_path", "response"),
        "_note": "poll transport approximated via session_api (submit + fetch); verify polling semantics",
    }


# --------------------------------------------------------------------------- #
# Top-level entry point                                                        #
# --------------------------------------------------------------------------- #
def classify_evidence(evidence: Dict[str, Any]) -> Dict[str, Any]:
    """Run every layer classifier, compose a config, and report resolution.

    Returns::

        {
          "layers": {<name>: {value, params, confidence, evidence}, ...},
          "config": {...runnable adapter config...},
          "overall_confidence": float,   # the weakest layer's confidence
          "unresolved": [<layer names below the confidence floor / unvalued>],
        }
    """
    ev = _evidence(evidence)
    chat_idx = _pick_chat_index(ev["pairs"], (evidence or {}).get("prompt_sent"))

    transport = classify_transport(ev, chat_idx)
    auth = classify_auth(ev, chat_idx)
    lifecycle = classify_auth_lifecycle(ev, chat_idx, auth)
    session = classify_session(ev, chat_idx)
    identity = classify_identity(ev, chat_idx)
    rate = classify_rate(ev, session)

    layers = {
        "transport": transport, "auth": auth, "auth_lifecycle": lifecycle,
        "session": session, "identity": identity, "rate": rate,
    }
    config = compose({"layers": layers, "evidence": ev})


    # Lift the captured credential VALUES out of `layers` and into their own key, then delete
    # them from the layer params. Two reasons, and the second is the one that matters:
    #
    #   1. The caller needs them, to put in the 0600 store before it validates or registers.
    #   2. `layers` is returned to the caller and is the natural thing to print, log or attach to
    #      a support bundle — `--json` emits it wholesale. A credential reachable at
    #      `layers.transport.params.secret_header_values` is a credential that ends up in a
    #      ticket. Having exactly one place to look after this point is worth the extra step.
    tp = layers.get("transport", {}).get("params") or {}
    secrets = {}
    if tp.get("secret_header_values"):
        url = tp.get("secret_header_url") or ""
        secrets = {secret_var_name(url, name): value
                   for name, value in tp["secret_header_values"].items()}
    if tp.get("secret_query_values"):
        url = tp.get("secret_header_url") or ""
        secrets.update({secret_var_name(url, "query:" + name): value
                        for name, value in tp["secret_query_values"].items()})
    tp.pop("secret_header_values", None)
    tp.pop("secret_query_values", None)
    tp.pop("secret_header_url", None)

    unresolved = [name for name in LAYER_NAMES
                  if layers[name]["value"] is None or layers[name]["confidence"] < LOW_CONF]
    overall = min((layers[n]["confidence"] for n in LAYER_NAMES), default=0.0)
    return {
        "layers": layers,
        "config": config,
        "secrets": secrets,
        "overall_confidence": round(overall, 3),
        "unresolved": unresolved,
        "chat_pair_index": chat_idx,
    }


# --------------------------------------------------------------------------- #
# Small shared helpers                                                         #
# --------------------------------------------------------------------------- #
def _nonsecret_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """Keep request headers that are safe to bake into a config (drop secrets)."""
    keep = {}
    drop = _SECRET_HEADERS | _CSRF_HEADERS | {
        "content-length", "host", "connection", "accept-encoding",
    }
    for k, v in headers.items():
        if k in drop or k.startswith(":"):     # ':authority' etc. — HTTP/2 internals
            continue
        if _looks_secret_header(k, v):
            # A credential under a name we did not anticipate. Dropping it is the whole promise
            # of this function; `dropped_secret_headers()` tells the operator what to re-supply.
            continue
        # Preserve a canonical-ish casing for a couple of common headers.
        keep[_canonical_header(k)] = v
    return keep


def dropped_secret_headers(headers: Dict[str, str]) -> List[str]:
    """Names (only) of headers withheld from a config because they look like credentials.

    Silently dropping a header the target requires just moves the confusion: the config then 401s
    for no visible reason. The names are safe to print; the values never are.
    """
    return sorted(_canonical_header(k) for k, v in headers.items()
                  if not k.startswith(":") and k not in _NEVER_SECRET
                  and _looks_secret_header(k, v))


def captured_secret_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """The credential headers WITH their values — `{Canonical-Name: value}`.

    The counterpart to `dropped_secret_headers`, which names them and nothing else. Keeping the
    value is the whole point of watching a signed-in session: the browser presented exactly what
    the target requires, and a capture that discards it produces a target that can never
    authenticate. MEASURED: 10 probes leased, 10 delivered, **0 answered**, because the endpoint
    wanted an `X-Window-Token` that had been seen, recognised, and thrown away.

    What is returned here must never be written into a config file. `compose` puts an `env:`
    reference in the config and the caller puts the value in the 0600 store — which is the
    arrangement `layers/auth.py` has specified from the beginning and that this path never used.
    """
    return {_canonical_header(k): v for k, v in headers.items()
            if not k.startswith(":") and k not in _NEVER_SECRET
            and isinstance(v, str) and v.strip()
            and _looks_secret_header(k, v)}


def _json_path_to_value(obj: Any, value: str, prefix: str = "") -> Optional[str]:
    """Dot-path of the first string leaf equal to `value`, or None. `data.token`, `token`, `items.0.id`."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            here = f"{prefix}.{k}" if prefix else str(k)
            if isinstance(v, str) and v == value:
                return here
            found = _json_path_to_value(v, value, here)
            if found:
                return found
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            here = f"{prefix}.{i}" if prefix else str(i)
            if isinstance(v, str) and v == value:
                return here
            found = _json_path_to_value(v, value, here)
            if found:
                return found
    return None


def _registrable_host(url: str) -> str:
    """`api.shop.example.com` -> `example.com`-ish: the last two labels, enough to tell a widget's own
    API from a third-party challenge or identity host."""
    from urllib.parse import urlparse  # noqa: PLC0415
    host = (urlparse(url or "").hostname or "").lower()
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def minted_credentials(values: Dict[str, str], pairs: List[Dict[str, Any]],
                       chat_idx: Optional[int], chat_url: str = "") -> Dict[str, Dict[str, Any]]:
    """Which captured credential headers were MINTED by an earlier call in the same session.

    A header whose value appears verbatim in the JSON body of a prior response (a create-conversation
    call handing back `{"conversation_id": …, "token": …}`) is not a static credential: it was minted
    for that conversation and a replay with it frozen works only until the conversation ends or
    expires. MEASURED on a lab widget: a direct app registered with the captured `X-Conv-Token`
    answered every probe through the ONE captured conversation — right answers, wrong mechanism, and
    a false clean run on any widget whose tokens expire. Returns `{header: {"pair": i, "path": …}}`.
    """
    out: Dict[str, Dict[str, Any]] = {}
    if not values or not pairs:
        return out
    upto = len(pairs) if chat_idx is None else max(0, chat_idx)
    own = _registrable_host(chat_url) if chat_url else ""
    for name, value in values.items():
        if not isinstance(value, str) or len(value) < 8:
            continue
        for i in range(upto):
            pair = pairs[i]
            req = pair.get("request") or {}
            # A minter is the widget's OWN API. A token handed out by a third-party host — a WAF's
            # challenge endpoint, a CAPTCHA, an identity provider — is a challenge answer, not a
            # conversation the adapter can re-create: MEASURED, the bot-challenge token endpoint
            # got replayed as a "create call" and failed every time. Same registrable domain only.
            if own and _registrable_host(req.get("url", "")) != own:
                continue
            # a call that SENDS the value is a consumer of it, never the minter
            sent = " ".join(str(v) for v in (req.get("headers") or {}).values())
            if value in sent:
                continue
            body = (pair.get("response") or {}).get("json")
            path = _json_path_to_value(body, value) if body is not None else None
            if path:
                out[name] = {"pair": i, "path": path}
                break
    return out


def _minted_auth_block(minted: Dict[str, Dict[str, Any]], pairs: List[Dict[str, Any]],
                       static_refs: Dict[str, str]) -> Dict[str, Any]:
    """A derived_multihop block: re-run the minting call before every probe, attach what it hands back.

    One minting call (the common case; several minted headers from the same call are all extracted).
    The static credentials the capture also saw (an access cookie, a tenant key) ride on the minting
    call and on the probe as env: references, resolved by layers/auth at request time.
    """
    first = next(iter(minted.values()))["pair"]
    create = pairs[first]["request"]
    step: Dict[str, Any] = {"method": create.get("method", "POST"), "url": create.get("url", "")}
    if create.get("json") is not None:
        step["json"] = create["json"]
    step_headers = {k: v for k, v in _nonsecret_headers(create.get("headers") or {}).items()
                    if k.lower() in ("content-type", "accept", "origin", "referer")}
    step_headers.update(static_refs)
    if step_headers:
        step["headers"] = step_headers
    step["extract"] = [{"var": f"MINTED_{i}", "path": spec["path"]}
                       for i, (name, spec) in enumerate(minted.items()) if spec["pair"] == first]
    attach = {name: f"{{{{MINTED_{i}}}}}" for i, (name, spec) in enumerate(minted.items()) if spec["pair"] == first}
    attach.update(static_refs)
    return {"type": "derived_multihop", "steps": [step], "attach": {"headers": attach}}



def _is_captured_static(block: Any) -> bool:
    """A static auth block whose every reference points at the capture store (never a reference
    nothing sets, like the inferred `env:DISCOVERED_TOKEN`)."""
    if not isinstance(block, dict) or block.get("type") != "static":
        return False
    refs = list((block.get("headers") or {}).values()) if block.get("mode") == "headers" \
        else [block.get("value_ref") or block.get("value")]
    return bool(refs) and all(isinstance(r, str) and r.startswith("env:ASCEND_SECRET_") for r in refs)


def secret_var_name(url: str, header: str) -> str:
    """The environment-variable name for one (target, header) credential.

    Host-scoped, because `env:DISCOVERED_TOKEN` — the name this module emitted for years — is
    the same string for every target anyone ever captures. Two targets in one shell would have
    overwritten each other, which is only invisible because nothing ever set it: grep the repo
    and `DISCOVERED_TOKEN` appears at its emission sites and in the docs, and nowhere else. It
    was a reference to a variable that by construction did not exist.
    """
    from urllib.parse import urlparse  # noqa: PLC0415
    host = ""
    try:
        host = (urlparse(url or "").hostname or "").strip()
    except ValueError:
        host = ""
    slug = re.sub(r"[^A-Z0-9]+", "_", f"{host}_{header}".upper()).strip("_")
    return f"ASCEND_SECRET_{slug}" if slug else "ASCEND_SECRET_TARGET"

def _canonical_header(name_lower: str) -> str:
    special = {"content-type": "Content-Type", "user-agent": "User-Agent",
               "accept": "Accept", "accept-language": "Accept-Language"}
    return special.get(name_lower, "-".join(w.capitalize() for w in name_lower.split("-")))


def _orig_header_name(pair: Dict[str, Any], lower: str) -> str:
    # We stored headers lowercased; return a canonicalized display name.
    return _canonical_header(lower)


_SESSION_KEY_NAMES = ("encryptionkey", "encryption_key", "sessionkey", "session_key",
                     "secret", "sessionsecret")
_NONCE_NAMES = ("idempotencykey", "idempotency_key", "nonce", "windowid", "window_id",
                "requestid", "request_id", "messageid", "message_id")


def _key_path_in(obj: Any) -> Optional[str]:
    """Dot-path to a session KEY minted beside the conversation id (Sierra's encryptionKey), or
    None. Same walk as `_id_field_of` but matched on the field NAME, since the value is opaque."""
    def walk(o: Any, prefix: str) -> Optional[str]:
        if isinstance(o, dict):
            for k, v in o.items():
                if str(k).lower() in _SESSION_KEY_NAMES and isinstance(v, (str, int)):
                    return f"{prefix}{k}"
                r = walk(v, f"{prefix}{k}.")
                if r:
                    return r
        elif isinstance(o, list):
            for i, v in enumerate(o):
                r = walk(v, f"{prefix}{i}.")
                if r:
                    return r
        return None
    return walk(obj, "") if obj is not None else None


def _template_session_fields(body: Any) -> Any:
    """Replace a captured message body's per-conversation VALUES with the adapter's tokens by
    FIELD NAME: conversationID -> {{CONV}}, an encryption/session key -> {{KEY}}, an idempotency
    key / nonce / window id -> a fresh {{UUID}} per request. Leaves {{PROMPT}} and everything else
    as it was. This is what turns a frozen static replay into a per-probe create-then-send."""
    def walk(o: Any) -> Any:
        if isinstance(o, dict):
            out = {}
            for k, v in o.items():
                lk = str(k).lower()
                if lk in ("conversationid", "conversation_id", "threadid", "thread_id") and isinstance(v, str):
                    out[k] = "{{CONV}}"
                elif lk in _SESSION_KEY_NAMES and isinstance(v, str):
                    out[k] = "{{KEY}}"
                elif lk in _NONCE_NAMES and isinstance(v, str):
                    out[k] = "{{UUID}}"
                else:
                    out[k] = walk(v)
            return out
        if isinstance(o, list):
            return [walk(x) for x in o]
        return o
    return walk(body)


def _body_template(req: Dict[str, Any]) -> Any:
    """Turn a captured request body into a template with ``{{PROMPT}}``."""
    body = req.get("json")
    prompt = _request_has_prompt(req)
    if isinstance(body, (dict, list)):
        # Only a NON-EMPTY prompt can be templated by substitution. An empty one (a create call
        # recorded with {"message": ""}) made str.replace("", "{{PROMPT}}") insert the placeholder
        # between every character, and json.loads then failed at char 1 — reported to the operator
        # as "the HAR parser dies on char 1", which sent an afternoon looking at the wrong file.
        if prompt:
            replaced = json.loads(json.dumps(body).replace(json.dumps(prompt)[1:-1], "{{PROMPT}}"))
            return replaced
        return body
    if isinstance(body, str) and body:
        return "{{PROMPT}}"
    return {"prompt": "{{PROMPT}}"}


def _paths_to_strings(obj: Any, prefix: str = "") -> List[Tuple[str, str]]:
    """Every (dot_path, string_value) in a nested JSON structure."""
    out: List[Tuple[str, str]] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.extend(_paths_to_strings(v, f"{prefix}.{k}" if prefix else str(k)))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            out.extend(_paths_to_strings(v, f"{prefix}.{i}" if prefix else str(i)))
    elif isinstance(obj, str):
        out.append((prefix, obj))
    return out


def _guess_response_path(resp_json: Any, reply_text: Optional[str] = None) -> str:
    """Dot-path to the answer text in a JSON response body.

    Every rule below selects ONE string, so each of them can land on a single block of a
    multi-block answer. The generalization is applied HERE, at the one exit, rather than at each
    `return` — the first attempt patched only the last branch and the onboarding flow, which
    reaches an earlier one, still derived `content.1.text` against a live target.
    """
    return _generalize_block_index(
        resp_json, _prefer_last_turn(resp_json, _guess_response_path_raw(resp_json, reply_text)))


_ASSISTANT_ROLES = {"assistant", "bot", "ai", "model", "agent", "system_response"}


def _role_of(item):
    """The role on a list item, or on its single nested message object.

    Both spellings are everywhere: `{"role": …, "content": …}` (a transcript) and
    `{"message": {"role": …, "content": …}}` (OpenAI-style choices). Reading only the top level
    made a list of alternative COMPLETIONS look like blocks of one message, and the block rule
    then concatenated two answers to the same question — which its own docstring says it must not
    do to `choices.0.message.content`.
    """
    if not isinstance(item, dict):
        return None
    r = item.get("role")
    if isinstance(r, str):
        return r.lower()
    nested = [v for v in item.values() if isinstance(v, dict) and isinstance(v.get("role"), str)]
    return nested[0]["role"].lower() if len(nested) == 1 else None


def _is_turn_list(parent):
    """True when every element is a role-tagged turn or alternative — never blocks of one message."""
    return (isinstance(parent, list) and len(parent) > 1
            and all(_role_of(x) is not None for x in parent))


def _is_transcript(parent):
    """A turn list with MIXED roles: a real conversation, so the answer is the last agent turn.
    All-assistant means alternative completions, where the FIRST is the answer and the index the
    deriver already chose is right."""
    roles = {_role_of(x) for x in parent} if _is_turn_list(parent) else set()
    return bool(roles - _ASSISTANT_ROLES) and bool(roles & _ASSISTANT_ROLES)


def _prefer_last_turn(resp_json, path):
    """Point a transcript path at the LAST assistant turn instead of whichever one was longest.

    A target that returns the whole conversation — a gateway envelope, a GraphQL mutation that
    replies with `messages` — carries the probe's own prompt as turn 0 and the answer last. Every
    rule above selects one string by length or by key name, so on such a body the deriver could
    land on the ECHO of the prompt: the run then scores the attacker's own text as the agent's
    reply, which is a finding-shaped result from nothing at all. The probe's echo check catches
    that for the whole body, not for one path inside it.

    Only a list of ROLE-TAGGED dicts is touched, and only to move the index within it, so a
    `choices.0.message.content` (alternative completions, not a transcript) is left alone.
    """
    if not isinstance(path, str) or "." not in path:
        return path
    parts = path.split(".")
    for i, seg in enumerate(parts):
        if not (seg.isdigit() or (seg.startswith("-") and seg[1:].isdigit())):
            continue
        parent = _dot(resp_json, ".".join(parts[:i])) if i else resp_json
        if not _is_transcript(parent):
            continue
        leaf = ".".join(parts[i + 1:])
        last = None
        for j, item in enumerate(parent):
            if _role_of(item) not in _ASSISTANT_ROLES:
                continue
            val = _dot(item, leaf) if leaf else item
            if isinstance(val, str) and val.strip():
                last = j
        if last is None or str(last) == seg:
            return path
        return ".".join(parts[:i] + [str(last)] + parts[i + 1:])
    return path


def _guess_response_path_raw(resp_json: Any, reply_text: Optional[str] = None) -> str:
    """GROUND TRUTH FIRST: if the capture read the bot's reply off the page, the correct
    path is the one whose value matches it. Otherwise fall back to well-known keys, then
    to the longest string ANYWHERE in the body (not just at the top level — answers are
    usually nested, e.g. data.answer, while short status flags sit on top).
    """
    if not isinstance(resp_json, (dict, list)):
        return "response"

    candidates = _paths_to_strings(resp_json)

    if reply_text:
        needle = " ".join(reply_text.split())[:120].strip()
        core = needle.split(":", 1)[-1].strip() if ":" in needle[:20] else needle
        best = None
        for path, val in candidates:
            v = " ".join(val.split())
            if not v:
                continue
            if v in needle or needle in v or (core and (core in v or v in core)):
                if best is None or len(v) > len(best[1]):
                    best = (path, v)
        if best:
            return best[0]

    for path in _RESPONSE_PATH_GUESSES:
        val = _dot(resp_json, path)
        if isinstance(val, str) and val.strip():
            return path

    # Longest string anywhere beats longest top-level string — but never an identifier. An id is
    # usually the longest string in an acknowledgement body and it changes per request, so picking
    # it made two different questions "answer" differently and passed the constant-reply guard.
    real = [(p, v) for p, v in candidates if v.strip() and not _is_identifier_leaf(p, v)]
    if real:
        return max(real, key=lambda pv: len(pv[1]))[0]
    return "response"


def _generalize_block_index(resp_json: Any, path: str) -> str:
    """Turn ``content.1.text`` into ``content.*.text`` when the siblings hold text too.

    Every rule above picks ONE string, which is wrong for the shape where the answer arrives as
    several content blocks — the Anthropic/Bedrock messages shape, and common enough that it turns
    up in ordinary gateway responses. "Longest string anywhere" then selects whichever block
    happens to be longest and the rest of the answer is discarded on every request.

    Measured on a two-block target: the deriver chose ``content.1.text`` and both the onboarding
    reply and `target check`'s "verified answer" began mid-sentence. Nothing flagged it, because
    every gate the tool had was satisfied — a string was returned. The cost is silent and total:
    block 0 leads the message, so a leaked system prompt is exactly what gets thrown away, and the
    assessment reports LOW risk.

    The constant-response guard cannot catch this one: a fragment of a real answer still VARIES
    between questions. It has to be fixed where the path is chosen.

    Only an index whose siblings actually carry a string at the same leaf is generalized, so
    ``choices.0.message.content`` — where the siblings are alternative completions rather than
    parts of one message — is left exactly as it is.
    """
    parts = path.split(".")
    for i, part in enumerate(parts):
        if not part.isdigit():
            continue
        parent = _dot(resp_json, ".".join(parts[:i])) if i else resp_json
        if not isinstance(parent, list) or len(parent) < 2:
            continue
        # A ROLE-TAGGED list is a transcript or a set of alternatives, not blocks of one message.
        # Concatenating it glues the probe's own echoed prompt onto the agent's reply, so every
        # probe is scored against its own text plus the answer. Measured against a GraphQL target
        # that returns the whole conversation: the wildcard produced
        # "{'message': 'Say pong.'}Pong! How can I help…". `_prefer_last_turn` has already pointed
        # the index at the last assistant turn; leave that index alone.
        if _is_turn_list(parent):
            continue
        suffix = ".".join(parts[i + 1:])
        vals = [(_dot(item, suffix) if suffix else item) for item in parent]
        texts = [v for v in vals if isinstance(v, str) and v.strip()]
        # Every element must carry text: a list of alternatives has one filled and the rest empty
        # or absent, while the parts of one message are all present.
        if len(texts) == len(parent):
            return ".".join(parts[:i] + ["*"] + parts[i + 1:])
    return path


def _first_id(obj: Any) -> Optional[str]:
    if isinstance(obj, dict):
        for f in _ID_FIELDS:
            v = obj.get(f)
            if isinstance(v, (str, int)) and str(v):
                return str(v)
        for v in obj.values():
            r = _first_id(v)
            if r:
                return r
    elif isinstance(obj, list):
        for v in obj:
            r = _first_id(v)
            if r:
                return r
    return None


_SESSION_ID_NAMES = ("conversationid", "conversation_id", "sessionid", "session_id",
                    "threadid", "thread_id", "session", "conversation")


def _session_first_id(obj: Any) -> Optional[str]:
    """Like `_first_id`, but PREFER a value in a conversation/session-named field over the first
    id-shaped value anywhere. A create response can carry several minted values (Sierra returns a
    static `token` AND a per-turn `conversationID`); the session is the conversation-named one,
    not whichever id happens to appear first. Falls back to `_first_id` when none is named."""
    def named(o: Any) -> Optional[str]:
        if isinstance(o, dict):
            for k, v in o.items():
                if str(k).lower() in _SESSION_ID_NAMES and isinstance(v, (str, int)) and str(v):
                    return str(v)
                r = named(v)
                if r:
                    return r
        elif isinstance(o, list):
            for v in o:
                r = named(v)
                if r:
                    return r
        return None
    return named(obj) or _first_id(obj)


def _id_field_of(obj: Any, target: str) -> Optional[str]:
    """Return the (dot-)field name whose value equals ``target``."""
    def walk(o: Any, prefix: str) -> Optional[str]:
        if isinstance(o, dict):
            for k, v in o.items():
                if isinstance(v, (str, int)) and str(v) == target:
                    return f"{prefix}{k}"
                r = walk(v, f"{prefix}{k}.")
                if r:
                    return r
        elif isinstance(o, list):
            for i, v in enumerate(o):
                r = walk(v, f"{prefix}{i}.")
                if r:
                    return r
        return None
    return walk(obj, "")


def _collect_prior_values(pairs: List[Dict[str, Any]], chat_idx: int) -> List[Tuple[int, str, str, str]]:
    """Collect (index, field, value, url) strings from responses before chat_idx."""
    out: List[Tuple[int, str, str, str]] = []
    for i in range(chat_idx):
        rj = pairs[i]["response"]["json"]
        url = pairs[i]["request"]["url"]
        for field, val in _iter_string_leaves(rj):
            if len(val) >= 8:
                out.append((i, field, val, url))
    return out


def _iter_string_leaves(obj: Any, prefix: str = ""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _iter_string_leaves(v, f"{prefix}{k}.")
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _iter_string_leaves(v, f"{prefix}{i}.")
    elif isinstance(obj, str):
        yield (prefix.rstrip("."), obj)


# Where a CSRF token actually hides in a rendered page. A meta tag is the most common by a
# wide margin; a hidden form input is the classic server-rendered form; the inline-JS
# assignment covers SPA bootstraps that print the token into a script block.
_HTML_TOKEN_PATTERNS = (
    ("meta tag",
     r"""<meta[^>]+?name=["']([\w:.-]*(?:csrf|xsrf)[\w:.-]*)["'][^>]+?content=["']([^"']+)["']"""),
    ("meta tag",   # attribute order is not guaranteed
     r"""<meta[^>]+?content=["']([^"']+)["'][^>]+?name=["']([\w:.-]*(?:csrf|xsrf)[\w:.-]*)["']"""),
    ("hidden input",
     r"""<input[^>]+?name=["']([\w:._-]*(?:csrf|xsrf|authenticity)[\w:._-]*)["'][^>]+?value=["']([^"']+)["']"""),
    ("hidden input",   # attribute order is not guaranteed here either
     r"""<input[^>]+?value=["']([^"']+)["'][^>]+?name=["']([\w:._-]*(?:csrf|xsrf|authenticity)[\w:._-]*)["']"""),
    ("inline script",
     r"""["']([\w.]*(?:csrf|xsrf)[\w.]*[Tt]oken)["']\s*[:=]\s*["']([^"']+)["']"""),
)


def _html_token_origin(pairs: List[Dict[str, Any]], chat_idx: int,
                       needle: str) -> Optional[Tuple[str, str, str]]:
    """Find `needle` in a prior page body and return (url, re-extraction regex, where).

    The regex is keyed on the ATTRIBUTE NAME observed, never on the token value -- the value
    rotates every session, so anchoring on it would produce a config that worked exactly once
    and then failed as a mysterious auth error.

    It is also built with a lookahead rather than a fixed attribute order. HTML attribute order
    is not guaranteed, and the first cut emitted `name=... content=...` after matching a tag
    written `content=... name=...`, so the generated regex could not re-extract the very token
    it had just found. A lookahead matches either order and still exposes exactly one capture
    group, which is what the auth layer's `m.group(1)` expects.
    """
    if not needle or len(needle) < 8:
        return None
    for i in range(chat_idx):
        body = pairs[i]["response"].get("raw_body") or ""
        if not body or len(body) > 4_000_000:
            continue
        for where, pat in _HTML_TOKEN_PATTERNS:
            for m in re.finditer(pat, body, re.I):
                a, b = m.group(1), m.group(2)
                # whichever group IS the token is the value; the other names it
                if a == needle:
                    name = b
                elif b == needle:
                    name = a
                else:
                    continue
                esc = re.escape(name)
                if where == "meta tag":
                    rx = (r'<meta(?=[^>]*name=["\']' + esc
                          + r'["\'])[^>]*content=["\']([^"\']+)["\']')
                elif where == "hidden input":
                    rx = (r'<input(?=[^>]*name=["\']' + esc
                          + r'["\'])[^>]*value=["\']([^"\']+)["\']')
                else:
                    rx = r'["\']' + esc + r'["\']\s*[:=]\s*["\']([^"\']+)["\']'
                return pairs[i]["request"]["url"], rx, where
    return None


def _reuse_origin(needle: str, prior: List[Tuple[int, str, str, str]],
                  substring: bool = False, own_host: str = "") -> Optional[Tuple[int, Optional[str], str]]:
    """Find the earliest prior response value that equals/appears-in ``needle``.

    Only the widget's OWN API can be the origin of a credential the adapter re-acquires. A value
    handed out by a third-party host — a bot challenge's token endpoint, a CAPTCHA, an identity
    provider — is a challenge answer or a login the adapter cannot replay from a script: MEASURED,
    the WAF's token endpoint was chained as "derived_multihop step 0" and failed every probe.
    With ``own_host`` (the chat request's registrable domain) such origins are ignored, which leaves
    the credential static; the browser fallback handles its expiry.
    """
    for idx, field, val, url in prior:
        if own_host and _registrable_host(url) != own_host:
            continue
        if (val in needle) if substring else (val == needle or val in needle):
            return (idx, field, url)
    return None


def _looks_token_endpoint(url: str) -> bool:
    low = (url or "").lower()
    return any(s in low for s in ("/oauth", "/token", "/auth/token", "/connect/token", "/authorize"))


def _has_access_token(resp_json: Any) -> bool:
    return isinstance(resp_json, dict) and ("access_token" in resp_json or "token" in resp_json)


def _same_endpoint(a: Dict[str, Any], b: Dict[str, Any]) -> bool:
    return a.get("method") == b.get("method") and _strip_query(a.get("url", "")) == _strip_query(b.get("url", ""))


def _cookie_name(cookie_header: str) -> str:
    first = cookie_header.split(";", 1)[0]
    return first.split("=", 1)[0].strip() if "=" in first else "session"


def _split_base_path(endpoint: str) -> Tuple[str, str]:
    from urllib.parse import urlparse
    u = urlparse(endpoint)
    base = f"{u.scheme}://{u.netloc}" if u.scheme else ""
    path = u.path or "/"
    return base, path


def _jwt_claims(token: str) -> Optional[Dict[str, Any]]:
    import base64
    if not token or token.count(".") != 2:
        return None
    seg = token.split(".")[1]
    seg += "=" * (-len(seg) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(seg))
    except Exception:  # noqa: BLE001 - malformed token payload
        return None


def _dot(data: Any, path: str) -> Any:
    cur = data
    for part in path.split("."):
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
