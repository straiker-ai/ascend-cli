"""
discovery.importers — the two ZERO-GUESSING inputs: a real ``curl`` command and
a published API spec.

WHY THIS EXISTS
---------------
``discover --url`` (browser capture) and ``discover --har`` both infer the
contract from traffic we observed. That works, but it needs a browser or a HAR.
The common enterprise case is simpler and higher signal: the customer hands us
an HTTP endpoint — usually as a ``curl`` line they already use, sometimes as an
OpenAPI/Swagger document — and nothing else.

Those two inputs are *ground truth*, not inference:

* a **curl command** is a request that the customer has already run successfully,
  so every header, id and flag in it is required-and-correct by construction. The
  only unknown is *which* field carried the human prompt — and even that is known
  when the caller can tell us what they typed (``prompt_hint``).
* an **API spec** is the vendor's own description of the contract; the request
  body shape and the answer field are declared rather than guessed.

So this module's job is *translation*, not detection: turn either artifact into a
runnable adapter config with everything else preserved byte-for-byte.

WHAT THIS MODULE DELIBERATELY DOES NOT DO
-----------------------------------------
It never decides that a config is correct. A config produced here is a
*candidate*; certainty comes only from :func:`discovery.validate.validate_config`
actually calling the live target and getting a real answer back. Confidence
scores in this file (``score`` on a spec endpoint) exist only to decide **what
order to try candidates in** — never to skip trying one.

SAFETY POSTURE
--------------
* curl parsing is 100% offline — no network at all, ever.
* spec discovery is the only network path: a handful of sequential, polite GETs
  for well-known spec locations, with an optional caller-supplied rate limit. It
  stops after repeated auth failures rather than hammering a host that clearly
  does not want anonymous reads, and it never guesses credentials.
* Nothing is imported at module load that touches the network (``requests`` and
  ``yaml`` are both lazy).

PUBLIC API
----------
    from_curl(curl_text, *, prompt_hint=None, secrets_to_env=False) -> config
    explain_curl(curl_text, *, prompt_hint=None)                    -> parsed pieces
    discover_spec(base_url, *, headers=None, timeout_s=10, ...)     -> fetch result
    endpoints_from_spec(spec)                                       -> [candidate, ...]
    config_from_spec_endpoint(base_url, endpoint)                   -> config
    configs_from_spec(base_url, spec, *, limit=5)                   -> [config, ...]
"""
from __future__ import annotations

import base64
import copy
import json
import re
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

# Field names shared with the HAR/browser classifier so both discovery paths
# agree on what a "prompt field" looks like.
from .classify import _PROMPT_FIELDS as _CLASSIFY_PROMPT_FIELDS

__all__ = [
    "PROMPT_PLACEHOLDER",
    "BENIGN_PROMPT",
    "SPEC_PATHS",
    "CurlParseError",
    "from_curl",
    "explain_curl",
    "discover_spec",
    "endpoints_from_spec",
    "config_from_spec_endpoint",
    "configs_from_spec",
]

#: The token every adapter substitutes the real prompt for.
PROMPT_PLACEHOLDER = "{{PROMPT}}"

#: The single innocuous prompt used for probing. Benign by policy: discovery must
#: never send adversarial content — that is the assessment's job, not discovery's.
BENIGN_PROMPT = "Hello, what can you help me with?"

#: Well-known spec locations, in the order they are tried. Ordered by how likely
#: the hit is to be the *canonical* machine-readable spec (not a UI bundle).
SPEC_PATHS: Tuple[str, ...] = (
    "/openapi.json",
    "/openapi.yaml",
    "/swagger.json",
    "/v1/openapi.json",
    "/api/openapi.json",
    "/.well-known/ai-plugin.json",
    "/.well-known/openapi.json",
    "/docs/openapi.json",
    "/api-docs",
    "/swagger/v1/swagger.json",
)

_USER_AGENT = "ascend-bridge-discovery/2 (benign spec fetch; 1 request per path)"

# Stop probing a host once it has refused us this many times — repeated 401/403
# is a "you are not welcome anonymously" signal, not something to brute past.
_MAX_AUTH_FAILURES = 2
_MAX_CONNECT_FAILURES = 3


class CurlParseError(ValueError):
    """Raised when a curl command cannot be turned into a usable config.

    The message always states what went wrong AND the next action to take —
    these errors are read by operators mid-engagement, not by a test harness.
    """


# =========================================================================== #
# Shared: what does a "prompt-carrying" field look like?                      #
# =========================================================================== #
# Keys that strongly suggest "this is where the human's words go".
_PROMPT_KEYS = tuple(dict.fromkeys(
    tuple(_CLASSIFY_PROMPT_FIELDS) + (
        "utterance", "user_input", "userinput", "user_message", "usermessage",
        "q", "ask", "instruction", "inputtext", "input_text", "messagetext",
        "message_text", "chat", "chatinput", "chat_input", "search",
    )
))
# Keys that are structurally never the prompt, even when their value is wordy.
_NEVER_PROMPT_KEYS = frozenset({
    "model", "role", "type", "id", "name", "version", "stream", "format",
    "locale", "language", "lang", "timezone", "tz", "apiversion", "api_version",
    "user", "userid", "user_id", "username", "sessionid", "session_id",
    "conversationid", "conversation_id", "threadid", "thread_id", "chatid",
    "chat_id", "channel", "source", "client", "platform", "token", "key",
    "apikey", "api_key", "secret", "signature", "timestamp", "tenant",
    "tenantid", "org", "orgid", "bot", "botid", "agentid", "agent_id",
    "deployment", "engine", "temperature", "max_tokens", "top_p", "n",
    "mimetype", "mime_type", "contenttype", "content_type", "url", "uri",
    "href", "callback", "redirect", "state", "nonce",
})
# Keys whose STRING values are the model's answer (used for response_path).
_ANSWER_KEYS = (
    "response", "answer", "reply", "output", "completion", "message", "text",
    "content", "result", "generated_text", "outputtext", "output_text",
    "answertext", "answer_text", "bot_response", "botresponse", "assistant",
)

_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_HEXISH_RE = re.compile(r"^[0-9a-f]{16,}$", re.I)
_JWT_RE = re.compile(r"^[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+$")
_ISO_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}")
_NUMERIC_RE = re.compile(r"^[-+]?\d+(\.\d+)?$")
_URLISH_RE = re.compile(r"^[a-z][a-z0-9+.-]*://", re.I)
_B64ISH_RE = re.compile(r"^[A-Za-z0-9+/=_-]{40,}$")


def _looks_opaque(value: str) -> bool:
    """True when a string is machine material (id/token/url), not human words.

    Used to keep the "longest natural-language string" fallback from latching
    onto a JWT or a session id, which are usually the longest strings in a body.
    """
    v = value.strip()
    if not v:
        return True
    if _UUID_RE.match(v) or _HEXISH_RE.match(v) or _JWT_RE.match(v):
        return True
    if _ISO_TS_RE.match(v) or _NUMERIC_RE.match(v) or _URLISH_RE.match(v):
        return True
    if " " not in v and _B64ISH_RE.match(v):
        return True
    if " " not in v and len(v) > 60:
        return True
    return False


def _key_score(key: str) -> float:
    """How prompt-like is a field *name* (independent of its value)."""
    k = (key or "").strip().lower().replace("-", "_")
    if not k:
        return 0.0
    if k in _NEVER_PROMPT_KEYS:
        return -8.0
    if k in _PROMPT_KEYS:
        return 6.0
    for p in _PROMPT_KEYS:
        if len(p) >= 4 and (k.endswith("_" + p) or k.endswith(p) or k.startswith(p + "_")):
            return 3.5
    return 0.0


def _nl_score(key: str, value: str) -> float:
    """Score a (field name, string value) pair as "this carried the human prompt".

    Deliberately additive and boring: name evidence dominates, then wordiness.
    A negative score means "definitely not the prompt".
    """
    if not isinstance(value, str):
        return -99.0
    v = value.strip()
    ks = _key_score(key)
    if not v:
        return -99.0
    if v.lower() in ("user", "assistant", "system", "true", "false", "null"):
        return -20.0
    score = ks
    if _looks_opaque(v):
        score -= 7.0
    words = len(v.split())
    score += min(words, 40) * 0.4
    if " " in v:
        score += 2.0
    if re.search(r"[.?!]", v):
        score += 1.0
    if len(v) >= 8:
        score += 0.5
    if len(v) <= 2:
        score -= 2.0
    return score


def _answer_key_score(key: str) -> float:
    """How answer-like is a field name (for guessing ``response_path``)."""
    k = (key or "").strip().lower().replace("-", "_")
    if not k:
        return 0.0
    if k in ("error", "code", "status", "id", "type", "role", "model", "usage",
             "finish_reason", "created", "object"):
        return -5.0
    for i, cand in enumerate(_ANSWER_KEYS):
        if k == cand:
            return 6.0 - i * 0.1
    for cand in _ANSWER_KEYS:
        if len(cand) >= 4 and (k.endswith("_" + cand) or k.endswith(cand)):
            return 3.0
    return 0.0


# =========================================================================== #
# JSON path helpers (dot paths, list indices as numeric segments)             #
# =========================================================================== #
def _string_leaves(obj: Any, prefix: str = "", key: str = "") -> List[Tuple[str, str, str]]:
    """Every ``(dot_path, last_key, string_value)`` in a nested JSON structure.

    ``last_key`` is what the scorers need: for ``messages.0.content`` it is
    ``content``, i.e. the name that actually describes the value.
    """
    out: List[Tuple[str, str, str]] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.extend(_string_leaves(v, f"{prefix}.{k}" if prefix else str(k), str(k)))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            out.extend(_string_leaves(v, f"{prefix}.{i}" if prefix else str(i), key))
    elif isinstance(obj, str):
        out.append((prefix, key, obj))
    return out


def _get_at_path(obj: Any, path: str) -> Any:
    """Read a dot path (``a.0.b``) out of nested dicts/lists; None if absent."""
    cur = obj
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


def _set_at_path(obj: Any, path: str, value: Any) -> None:
    """Write ``value`` at a dot path, in place. Silently no-ops on a bad path."""
    parts = path.split(".")
    cur = obj
    for part in parts[:-1]:
        if isinstance(cur, dict):
            cur = cur.get(part)
        elif isinstance(cur, list):
            try:
                cur = cur[int(part)]
            except (ValueError, IndexError):
                return
        else:
            return
    last = parts[-1]
    if isinstance(cur, dict):
        cur[last] = value
    elif isinstance(cur, list):
        try:
            cur[int(last)] = value
        except (ValueError, IndexError):
            return


# =========================================================================== #
# 1) curl import                                                              #
# =========================================================================== #
# Short options that consume the NEXT token as their value.
_SHORT_VALUE_OPTS = set("XHdubAeoTwCEKmFY")
# Long options that consume a value.
_LONG_VALUE_OPTS = {
    "request", "header", "data", "data-raw", "data-binary", "data-ascii",
    "data-urlencode", "json", "url", "user", "cookie", "cookie-jar", "form",
    "form-string", "user-agent", "referer", "output", "write-out", "max-time",
    "connect-timeout", "proxy", "proxy-user", "cert", "key", "cacert",
    "capath", "resolve", "interface", "retry", "retry-delay", "limit-rate",
    "range", "upload-file", "oauth2-bearer", "aws-sigv4", "unix-socket",
    "http-version", "trace", "trace-ascii", "config", "dump-header",
    "expect100-timeout", "happy-eyeballs-timeout-ms", "keepalive-time",
    "local-port", "max-filesize", "max-redirs", "next-key",
}
# Long options that are switches (no value) and are safe to accept-and-ignore.
_LONG_BOOL_OPTS = {
    "compressed", "insecure", "location", "location-trusted", "silent",
    "show-error", "verbose", "include", "fail", "fail-with-body", "get",
    "head", "no-buffer", "globoff", "http1.0", "http1.1", "http2",
    "http2-prior-knowledge", "http3", "tlsv1.2", "tlsv1.3", "ipv4", "ipv6",
    "raw", "no-keepalive", "path-as-is", "progress-bar", "remote-name",
    "tcp-nodelay", "disable", "no-progress-meter", "anyauth", "basic",
    "digest", "ntlm", "negotiate", "sslv3", "ssl-no-revoke", "trace-time",
}


def _read_double_quoted(text: str, i: int) -> Tuple[str, int]:
    """Read a ``"..."`` run starting at ``i`` (just past the quote).

    Shell semantics: only ``\\"``, ``\\\\``, ``\\$`` and ``\\```  are escapes; a
    backslash before anything else (notably ``\\n`` inside an embedded JSON
    string) stays literal — which is exactly what keeps JSON bodies intact.
    """
    out: List[str] = []
    n = len(text)
    while i < n:
        c = text[i]
        if c == '"':
            return "".join(out), i + 1
        if c == "\\":
            nxt = text[i + 1: i + 2]
            if nxt == "\n":
                i += 2
                continue
            if nxt in ('"', "\\", "$", "`"):
                out.append(nxt)
                i += 2
                continue
            out.append(c)
            i += 1
            continue
        out.append(c)
        i += 1
    raise CurlParseError(
        "unterminated double quote in the curl command; "
        "re-copy it (Chrome DevTools > Network > right-click > Copy as cURL) and retry"
    )


_ANSI_C_SIMPLE = {
    "n": "\n", "t": "\t", "r": "\r", "a": "\a", "b": "\b", "f": "\f",
    "v": "\v", "e": "\x1b", "E": "\x1b", "\\": "\\", "'": "'", '"': '"', "?": "?",
}


def _read_ansi_c_quoted(text: str, i: int) -> Tuple[str, int]:
    """Read a bash ``$'...'`` (ANSI-C) run starting just past the quote.

    Chrome's "Copy as cURL (bash)" emits ``$'...'`` whenever a header or body
    contains a newline or a non-ASCII character, so this is not exotic.
    """
    out: List[str] = []
    n = len(text)
    while i < n:
        c = text[i]
        if c == "'":
            return "".join(out), i + 1
        if c == "\\" and i + 1 < n:
            nxt = text[i + 1]
            if nxt in _ANSI_C_SIMPLE:
                out.append(_ANSI_C_SIMPLE[nxt])
                i += 2
                continue
            if nxt == "x":
                m = re.match(r"[0-9a-fA-F]{1,2}", text[i + 2:])
                if m:
                    out.append(chr(int(m.group(0), 16)))
                    i += 2 + len(m.group(0))
                    continue
            if nxt in ("u", "U"):
                width = 4 if nxt == "u" else 8
                m = re.match(r"[0-9a-fA-F]{1,%d}" % width, text[i + 2:])
                if m:
                    out.append(chr(int(m.group(0), 16)))
                    i += 2 + len(m.group(0))
                    continue
            m = re.match(r"[0-7]{1,3}", text[i + 1:])
            if m:
                out.append(chr(int(m.group(0), 8)))
                i += 1 + len(m.group(0))
                continue
            out.append(nxt)
            i += 2
            continue
        out.append(c)
        i += 1
    raise CurlParseError(
        "unterminated $'...' quote in the curl command; re-copy the command and retry"
    )


_CURL_COMMAND_START = re.compile(
    r"[ \t]*(?:\$[ \t]+)?(?:sudo[ \t]+)?(?:[^;&|\s'\"]*[/\\])?curl(?:\.exe)?(?=\s|$)", re.I
)
_MULTI_REQUEST = "This cURL input contains multiple requests. Import one request at a time."


def _tokenize(text: str) -> List[str]:
    """Split a shell command line into argv, the way bash would.

    Handles: ``\\``+newline and ``^``+newline continuations (bash and Windows
    cmd), single quotes (verbatim), double quotes (limited escapes),
    ``$'...'`` ANSI-C quoting, and quote runs glued to a token (``-H'x: y'``).
    """
    tokens: List[str] = []
    buf: List[str] = []
    started = False
    seen_command = _CURL_COMMAND_START.match(text) is not None
    comment_end = 0
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        # The quoted and escaped branches below consume complete operands. Only
        # an unquoted shell boundary can introduce another command.
        if c == "#" and not started and i >= comment_end:
            newline = text.find("\n", i)
            comment_end = n if newline < 0 else newline
        if c in "\n\r;&|" and i >= comment_end and _CURL_COMMAND_START.match(text, i + 1):
            if seen_command:
                raise CurlParseError(_MULTI_REQUEST)
            seen_command = True
        if c in " \t\r\n":
            if started:
                tokens.append("".join(buf))
                buf, started = [], False
            i += 1
            continue
        if c == "\\":
            nxt = text[i + 1: i + 2]
            if nxt == "\n":
                i += 2
                continue
            if nxt == "\r" and text[i + 2: i + 3] == "\n":
                i += 3
                continue
            if nxt:
                buf.append(nxt)
                started = True
                i += 2
                continue
            i += 1
            continue
        if c == "^" and text[i + 1: i + 2] in ("\n", "\r"):
            # Windows `cmd` line continuation (curl copied from PowerShell/cmd).
            i += 2
            if text[i - 1: i] == "\r" and text[i: i + 1] == "\n":
                i += 1
            continue
        if c == "'":
            j = text.find("'", i + 1)
            if j < 0:
                raise CurlParseError(
                    "unterminated single quote in the curl command; "
                    "re-copy the whole command (it was probably truncated) and retry"
                )
            buf.append(text[i + 1:j])
            started = True
            i = j + 1
            continue
        if c == '"':
            s, i = _read_double_quoted(text, i + 1)
            buf.append(s)
            started = True
            continue
        if c == "$" and text[i + 1: i + 2] == "'":
            s, i = _read_ansi_c_quoted(text, i + 2)
            buf.append(s)
            started = True
            continue
        if c == "$" and text[i + 1: i + 2] == '"':
            s, i = _read_double_quoted(text, i + 2)
            buf.append(s)
            started = True
            continue
        buf.append(c)
        started = True
        i += 1
    if started:
        tokens.append("".join(buf))
    return tokens


def _looks_like_url(tok: str) -> bool:
    """True for a bare argument that is plausibly the request URL."""
    if not tok or tok.startswith("-"):
        return False
    if _URLISH_RE.match(tok):
        return True
    # host-ish: has a dot or a :port before the first slash, no spaces
    head = tok.split("/", 1)[0]
    return bool(re.match(r"^[A-Za-z0-9._-]+(:\d+)?$", head) and ("." in head or ":" in head))


def _urlencode_pair(spec: str) -> str:
    """Apply ``--data-urlencode`` semantics to one argument.

    Forms: ``name=value`` (encode value), ``=value`` (encode value, no name),
    ``content`` (encode whole thing). ``name@file`` / ``@file`` need a file we do
    not have, so they are passed through and flagged by the caller.
    """
    if spec.startswith("="):
        return quote(spec[1:], safe="")
    if "=" in spec:
        name, _, value = spec.partition("=")
        return f"{name}={quote(value, safe='')}"
    return quote(spec, safe="")


def _parse_curl(curl_text: str) -> Dict[str, Any]:
    """Parse a curl command into its raw pieces (no prompt detection yet).

    Returns a dict with url/method/header_list/data parts/flags/warnings. Kept
    separate from :func:`explain_curl` so both the explainer and the config
    builder work off exactly the same parse.
    """
    if not isinstance(curl_text, str) or not curl_text.strip():
        raise CurlParseError(
            "empty curl input; paste the full command, e.g. "
            "curl -X POST https://host/chat -H 'Content-Type: application/json' -d '{\"message\":\"hi\"}'"
        )

    tokens = _tokenize(curl_text)
    if not tokens:
        raise CurlParseError("no tokens found in the curl input; paste the full command and retry")

    # Drop everything up to and including the `curl` word (handles leading `$ `,
    # `sudo`, an absolute path, or a `\n`-wrapped snippet).
    start = 0
    for idx, tok in enumerate(tokens):
        base = tok.rsplit("/", 1)[-1].lower()
        if base in ("curl", "curl.exe"):
            start = idx + 1
            break
    else:
        if not any(_looks_like_url(t) for t in tokens):
            raise CurlParseError(
                "input does not look like a curl command (no `curl` word and no URL found); "
                "paste the command exactly as you run it"
            )

    args = tokens[start:]
    url: Optional[str] = None
    method: Optional[str] = None
    header_list: List[Tuple[str, str]] = []
    data_parts: List[Tuple[str, str]] = []   # (kind, value)
    json_parts: List[str] = []
    basic_user: Optional[str] = None
    basic_pass: Optional[str] = None
    cookie_parts: List[str] = []
    bearer: Optional[str] = None
    insecure = False
    follow = False
    get_flag = False
    max_time: Optional[float] = None
    form_parts: List[str] = []
    ignored: List[str] = []
    unknown: List[str] = []
    warnings: List[str] = []
    extra_urls: List[str] = []
    next_transfer = False

    def _need_value(flag: str, it: List[str], i: int) -> Tuple[str, int]:
        if i + 1 >= len(it):
            raise CurlParseError(
                f"{flag} was given with no value; the curl command looks truncated — "
                "re-copy the whole line and retry"
            )
        return it[i + 1], i + 1

    i = 0
    while i < len(args):
        tok = args[i]
        if tok in ("--next", "-:"):
            next_transfer = True
        if tok == "--":
            i += 1
            continue
        if tok.startswith("--"):
            name, eq, inline = tok[2:].partition("=")
            lname = name.lower()
            if lname in _LONG_VALUE_OPTS:
                if eq:
                    value = inline
                else:
                    value, i = _need_value("--" + name, args, i)
            elif lname in _LONG_BOOL_OPTS:
                value = ""
            else:
                # Unknown long flag: assume it is a switch. If it carried an
                # inline value we still record it so nothing vanishes silently.
                unknown.append(tok)
                i += 1
                continue

            if lname == "request":
                method = value.upper()
            elif lname == "header":
                if ":" in value:
                    hname, _, hval = value.partition(":")
                    header_list.append((hname.strip(), hval.strip()))
                elif value.endswith(";"):
                    header_list.append((value[:-1].strip(), ""))
                else:
                    warnings.append(f"ignored malformed header {value!r} (expected 'Name: value')")
            elif lname == "url":
                if url is None:
                    url = value
                else:
                    extra_urls.append(value)
            elif lname == "data-raw":
                # curl: --data-raw never treats a leading '@' as a filename.
                data_parts.append(("literal", value))
            elif lname in ("data", "data-ascii"):
                data_parts.append(("raw", value))
            elif lname == "data-binary":
                data_parts.append(("binary", value))
            elif lname == "data-urlencode":
                data_parts.append(("urlencode", value))
            elif lname == "json":
                json_parts.append(value)
            elif lname == "user":
                basic_user, _, basic_pass = value.partition(":")
            elif lname == "oauth2-bearer":
                bearer = value
            elif lname == "cookie":
                cookie_parts.append(value)
            elif lname in ("form", "form-string"):
                form_parts.append(value)
            elif lname == "user-agent":
                header_list.append(("User-Agent", value))
            elif lname == "referer":
                header_list.append(("Referer", value))
            elif lname == "insecure":
                insecure = True
            elif lname in ("location", "location-trusted"):
                follow = True
            elif lname == "get":
                get_flag = True
            elif lname in ("max-time", "connect-timeout"):
                try:
                    max_time = max(max_time or 0.0, float(value))
                except ValueError:
                    warnings.append(f"ignored non-numeric {tok} value {value!r}")
            else:
                ignored.append("--" + name)
            i += 1
            continue

        if tok.startswith("-") and len(tok) > 1:
            # Short option, possibly clustered (-sS) or glued to its value (-XPOST).
            j = 1
            while j < len(tok):
                opt = tok[j]
                if opt in _SHORT_VALUE_OPTS:
                    glued = tok[j + 1:]
                    if glued:
                        value = glued
                    else:
                        value, i = _need_value("-" + opt, args, i)
                    if opt == "X":
                        method = value.upper()
                    elif opt == "H":
                        if ":" in value:
                            hname, _, hval = value.partition(":")
                            header_list.append((hname.strip(), hval.strip()))
                        elif value.endswith(";"):
                            header_list.append((value[:-1].strip(), ""))
                        else:
                            warnings.append(
                                f"ignored malformed header {value!r} (expected 'Name: value')")
                    elif opt == "d":
                        data_parts.append(("raw", value))
                    elif opt == "u":
                        basic_user, _, basic_pass = value.partition(":")
                    elif opt == "b":
                        cookie_parts.append(value)
                    elif opt == "A":
                        header_list.append(("User-Agent", value))
                    elif opt == "e":
                        header_list.append(("Referer", value))
                    elif opt == "F":
                        form_parts.append(value)
                    elif opt == "m":
                        try:
                            max_time = max(max_time or 0.0, float(value))
                        except ValueError:
                            warnings.append(f"ignored non-numeric -m value {value!r}")
                    else:
                        ignored.append("-" + opt)
                    break  # value consumed the rest of this token
                if opt == "k":
                    insecure = True
                elif opt == "L":
                    follow = True
                elif opt == "G":
                    get_flag = True
                elif opt in "sSvif#N4610":
                    ignored.append("-" + opt)
                else:
                    unknown.append("-" + opt)
                j += 1
            i += 1
            continue

        # Bare token: the URL (curl accepts it in any position).
        if url is None:
            url = tok
        else:
            extra_urls.append(tok)
        i += 1

    if url is None:
        raise CurlParseError(
            "no URL found in the curl command; add the target URL "
            "(e.g. https://host/api/chat) and retry"
        )
    if extra_urls and next_transfer:
        raise CurlParseError(_MULTI_REQUEST)
    if extra_urls:
        warnings.append(
            f"multiple URLs given ({[url] + extra_urls}); using the first — "
            "split multi-URL curl commands into one command per target"
        )
    if not _URLISH_RE.match(url):
        url = "https://" + url.lstrip("/")
        warnings.append(f"no scheme on the URL; assuming https -> {url}")
    if form_parts:
        warnings.append(
            "multipart form fields (-F/--form) are present; the direct_api adapter sends "
            "JSON or urlencoded bodies only. Convert the call to JSON, or write a small "
            "custom adapter, if the target truly requires multipart"
        )
    if follow:
        ignored.append("--location")
    if bearer:
        header_list.append(("Authorization", f"Bearer {bearer}"))

    # Body assembly, exactly as curl would do it.
    raw_body: Optional[str] = None
    body_flavor: Optional[str] = None
    if json_parts:
        raw_body = "".join(json_parts)          # curl concatenates repeated --json
        body_flavor = "json"
    elif data_parts:
        chunks: List[str] = []
        for kind, value in data_parts:
            if value.startswith("@") and kind != "literal":
                warnings.append(
                    f"body came from a file ({value}) which is not available here; "
                    "inline the file's contents into the curl command (-d '<contents>') and retry"
                )
                continue
            chunks.append(_urlencode_pair(value) if kind == "urlencode" else value)
        raw_body = "&".join(chunks) if len(chunks) > 1 else (chunks[0] if chunks else "")
        body_flavor = "urlencode" if any(k == "urlencode" for k, _ in data_parts) else None

    if basic_user is not None:
        blob = base64.b64encode(f"{basic_user}:{basic_pass or ''}".encode()).decode()
        header_list.append(("Authorization", f"Basic {blob}"))
    if cookie_parts:
        joined = "; ".join(c.strip().strip(";") for c in cookie_parts if c.strip())
        if "=" in joined:
            header_list.append(("Cookie", joined))
        else:
            warnings.append(
                f"-b/--cookie value {joined!r} looks like a cookie FILE, not a cookie string; "
                "pass the cookies inline (-b 'k=v; k2=v2') if the target needs them"
            )

    if method is None:
        method = "GET" if (raw_body is None or get_flag) else "POST"
    if get_flag and raw_body:
        # -G moves the data into the query string.
        url = _append_query(url, raw_body)
        raw_body, body_flavor = None, None

    return {
        "url": url,
        "method": method,
        "header_list": header_list,
        "raw_body": raw_body,
        "body_flavor": body_flavor,
        "insecure": insecure,
        "basic_user": basic_user,
        "max_time_s": max_time,
        "ignored_flags": sorted(set(ignored)),
        "unknown_flags": sorted(set(unknown)),
        "warnings": warnings,
    }


def _append_query(url: str, encoded: str) -> str:
    """Append an already-encoded query fragment to a URL."""
    if not encoded:
        return url
    parts = urlsplit(url)
    query = f"{parts.query}&{encoded}" if parts.query else encoded
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, parts.fragment))


def _headers_dict(header_list: Sequence[Tuple[str, str]]) -> Dict[str, str]:
    """Collapse the ordered header list to a dict, last value winning."""
    out: Dict[str, str] = {}
    for name, value in header_list:
        out[name] = value
    return out


def _content_type(headers: Dict[str, str]) -> str:
    for k, v in headers.items():
        if k.lower() == "content-type":
            return v
    return ""


def _classify_body(raw: Optional[str], content_type: str,
                   flavor: Optional[str]) -> Tuple[str, Any]:
    """Decide how a raw body should be represented: json / form / text / none.

    Content-Type is trusted first (the customer's own call declared it); the body
    text itself is the tiebreaker when no Content-Type was sent.
    """
    if raw is None or raw == "":
        return "none", None
    ct = (content_type or "").lower()
    if "json" in ct:
        try:
            return "json", json.loads(raw)
        except ValueError:
            return "text", raw
    if "x-www-form-urlencoded" in ct or flavor == "urlencode":
        return "form", dict(parse_qsl(raw, keep_blank_values=True))
    stripped = raw.lstrip()
    if stripped[:1] in ("{", "["):
        try:
            return "json", json.loads(raw)
        except ValueError:
            pass
    if re.match(r"^[^=&\s]+=[^&]*(&[^=&\s]+=[^&]*)*$", raw.strip()):
        return "form", dict(parse_qsl(raw, keep_blank_values=True))
    return "text", raw


# Sibling keys that say WHO wrote a message — the difference between the system
# prompt and the user's turn in an OpenAI-style `messages` array.
_ROLE_KEYS = ("role", "author", "sender", "from", "speaker", "participant")
_HUMAN_ROLES = frozenset({"user", "human", "customer", "end_user", "enduser", "member", "me"})
_MACHINE_ROLES = frozenset({"system", "assistant", "bot", "ai", "agent", "tool",
                            "function", "developer"})


def _role_bonus(body: Any, path: str) -> float:
    """Boost/penalize a candidate by its sibling ``role`` field.

    In a chat-history body every turn has the same field name (``content``), so
    the name alone cannot separate the system prompt from the user's words —
    but the sibling role can, and it is declared, not guessed.
    """
    if "." not in path:
        return 0.0
    parent = _get_at_path(body, path.rsplit(".", 1)[0])
    if not isinstance(parent, dict):
        return 0.0
    for rk in _ROLE_KEYS:
        rv = parent.get(rk)
        if isinstance(rv, str):
            r = rv.strip().lower()
            if r in _HUMAN_ROLES:
                return 4.0
            if r in _MACHINE_ROLES:
                return -5.0
    return 0.0


def _json_candidates(body: Any) -> List[Dict[str, Any]]:
    """Prompt candidates for a JSON body, in document order, with scores."""
    out: List[Dict[str, Any]] = []
    for path, key, value in _string_leaves(body):
        out.append({"where": "body", "path": path, "key": key, "value": value,
                    "score": _nl_score(key, value) + _role_bonus(body, path)})
    return out


def _locate_prompt(body_kind: str, body: Any, query: Dict[str, str],
                   prompt_hint: Optional[str]) -> Optional[Dict[str, Any]]:
    """Find where the human's words sit: body field, form field, or query param.

    With ``prompt_hint`` this is exact (we look for that literal text and use
    substring replacement so any scaffolding around it survives). Without it we
    fall back to the best-scoring natural-language string — still deterministic,
    but the caller should prefer the hint when they have it.

    Returns ``{"where", "path", "key", "value", "exact"}`` or None.
    """
    candidates: List[Dict[str, Any]] = []
    if body_kind == "json" and isinstance(body, (dict, list)):
        candidates.extend(_json_candidates(body))
    elif body_kind == "form" and isinstance(body, dict):
        for key, value in body.items():
            if isinstance(value, str):
                candidates.append({"where": "form", "path": key, "key": key, "value": value,
                                   "score": _nl_score(key, value)})
    elif body_kind == "text" and isinstance(body, str):
        candidates.append({"where": "text", "path": "", "key": "", "value": body,
                           "score": _nl_score("", body)})
    for key, value in (query or {}).items():
        candidates.append({"where": "query", "path": key, "key": key, "value": value,
                           "score": _nl_score(key, value)})

    if not candidates:
        return None

    if prompt_hint:
        hint = prompt_hint.strip()
        squashed = " ".join(hint.split())
        for cand in candidates:
            if cand["value"].strip() == hint or " ".join(cand["value"].split()) == squashed:
                cand["exact"] = True
                return cand
        for cand in candidates:
            if hint and hint in cand["value"]:
                # The prompt is embedded in a larger string (e.g. a chat
                # transcript prefix) — replace only the prompt part.
                cand["exact"] = False
                return cand
        return None

    scored = [(c["score"], i, c) for i, c in enumerate(candidates) if c["score"] > 0]
    if not scored:
        return None
    # Highest score wins. Ties break toward the LAST candidate in document order
    # (in a chat-history body the live turn is the last one), then toward the
    # longer value (more likely to be prose).
    scored.sort(key=lambda sc: (sc[0], sc[1], len(sc[2]["value"])), reverse=True)
    best = scored[0][2]
    best["exact"] = True
    return best


def explain_curl(curl_text: str, *, prompt_hint: Optional[str] = None) -> Dict[str, Any]:
    """Parse a curl command and return its pieces — for debugging and tests.

    Pure and offline. This is the function to call when :func:`from_curl` picked
    the wrong prompt field and you want to see what it saw.

    Returns:
        ``{"url", "method", "headers", "query", "body", "body_kind", "raw_body",
        "content_type", "prompt_field", "prompt_value", "prompt_exact",
        "basic_auth_user", "insecure", "max_time_s", "ignored_flags",
        "unknown_flags", "warnings", "prompt_candidates"}`` where
        ``prompt_field`` is a location string such as ``body:messages.1.content``,
        ``form:q``, ``query:text`` or ``text:`` (whole body), or None.
    """
    parsed = _parse_curl(curl_text)
    headers = _headers_dict(parsed["header_list"])
    query = dict(parse_qsl(urlsplit(parsed["url"]).query, keep_blank_values=True))
    ctype = _content_type(headers)
    body_kind, body = _classify_body(parsed["raw_body"], ctype, parsed["body_flavor"])

    found = _locate_prompt(body_kind, body, query, prompt_hint)
    prompt_field = None
    if found is not None:
        prompt_field = f"{found['where']}:{found['path']}"

    # Everything we considered, best first — the thing you want when the pick is wrong.
    considered: List[Dict[str, Any]] = []
    if body_kind == "json" and isinstance(body, (dict, list)):
        considered += _json_candidates(body)
    elif body_kind == "form" and isinstance(body, dict):
        considered += [{"where": "form", "path": k, "key": k, "value": v,
                        "score": _nl_score(k, v)} for k, v in body.items()
                       if isinstance(v, str)]
    elif body_kind == "text" and isinstance(body, str):
        considered.append({"where": "text", "path": "", "key": "", "value": body,
                           "score": _nl_score("", body)})
    considered += [{"where": "query", "path": k, "key": k, "value": v,
                    "score": _nl_score(k, v)} for k, v in query.items()]
    considered.sort(key=lambda c: c["score"], reverse=True)
    for c in considered:
        c["score"] = round(c["score"], 2)

    return {
        "url": parsed["url"],
        "method": parsed["method"],
        "headers": headers,
        "header_list": parsed["header_list"],
        "query": query,
        "body": body,
        "body_kind": body_kind,
        "raw_body": parsed["raw_body"],
        "content_type": ctype,
        "prompt_field": prompt_field,
        "prompt_value": found["value"] if found else None,
        "prompt_exact": bool(found and found.get("exact")),
        "prompt_candidates": considered,
        "basic_auth_user": parsed["basic_user"],
        "insecure": parsed["insecure"],
        "max_time_s": parsed["max_time_s"],
        "ignored_flags": parsed["ignored_flags"],
        "unknown_flags": parsed["unknown_flags"],
        "warnings": list(parsed["warnings"]),
    }


def _env_name(header_name: str) -> str:
    """Deterministic env var name for a header's secret (``X-Api-Key`` -> ``ASCEND_X_API_KEY``)."""
    slug = re.sub(r"[^A-Za-z0-9]+", "_", header_name).strip("_").upper()
    return f"ASCEND_{slug}" if slug else "ASCEND_SECRET"


_SECRET_HEADER_NAMES = frozenset({
    "authorization", "x-api-key", "api-key", "apikey", "x-auth-token",
    "x-authentication", "authentication", "x-access-token", "cookie",
    "x-goog-api-key", "openai-api-key", "anthropic-api-key", "x-amz-security-token",
})


def _auth_block_for(header_name: str, value: str) -> Tuple[Dict[str, Any], List[str]]:
    """Build a ``layers.auth`` static block for one secret header.

    Returns ``(auth_block, env_names)``. The block matches what
    ``AuthProvider._materialize_static`` expects, so ``validate_config`` can run
    it straight away once the env vars are exported.
    """
    lname = header_name.lower()
    if lname == "authorization":
        scheme, _, rest = value.partition(" ")
        if scheme.lower() == "bearer" and rest:
            env = "ASCEND_BEARER_TOKEN"
            return ({"type": "static", "mode": "bearer", "name": header_name,
                     "prefix": "Bearer", "value_ref": f"env:{env}"}, [env])
        if scheme.lower() == "basic" and rest:
            user = ""
            try:
                decoded = base64.b64decode(rest + "=" * (-len(rest) % 4)).decode("utf-8", "replace")
                user = decoded.split(":", 1)[0]
            except Exception:  # noqa: BLE001 - a malformed blob just means no username hint
                user = ""
            block: Dict[str, Any] = {
                "type": "static", "mode": "basic",
                "username_ref": f"literal:{user}" if user else "env:ASCEND_BASIC_USER",
                "password_ref": "env:ASCEND_BASIC_PASS",
            }
            envs = ["ASCEND_BASIC_PASS"] + ([] if user else ["ASCEND_BASIC_USER"])
            return block, envs
        env = "ASCEND_AUTHORIZATION"
        return ({"type": "static", "mode": "custom", "name": header_name,
                 "template": (f"{scheme} " if scheme and rest else "") + "{{VALUE}}",
                 "value_ref": f"env:{env}"}, [env])
    if lname == "cookie":
        env = "ASCEND_COOKIE"
        return ({"type": "static", "mode": "custom", "name": "Cookie",
                 "template": "{{VALUE}}", "value_ref": f"env:{env}"}, [env])
    env = _env_name(header_name)
    return ({"type": "static", "mode": "api_key", "in": "header",
             "name": header_name, "value_ref": f"env:{env}"}, [env])


def from_curl(
    curl_text: str,
    *,
    prompt_hint: Optional[str] = None,
    secrets_to_env: bool = False,
    timeout_ms: Optional[int] = None,
    response_path: Optional[str] = None,
    require_prompt: bool = True,
) -> Dict[str, Any]:
    """Turn a real curl command into a ``direct_api`` adapter config.

    This is a translation, not an inference: every header, id and flag from the
    curl survives untouched, because the customer's call already proved they are
    required. The single edit is replacing the human prompt with
    ``{{PROMPT}}`` so the relay can substitute each assessment turn.

    Args:
        curl_text: the command, as copied (line continuations and quoting fine).
        prompt_hint: the literal text the user typed in that curl. When given,
            the prompt field is located EXACTLY — no scoring involved. Strongly
            preferred; without it the longest natural-language-looking string is
            used, which is right most of the time but not by construction.
        secrets_to_env: when True, secret headers are moved out of the config
            into an ``auth`` block with ``env:NAME`` references (nothing secret
            is written to disk, but the config will not run until those env vars
            are exported). Default False so the config works immediately —
            discovery has to be able to prove the target answers before anyone
            invests in secret plumbing.
        timeout_ms: override the request timeout (default: curl's ``--max-time``
            if present, else 30000).
        response_path: pin the dot-path to the answer if you already know it. A
            request cannot reveal where the ANSWER lives, so this is None by
            default and is meant to be resolved from the first live reply.
        require_prompt: raise when no prompt field can be located. Set False to
            get the config anyway (with ``_prompt_field: None``) and patch it by
            hand — but be aware such a config replays a FIXED prompt every turn.

    Returns:
        A ``direct_api`` config: ``endpoint``, ``method``, ``headers``, ``body``,
        ``response_path`` (always None — resolve it from the live reply with
        :func:`discovery.validate.validate_config`), ``timeout_ms``, plus
        ``_source: "curl"`` and ``_notes``/``_prompt_field`` breadcrumbs.

    Raises:
        CurlParseError: unparseable command, missing URL, or (with
            ``require_prompt``) no locatable prompt — always with the next action.
    """
    parsed = _parse_curl(curl_text)
    headers = _headers_dict(parsed["header_list"])
    url = parsed["url"]
    query = dict(parse_qsl(urlsplit(url).query, keep_blank_values=True))
    ctype = _content_type(headers)
    body_kind, body = _classify_body(parsed["raw_body"], ctype, parsed["body_flavor"])
    notes: List[str] = list(parsed["warnings"])

    if parsed["ignored_flags"]:
        notes.append(f"accepted and ignored (no effect on the config): {parsed['ignored_flags']}")
    if parsed["unknown_flags"]:
        notes.append(
            f"unrecognised flags treated as switches: {parsed['unknown_flags']}; "
            "if one of them carried a value, add it to the config by hand"
        )
    unexpanded = sorted({m for m in re.findall(r"\$\{?[A-Za-z_][A-Za-z0-9_]*\}?",
                                              " ".join([str(v) for v in headers.values()]
                                                       + [parsed["raw_body"] or "", url]))})
    if unexpanded:
        notes.append(
            f"unexpanded shell variables in the request: {unexpanded}. Your shell would have "
            "substituted real values — paste the command with the values inlined, or export the "
            "same variables and re-render before validating"
        )
    if parsed["insecure"]:
        notes.append(
            "-k/--insecure was set: the original call skipped TLS verification. "
            "Run validation with verify_tls=False if the target uses a private CA"
        )

    # --- locate and template the prompt ---------------------------------- #
    already_templated = (PROMPT_PLACEHOLDER in (parsed["raw_body"] or "")) or \
                        (PROMPT_PLACEHOLDER in url)
    prompt_field: Optional[str] = None
    prompt_value: Optional[str] = None
    endpoint = url

    if already_templated:
        prompt_field = "preserved"
        notes.append("the command already contained {{PROMPT}}; left exactly as given")
    else:
        found = _locate_prompt(body_kind, body, query, prompt_hint)
        if found is None:
            if require_prompt:
                seen = [f"{c['where']}:{c['path']}={c['value'][:40]!r}"
                        for c in explain_curl(curl_text)["prompt_candidates"][:6]]
                raise CurlParseError(
                    "could not tell which field carried the prompt. "
                    + (f"prompt_hint={prompt_hint!r} was not found in the request. "
                       if prompt_hint else "")
                    + "Next: re-run with prompt_hint='<the exact text you typed in that curl>', "
                      "or edit the command to put {{PROMPT}} where the prompt goes. "
                    + (f"Fields seen: {seen}" if seen else "No string fields were found at all — "
                                                           "is this the right request?")
                )
            notes.append(
                "NO PROMPT FIELD FOUND — this config replays a fixed request. "
                "Put {{PROMPT}} where the prompt belongs before using it for an assessment"
            )
        else:
            prompt_field = f"{found['where']}:{found['path']}"
            prompt_value = found["value"]
            if found["where"] == "body":
                body = copy.deepcopy(body)
                new_value = (PROMPT_PLACEHOLDER if found["exact"]
                             else found["value"].replace(prompt_hint or "", PROMPT_PLACEHOLDER, 1))
                _set_at_path(body, found["path"], new_value)
            elif found["where"] == "form":
                body = dict(body)
                body[found["path"]] = (PROMPT_PLACEHOLDER if found["exact"]
                                       else found["value"].replace(prompt_hint or "",
                                                                   PROMPT_PLACEHOLDER, 1))
            elif found["where"] == "text":
                body = (PROMPT_PLACEHOLDER if found["exact"]
                        else found["value"].replace(prompt_hint or "", PROMPT_PLACEHOLDER, 1))
            elif found["where"] == "query":
                # direct_api URL-encodes the substituted prompt, so the literal
                # placeholder is what belongs in the URL.
                parts = urlsplit(url)
                pairs = parse_qsl(parts.query, keep_blank_values=True)
                rebuilt = [(k, PROMPT_PLACEHOLDER if k == found["path"] else v) for k, v in pairs]
                endpoint = urlunsplit((parts.scheme, parts.netloc, parts.path,
                                       urlencode(rebuilt, safe="{}"), parts.fragment))
            if not found["exact"]:
                notes.append(
                    f"the prompt was embedded inside a larger value at {prompt_field}; "
                    "only the prompt text was replaced, the surrounding text is preserved"
                )

    # --- body / content-type ---------------------------------------------- #
    config_headers = dict(headers)
    if body_kind == "form":
        # Keep form encoding: direct_api switches on this Content-Type.
        existing = next((k for k in config_headers if k.lower() == "content-type"), None)
        if existing:
            config_headers[existing] = "application/x-www-form-urlencoded"
        else:
            config_headers["Content-Type"] = "application/x-www-form-urlencoded"
    elif body_kind == "json":
        if not any(k.lower() == "content-type" for k in config_headers):
            config_headers["Content-Type"] = "application/json"
    elif body_kind == "text":
        notes.append(
            "the body is plain text; direct_api serialises it as a JSON string. "
            "If the target needs raw text on the wire, wrap it in a JSON field or use a "
            "custom adapter"
        )

    # Hop-by-hop / recomputed headers must not be pinned in the config.
    for drop in ("content-length", "host", "connection", "accept-encoding",
                 "transfer-encoding", "expect"):
        for k in [k for k in config_headers if k.lower() == drop]:
            config_headers.pop(k, None)

    config: Dict[str, Any] = {
        "adapter": "direct_api",
        "endpoint": endpoint,
        "method": parsed["method"],
        "headers": config_headers,
        "body": body if body_kind != "none" else {},
        # Deliberately None unless pinned: a request cannot tell us where the
        # ANSWER lives, and that is proven from a LIVE reply, never guessed.
        "response_path": response_path,
        "timeout_ms": int(timeout_ms if timeout_ms is not None
                          else (parsed["max_time_s"] * 1000 if parsed["max_time_s"] else 30000)),
        "_source": "curl",
        "_prompt_field": prompt_field,
        "_prompt_sample": prompt_value,
        "_body_kind": body_kind,
        "_insecure": parsed["insecure"],
    }

    # --- optional secret externalisation ----------------------------------- #
    if secrets_to_env:
        secret_headers = [(k, v) for k, v in config_headers.items()
                          if k.lower() in _SECRET_HEADER_NAMES]
        env_refs: Dict[str, str] = {}
        env_names: List[str] = []
        for idx, (name, value) in enumerate(secret_headers):
            config_headers.pop(name, None)
            if idx == 0:
                block, envs = _auth_block_for(name, value)
                config["auth"] = block
                env_names.extend(envs)
            else:
                env = _env_name(name)
                env_refs[name] = f"env:{env}"
                env_names.append(env)
        if secret_headers:
            config["_secret_env"] = env_names
            if env_refs:
                config["_secrets_to_export"] = env_refs
                notes.append(
                    f"extra secret headers were removed: {list(env_refs)}. Only the `auth` block is "
                    "resolved automatically — re-add these headers (or fold them into auth) before "
                    "validating"
                )
            notes.append(
                "secrets_to_env=True: export " + ", ".join(env_names) +
                " before validating, or re-run with secrets_to_env=False to keep the working values"
            )

    if not response_path:
        notes.append(
            "response_path is not set: direct_api will fall back to the deepest string in the "
            "reply, which is often an id/status rather than the answer. Send one benign prompt, "
            "then pin response_path from the real reply "
            "(discovery.classify._guess_response_path(resp_json, reply_text) does exactly this) "
            "before running an assessment"
        )

    config["_notes"] = notes
    return config


# =========================================================================== #
# 2) API spec import                                                          #
# =========================================================================== #
def _normalize_base(base_url: str) -> str:
    if not isinstance(base_url, str) or not base_url.strip():
        raise ValueError("base_url is required, e.g. 'https://api.example.com'")
    base = base_url.strip()
    if not _URLISH_RE.match(base):
        base = "https://" + base.lstrip("/")
    return base.rstrip("/")


def _origin(url: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, "", "", ""))


def _spec_candidates(base_url: str, paths: Sequence[str]) -> List[str]:
    """Full URLs to try, in order, without duplicates.

    A base URL with a path (``https://host/api/v2``) gets both the path-relative
    and the origin-relative variants — vendors publish specs at either.
    """
    base = _normalize_base(base_url)
    out: List[str] = []
    if re.search(r"\.(json|ya?ml)$", urlsplit(base).path, re.I):
        out.append(base)          # caller pointed straight at the document
    for p in paths:
        out.append(base + p)
    origin = _origin(base)
    if origin != base:
        for p in paths:
            out.append(origin + p)
    seen: set = set()
    ordered: List[str] = []
    for u in out:
        if u not in seen:
            seen.add(u)
            ordered.append(u)
    return ordered


def _looks_yaml(text: str) -> bool:
    head = text.lstrip()[:400]
    return bool(re.match(r"^(openapi|swagger|info|paths)\s*:", head, re.M))


def _parse_spec_body(text: str, content_type: str) -> Tuple[Optional[Any], str, Optional[str]]:
    """Parse a fetched body as JSON, then (lazily) as YAML.

    Returns ``(obj, format, error)``. YAML support is optional by design: adding
    a PyYAML dependency to a stdlib+requests tool is not worth it, so a YAML-only
    target reports what to install rather than failing opaquely.
    """
    stripped = (text or "").strip()
    if not stripped:
        return None, "", "empty body"
    try:
        return json.loads(stripped), "json", None
    except ValueError:
        pass
    if _looks_yaml(stripped) or "yaml" in (content_type or "").lower():
        try:
            import yaml  # lazy, optional
        except ImportError:
            return None, "yaml", (
                "body is YAML but PyYAML is not installed — "
                "`pip install pyyaml`, or convert the spec to JSON and pass it to "
                "endpoints_from_spec() directly"
            )
        try:
            obj = yaml.safe_load(stripped)
        except Exception as exc:  # noqa: BLE001 - yaml raises many types
            return None, "yaml", f"YAML parse failed: {exc}"
        return obj, "yaml", None
    return None, "", "body is neither JSON nor YAML (probably an HTML docs page)"


def _is_spec(obj: Any) -> Optional[str]:
    """Classify a parsed document: ``openapi`` / ``swagger`` / ``ai-plugin`` / None."""
    if not isinstance(obj, dict):
        return None
    if obj.get("openapi"):
        return "openapi"
    if obj.get("swagger"):
        return "swagger"
    if isinstance(obj.get("paths"), dict) and obj["paths"]:
        return "openapi"
    if obj.get("schema_version") and isinstance(obj.get("api"), dict):
        return "ai-plugin"
    return None


class _Pace:
    """Sequential pacing for polite probing (caller-supplied requests/minute)."""

    def __init__(self, qpm: Optional[float]) -> None:
        self.min_gap = 60.0 / qpm if qpm and qpm > 0 else 0.0
        self._last = 0.0

    def wait(self) -> None:
        if not self.min_gap:
            return
        gap = self.min_gap - (time.monotonic() - self._last)
        if gap > 0:
            time.sleep(gap)
        self._last = time.monotonic()


def discover_spec(
    base_url: str,
    *,
    headers: Optional[Dict[str, str]] = None,
    timeout_s: float = 10.0,
    verify_tls: bool = True,
    paths: Optional[Sequence[str]] = None,
    rate_limit_qpm: Optional[float] = None,
) -> Dict[str, Any]:
    """Fetch the target's API spec from the well-known locations.

    Tries :data:`SPEC_PATHS` in order and returns the FIRST document that parses
    as an OpenAPI/Swagger/ai-plugin spec. Low volume and sequential by design:
    one GET per location, an optional ``rate_limit_qpm`` gap between them, and an
    early stop after repeated 401/403 (a host refusing anonymous reads is not
    something to keep poking) or repeated connection failures.

    Network happens only inside this call; ``requests`` is imported lazily.

    Args:
        base_url: target base (``https://api.example.com`` or ``.../api/v2``).
            May also point straight at a ``.json``/``.yaml`` document.
        headers: extra headers (e.g. an Authorization the customer gave you).
        timeout_s: per-request timeout.
        verify_tls: set False only for private-CA targets.
        paths: override the probe list.
        rate_limit_qpm: max requests per minute across this call.

    Returns:
        ``{"ok", "spec", "spec_url", "format", "kind", "endpoints", "tried",
        "error", "hint"}``. ``endpoints`` is :func:`endpoints_from_spec` on the
        hit, so a caller can go straight to building candidates. On failure
        ``error`` says what happened and ``hint`` says what to do next.
    """
    import requests  # lazy: no network machinery at import time

    probe_paths = tuple(paths) if paths else SPEC_PATHS
    candidates = _spec_candidates(base_url, probe_paths)
    req_headers = {
        "Accept": "application/json, application/yaml, text/yaml;q=0.9, */*;q=0.1",
        "User-Agent": _USER_AGENT,
    }
    req_headers.update(headers or {})

    pace = _Pace(rate_limit_qpm)
    tried: List[Dict[str, Any]] = []
    auth_failures = 0
    connect_failures = 0
    yaml_missing = False
    session = requests.Session()

    def _result(**kw: Any) -> Dict[str, Any]:
        out: Dict[str, Any] = {"ok": False, "spec": None, "spec_url": None, "format": None,
                               "kind": None, "endpoints": [], "tried": tried,
                               "error": None, "hint": None}
        out.update(kw)
        return out

    try:
        for url in candidates:
            pace.wait()
            try:
                resp = session.get(url, headers=req_headers, timeout=timeout_s,
                                   verify=verify_tls, allow_redirects=True)
            except Exception as exc:  # noqa: BLE001 - requests raises many transport errors
                connect_failures += 1
                tried.append({"url": url, "status": None, "ok": False, "note": str(exc)[:200]})
                if connect_failures >= _MAX_CONNECT_FAILURES:
                    return _result(
                        error=f"could not reach {_origin(_normalize_base(base_url))} "
                              f"({connect_failures} transport failures; last: {str(exc)[:160]})",
                        hint="check the host/VPN/proxy, or pass verify_tls=False for a private CA")
                continue

            status = resp.status_code
            if status in (401, 403):
                auth_failures += 1
                tried.append({"url": url, "status": status, "ok": False,
                              "note": "auth required"})
                if auth_failures >= _MAX_AUTH_FAILURES:
                    return _result(
                        error=f"the target returns {status} for spec paths (stopped after "
                              f"{auth_failures} auth failures — no credential guessing)",
                        hint="ask the customer for a read token and pass it via "
                             "headers={'Authorization': 'Bearer ...'}, or ask them to send the "
                             "spec file / a working curl instead")
                continue
            if status == 429:
                retry_after = resp.headers.get("Retry-After")
                return _result(
                    error=f"rate limited (429) at {url}",
                    hint=(f"wait {retry_after}s and retry" if retry_after else
                          "retry later with rate_limit_qpm set to a low value (e.g. 10)"))
            if status >= 400:
                tried.append({"url": url, "status": status, "ok": False, "note": "not found"})
                continue

            ctype = resp.headers.get("Content-Type", "")
            obj, fmt, err = _parse_spec_body(resp.text, ctype)
            if obj is None:
                if fmt == "yaml" and err and "PyYAML" in err:
                    yaml_missing = True
                tried.append({"url": url, "status": status, "ok": False, "note": err or "unparsed"})
                continue

            kind = _is_spec(obj)
            if kind == "ai-plugin":
                # An ai-plugin manifest points AT the real spec — follow it once.
                api_url = ((obj.get("api") or {}).get("url") or "").strip()
                tried.append({"url": url, "status": status, "ok": True,
                              "note": f"ai-plugin manifest -> {api_url or '(no api.url)'}"})
                if not api_url:
                    continue
                pace.wait()
                try:
                    resp2 = session.get(api_url, headers=req_headers, timeout=timeout_s,
                                        verify=verify_tls, allow_redirects=True)
                    obj2, fmt2, err2 = _parse_spec_body(resp2.text,
                                                        resp2.headers.get("Content-Type", ""))
                except Exception as exc:  # noqa: BLE001
                    tried.append({"url": api_url, "status": None, "ok": False,
                                  "note": str(exc)[:200]})
                    continue
                tried.append({"url": api_url, "status": resp2.status_code,
                              "ok": obj2 is not None, "note": err2 or "parsed"})
                if obj2 is not None and _is_spec(obj2):
                    return _result(ok=True, spec=obj2, spec_url=api_url, format=fmt2,
                                   kind=_is_spec(obj2), endpoints=endpoints_from_spec(obj2))
                continue
            if kind is None:
                tried.append({"url": url, "status": status, "ok": False,
                              "note": "parsed but has no openapi/swagger/paths keys"})
                continue

            tried.append({"url": url, "status": status, "ok": True, "note": f"{kind} spec"})
            endpoints = endpoints_from_spec(obj)
            res = _result(ok=True, spec=obj, spec_url=url, format=fmt, kind=kind,
                          endpoints=endpoints)
            if not endpoints:
                res["hint"] = ("spec found but no chat-like POST operation matched; inspect "
                               "spec['paths'] and build the config with "
                               "config_from_spec_endpoint(base_url, {'path':..., 'method':'post'})")
            return res
    finally:
        try:
            session.close()
        except Exception:  # noqa: BLE001 - closing must never mask the real result
            pass

    hint = ("no machine-readable spec at the well-known locations. Next: ask for the spec URL "
            "(pass it as base_url), or ask for ONE working curl and use from_curl()")
    if yaml_missing:
        hint = ("a YAML spec was found but PyYAML is not installed — `pip install pyyaml` and "
                "retry, or convert the spec to JSON. " + hint)
    return _result(error=f"no spec found in {len(tried)} probed locations", hint=hint)


# --------------------------------------------------------------------------- #
# spec -> candidate chat endpoints                                            #
# --------------------------------------------------------------------------- #
_CHAT_WORDS = (
    "chat", "message", "completion", "converse", "invoke", "query", "ask",
    "generate", "prompt", "conversation", "assistant", "agent", "respond",
    "answer", "inference", "predict", "run", "talk", "send",
)
_ANTI_WORDS = (
    "delete", "feedback", "history", "list", "upload", "file", "login",
    "logout", "token", "auth", "health", "metric", "admin", "rating",
    "thumbs", "export", "config", "webhook", "subscribe", "batch", "cancel",
    "status", "usage", "billing", "embedding", "moderation", "transcription",
    "speech", "image", "audio", "vector", "index", "document",
)


def _deref(spec: Any, node: Any, depth: int = 0, seen: Optional[set] = None) -> Any:
    """Resolve local ``$ref`` pointers against the spec root.

    Recursion is bounded and ref-cycle guarded — self-referential schemas (a
    message whose ``parent`` is a message) are common and must not hang.
    """
    if depth > 12 or not isinstance(node, (dict, list)):
        return node
    seen = set() if seen is None else seen
    if isinstance(node, dict):
        ref = node.get("$ref")
        if isinstance(ref, str):
            if not ref.startswith("#/") or ref in seen:
                return {k: v for k, v in node.items() if k != "$ref"}
            target: Any = spec
            for part in ref[2:].split("/"):
                part = part.replace("~1", "/").replace("~0", "~")
                if isinstance(target, dict):
                    target = target.get(part)
                else:
                    target = None
                if target is None:
                    return {}
            return _deref(spec, target, depth + 1, seen | {ref})
        return {k: _deref(spec, v, depth + 1, seen) for k, v in node.items()}
    return [_deref(spec, v, depth + 1, seen) for v in node]


def _json_content_schema(container: Dict[str, Any]) -> Tuple[Optional[Any], Optional[str]]:
    """Pull the JSON schema out of an OAS3 ``content`` map (or the first type)."""
    content = container.get("content")
    if not isinstance(content, dict) or not content:
        return None, None
    for ctype, media in content.items():
        if "json" in ctype.lower() and isinstance(media, dict):
            return media.get("schema"), ctype
    ctype, media = next(iter(content.items()))
    return (media or {}).get("schema") if isinstance(media, dict) else None, ctype


def _spec_servers(spec: Dict[str, Any]) -> List[str]:
    """Server prefixes declared by the spec (OAS3 ``servers`` / Swagger2 ``basePath``)."""
    out: List[str] = []
    for srv in spec.get("servers") or []:
        if isinstance(srv, dict) and isinstance(srv.get("url"), str):
            out.append(srv["url"])
    if not out and isinstance(spec.get("basePath"), str):
        out.append(spec["basePath"])
    return out


def _score_endpoint(path: str, op: Dict[str, Any], req_schema: Any,
                    resp_schema: Any) -> Tuple[float, List[str]]:
    """Rank how likely an operation is THE chat call.

    The score only orders the try-list; a low score is still tried, because only
    a live call decides. Reasons are returned so a human can audit the order.
    """
    reasons: List[str] = []
    text_parts = [path, str(op.get("summary") or ""), str(op.get("operationId") or ""),
                  str(op.get("description") or "")[:200]]
    tags = op.get("tags")
    if isinstance(tags, list):
        text_parts.extend(str(t) for t in tags)
    haystack = " ".join(text_parts).lower()

    score = 0.0
    for w in _CHAT_WORDS:
        if w in haystack:
            score += 2.0
            reasons.append(f"keyword:{w}")
    for w in _ANTI_WORDS:
        if w in haystack:
            score -= 1.5
            reasons.append(f"anti:{w}")
    # A request body with a message-like string property is the strongest signal
    # available offline: it is where the prompt would go.
    props = (req_schema or {}).get("properties") if isinstance(req_schema, dict) else None
    if isinstance(props, dict):
        for name in props:
            if _key_score(str(name)) >= 3.5:
                score += 2.5
                reasons.append(f"request-field:{name}")
                break
    rprops = (resp_schema or {}).get("properties") if isinstance(resp_schema, dict) else None
    if isinstance(rprops, dict):
        for name in rprops:
            if _answer_key_score(str(name)) >= 3.0:
                score += 1.5
                reasons.append(f"response-field:{name}")
                break
    return score, reasons


def endpoints_from_spec(spec: Any, *, methods: Sequence[str] = ("post",),
                        min_score: float = 0.5) -> List[Dict[str, Any]]:
    """Extract candidate CHAT endpoints from a parsed OpenAPI/Swagger spec.

    Pure — no network. Handles OpenAPI 3 (``requestBody.content``) and Swagger 2
    (``parameters[in=body].schema``), and resolves local ``$ref``s so the caller
    gets usable schemas rather than pointers.

    Args:
        spec: the parsed spec document.
        methods: HTTP methods to consider (chat calls are POST in practice).
        min_score: drop candidates below this rank.

    Returns:
        ``[{"path", "method", "request_schema", "response_schema", "summary",
        "score", "operation_id", "tags", "parameters", "content_type",
        "server", "reasons"}, ...]``, best first. Every entry is a candidate to
        be TRIED, not a conclusion.
    """
    if not isinstance(spec, dict):
        return []
    paths = spec.get("paths")
    if not isinstance(paths, dict):
        return []
    servers = _spec_servers(spec)
    server = servers[0] if servers else ""
    consumes_root = spec.get("consumes") if isinstance(spec.get("consumes"), list) else None

    out: List[Dict[str, Any]] = []
    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        shared_params = item.get("parameters") or []
        for method in methods:
            op = item.get(method) or item.get(method.upper())
            if not isinstance(op, dict):
                continue
            op = _deref(spec, op)
            params = list(_deref(spec, shared_params) or []) + list(op.get("parameters") or [])

            # request schema: OAS3 first, then Swagger 2 body/formData params.
            req_schema, content_type = None, None
            body_container = op.get("requestBody")
            if isinstance(body_container, dict):
                req_schema, content_type = _json_content_schema(body_container)
            if req_schema is None:
                for p in params:
                    if isinstance(p, dict) and p.get("in") == "body":
                        req_schema = p.get("schema")
                        content_type = (consumes_root or op.get("consumes") or
                                        ["application/json"])[0]
                        break
            req_schema = _deref(spec, req_schema) if req_schema is not None else None

            # response schema: first 2xx, else default.
            responses = op.get("responses") or {}
            resp_schema = None
            for code in ("200", "201", "202", 200, 201, 202, "default"):
                r = responses.get(code)
                if isinstance(r, dict):
                    resp_schema, _ = _json_content_schema(r)
                    if resp_schema is None:
                        resp_schema = r.get("schema")
                    if resp_schema is not None:
                        break
            resp_schema = _deref(spec, resp_schema) if resp_schema is not None else None

            score, reasons = _score_endpoint(str(path), op, req_schema, resp_schema)
            if score < min_score:
                continue
            out.append({
                "path": str(path),
                "method": method.upper(),
                "request_schema": req_schema,
                "response_schema": resp_schema,
                "summary": op.get("summary") or op.get("description") or "",
                "score": round(score, 2),
                "operation_id": op.get("operationId"),
                "tags": op.get("tags") or [],
                "parameters": params,
                "content_type": content_type or "application/json",
                "server": server,
                "reasons": reasons,
            })
    out.sort(key=lambda e: e["score"], reverse=True)
    return out


# --------------------------------------------------------------------------- #
# spec endpoint -> runnable config                                            #
# --------------------------------------------------------------------------- #
_PLACEHOLDER_BY_FORMAT = {
    "date-time": "2024-01-01T00:00:00Z",
    "date": "2024-01-01",
    "email": "discovery@example.com",
    "uuid": "00000000-0000-4000-8000-000000000000",
    "uri": "https://example.com",
    "url": "https://example.com",
    "hostname": "example.com",
    "ipv4": "127.0.0.1",
    "byte": "YXNjZW5k",
    "password": "ascend-discovery",
}
# Field names whose synthesized value is a GUESS that will 400 if wrong — the
# caller must be told, because "it failed" is otherwise indistinguishable from
# "the endpoint is wrong".
_MUST_CONFIRM_FIELDS = ("model", "deployment", "engine", "agent_id", "agentid",
                        "assistant_id", "bot_id", "botid", "project", "tenant")


def _string_placeholder(name: str, schema: Dict[str, Any]) -> str:
    """A sensible placeholder for a required string property."""
    fmt = str(schema.get("format") or "").lower()
    if fmt in _PLACEHOLDER_BY_FORMAT:
        return _PLACEHOLDER_BY_FORMAT[fmt]
    n = (name or "").lower()
    if n == "role":
        return "user"
    if "id" in n:
        return "ascend-discovery-1"
    if "lang" in n or "locale" in n:
        return "en"
    return "ascend-discovery"


def _synthesize(schema: Any, name: str = "", depth: int = 0,
                notes: Optional[List[str]] = None) -> Any:
    """Build the SMALLEST body the schema declares as valid.

    Priority: ``example``/``default`` from the spec (vendor ground truth) >
    ``enum`` first value > type/format placeholder. Only required properties are
    filled, plus message-like ones (the prompt has to have somewhere to live)
    and any property that ships its own example.
    """
    notes = notes if notes is not None else []
    if not isinstance(schema, dict) or depth > 6:
        return {}
    if "example" in schema:
        return schema["example"]
    if "default" in schema:
        return schema["default"]
    for combiner in ("allOf", "oneOf", "anyOf"):
        if isinstance(schema.get(combiner), list) and schema[combiner]:
            if combiner == "allOf":
                merged: Dict[str, Any] = {}
                for sub in schema[combiner]:
                    part = _synthesize(sub, name, depth + 1, notes)
                    if isinstance(part, dict):
                        merged.update(part)
                if merged:
                    return merged
            else:
                return _synthesize(schema[combiner][0], name, depth + 1, notes)
    if isinstance(schema.get("enum"), list) and schema["enum"]:
        enum = schema["enum"]
        if (name or "").lower() == "role" and "user" in enum:
            return "user"
        return enum[0]

    stype = schema.get("type")
    if isinstance(stype, list):
        stype = next((t for t in stype if t != "null"), "string")
    if stype == "object" or (stype is None and "properties" in schema):
        props = schema.get("properties") or {}
        required = set(schema.get("required") or [])
        out: Dict[str, Any] = {}
        for pname, pschema in props.items():
            if not isinstance(pschema, dict):
                continue
            wanted = (pname in required
                      or _key_score(str(pname)) >= 3.5
                      or "example" in pschema or "default" in pschema)
            if not wanted:
                continue
            out[pname] = _synthesize(pschema, str(pname), depth + 1, notes)
            if str(pname).lower() in _MUST_CONFIRM_FIELDS and isinstance(out[pname], str):
                notes.append(
                    f"required field '{pname}' was filled with the placeholder "
                    f"{out[pname]!r}; set the real value if the call returns 4xx")
        return out
    if stype == "array":
        items = schema.get("items") or {}
        min_items = schema.get("minItems") or 0
        # One item when the array is required-ish or message-like: an empty
        # `messages: []` is a valid body that can never carry a prompt.
        if min_items or _key_score(name) >= 3.5 or isinstance(items, dict) and items:
            return [_synthesize(items, name, depth + 1, notes)]
        return []
    if stype == "integer":
        return schema.get("minimum", 1)
    if stype == "number":
        return schema.get("minimum", 1)
    if stype == "boolean":
        return False
    if stype == "null":
        return None
    return _string_placeholder(name, schema)


def _place_prompt(body: Any, notes: List[str]) -> Tuple[Any, Optional[str]]:
    """Put ``{{PROMPT}}`` in the most message-like string in a synthesized body."""
    if isinstance(body, str):
        return PROMPT_PLACEHOLDER, ""
    if not isinstance(body, (dict, list)):
        return {"message": PROMPT_PLACEHOLDER}, "message"
    leaves = _string_leaves(body)
    scored = [(_key_score(k) + (0.5 if v == "ascend-discovery" else 0.0), p)
              for p, k, v in leaves]
    scored = [(s, p) for s, p in scored if s > 0]
    if scored:
        scored.sort(reverse=True)
        path = scored[0][1]
        body = copy.deepcopy(body)
        _set_at_path(body, path, PROMPT_PLACEHOLDER)
        return body, path
    if isinstance(body, dict):
        body = copy.deepcopy(body)
        body["message"] = PROMPT_PLACEHOLDER
        notes.append(
            "the request schema declares no message-like string property; added "
            "'message' as the prompt field — check the spec if the target rejects it")
        return body, "message"
    notes.append("could not place {{PROMPT}} in the schema-derived body; edit it by hand")
    return body, None


def _schema_answer_paths(schema: Any, prefix: str = "", key: str = "",
                         depth: int = 0) -> List[Tuple[float, str]]:
    """Candidate ``(score, dot_path)`` pairs for the answer string in a response."""
    if not isinstance(schema, dict) or depth > 6:
        return []
    for combiner in ("allOf", "oneOf", "anyOf"):
        if isinstance(schema.get(combiner), list) and schema[combiner]:
            out: List[Tuple[float, str]] = []
            for sub in schema[combiner]:
                out.extend(_schema_answer_paths(sub, prefix, key, depth + 1))
            return out
    stype = schema.get("type")
    if isinstance(stype, list):
        stype = next((t for t in stype if t != "null"), None)
    if stype == "object" or "properties" in schema:
        out = []
        for pname, pschema in (schema.get("properties") or {}).items():
            child = f"{prefix}.{pname}" if prefix else str(pname)
            out.extend(_schema_answer_paths(pschema, child, str(pname), depth + 1))
        return out
    if stype == "array":
        child = f"{prefix}.0" if prefix else "0"
        return _schema_answer_paths(schema.get("items") or {}, child, key, depth + 1)
    if stype == "string" or (stype is None and not schema):
        score = _answer_key_score(key)
        # A shallower answer field beats a deeply nested same-named one.
        return [(score - 0.2 * prefix.count("."), prefix)] if score > 0 else []
    return []


def _join_url(base: str, server: str, path: str) -> str:
    """Join base + spec server prefix + operation path without duplicating segments."""
    base = _normalize_base(base)
    prefix = ""
    if server:
        if _URLISH_RE.match(server):
            s = urlsplit(server)
            if s.netloc == urlsplit(base).netloc:
                base = urlunsplit((s.scheme, s.netloc, "", "", "")) + s.path.rstrip("/")
                prefix = ""
            else:
                prefix = s.path.rstrip("/")
        else:
            prefix = "/" + server.strip("/") if server.strip("/") else ""
    if prefix and urlsplit(base).path.rstrip("/").endswith(prefix):
        prefix = ""   # base already carries the server prefix
    if not path.startswith("/"):
        path = "/" + path
    return base + prefix + path


def config_from_spec_endpoint(base_url: str, endpoint: Dict[str, Any]) -> Dict[str, Any]:
    """Build a ``direct_api`` config from one spec endpoint candidate.

    The body is the smallest request the schema declares as valid, with
    ``{{PROMPT}}`` in the most message-like string property; ``response_path`` is
    the most answer-like string in the declared response schema (or None, which
    lets ``direct_api`` fall back to a best-effort extract).

    Everything here is derived from the vendor's own document — but it is still
    only a CANDIDATE. Prove it with ``validate_config`` before using it, and try
    the next candidate when it fails.

    Args:
        base_url: the target base URL (the spec's ``servers`` entry is folded in).
        endpoint: one dict from :func:`endpoints_from_spec` (only ``path`` and
            ``method`` are strictly required).

    Returns:
        A ``direct_api`` config with ``_source: "openapi"`` and ``_notes``
        listing every value that was synthesized rather than declared.
    """
    if not isinstance(endpoint, dict) or not endpoint.get("path"):
        raise ValueError("endpoint must be a dict with at least {'path': '/chat'} "
                         "(use endpoints_from_spec() to build one)")
    notes: List[str] = []
    path = str(endpoint["path"])
    method = str(endpoint.get("method") or "POST").upper()

    # Path + query parameters declared on the operation.
    params = endpoint.get("parameters") or []
    query_pairs: List[Tuple[str, str]] = []
    for p in params:
        if not isinstance(p, dict):
            continue
        loc, pname = p.get("in"), str(p.get("name") or "")
        pschema = p.get("schema") if isinstance(p.get("schema"), dict) else p
        if loc == "path" and pname:
            value = _synthesize(pschema, pname, notes=notes)
            value = value if isinstance(value, str) else str(value)
            path = path.replace("{%s}" % pname, value)
            notes.append(f"path parameter '{pname}' filled with placeholder {value!r} — "
                         "replace it with a real id")
        elif loc == "query" and pname and p.get("required"):
            value = _synthesize(pschema, pname, notes=notes)
            query_pairs.append((pname, value if isinstance(value, str) else str(value)))

    endpoint_url = _join_url(base_url, str(endpoint.get("server") or ""), path)
    if query_pairs:
        endpoint_url = _append_query(endpoint_url, urlencode(query_pairs))

    req_schema = endpoint.get("request_schema")
    if isinstance(req_schema, dict) and req_schema:
        body = _synthesize(req_schema, notes=notes)
        if not isinstance(body, (dict, list, str)):
            body = {}
    else:
        body = {}
        notes.append("the spec declares no JSON request body for this operation; "
                     "using {'message': '{{PROMPT}}'} — confirm against the docs")
    body, prompt_path = _place_prompt(body if body != {} else {}, notes)

    resp_candidates = _schema_answer_paths(endpoint.get("response_schema"))
    response_path: Optional[str] = None
    if resp_candidates:
        resp_candidates.sort(reverse=True)
        response_path = resp_candidates[0][1] or None
    if response_path is None:
        notes.append(
            "no answer-like string in the declared response schema; response_path is None, so "
            "direct_api falls back to the deepest string in the reply (often an id). Pin "
            "response_path from the first live reply before running an assessment")

    headers = {"Content-Type": endpoint.get("content_type") or "application/json",
               "Accept": "application/json"}
    return {
        "adapter": "direct_api",
        "endpoint": endpoint_url,
        "method": method,
        "headers": headers,
        "body": body,
        "response_path": response_path,
        "timeout_ms": 30000,
        "_source": "openapi",
        "_prompt_field": f"body:{prompt_path}" if prompt_path is not None else None,
        "_endpoint": {"path": endpoint.get("path"), "method": method,
                      "summary": endpoint.get("summary", ""),
                      "operation_id": endpoint.get("operation_id"),
                      "score": endpoint.get("score"),
                      "reasons": endpoint.get("reasons", [])},
        "_notes": notes,
    }


def configs_from_spec(base_url: str, spec: Any, *, limit: int = 5) -> List[Dict[str, Any]]:
    """Convenience: ranked candidate configs for a spec, best first.

    The ranking decides only the ORDER in which candidates are tried — feed the
    list to ``validate.iterate``/the prober and let a real answer decide which
    one is right.
    """
    return [config_from_spec_endpoint(base_url, ep)
            for ep in endpoints_from_spec(spec)[: max(0, limit)]]
