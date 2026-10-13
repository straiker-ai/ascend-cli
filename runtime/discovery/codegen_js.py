"""
codegen_js — a derived contract as a hosted JavaScript ADAPTOR for the Ascend engine.

`ascend target add` derives a contract (`direct_api`, `sse_stream`, `websocket_direct`,
`session_api`, `session_poll`, …) and proves it against the live target. This module turns that
proven contract into the one file the engine runs on its own side: a synchronous
`sendTurn(turn, host)` stored on a direct application as `request_template._adaptor_src`. Nothing
then has to run on the operator's machine for the whole assessment, which is why the hosted
adaptor is the default and the local bridge is the explicit, deprecated path.

One generator per shape, each modelled on an adaptor that already passed the publish gate and
ran a scored assessment against a live target:

    direct_api        one request, one JSON (or text) reply, the answer at `response_path`
    sse_stream        one request, a token stream to reassemble (data: frames or ndjson), with an
                      optional create-a-conversation step and a `{{CONV}}` path
    websocket_direct  one socket per turn: send the templated frame, collect frames until a
                      terminal frame or an idle gap, bounded
    session_api       create a session (minted once per conversation in `host.state.getOrMint`),
                      send through it, re-mint once on a 401
    session_poll      create -> send -> poll the transcript until a new bot turn appears
    scaffold          everything else: the shipped onboarding scaffold with the captured request
                      described in its header, for a person or an agent to finish

Rules every generated file obeys (the gate refuses the rest; the engine's own gate.core.js is
the authority): synchronous host calls only, no `async`/`await`/`Promise`, no
`fetch`/`require`/`import`, no timers, no global the isolate does not have (only the names
host.d.ts lists — `console` IS one, routed to host.log), no `this` outside a class body, no
`with`, no `host[expr]`, no `__`-prefixed name, plain JavaScript (not TypeScript), and `sendTurn`
defined. The prompt is read from the rendered payload; headers come from `turn.headers`;
credentials come only from `turn.headers` or `host.config` — never a literal in the source.

The pure half: no network, no terminal. The CLI (`shells/cli/ascend.py`) gates the result
through the engine, creates the application and proves the stored bytes with `adaptor verify`.
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

PROMPT_TOKEN = "{{PROMPT}}"
RESPONSE_TOKEN = "{{RESPONSE}}"
# The shapes a generator exists for. Anything else gets the scaffold.
SHAPES = ("direct_api", "sse_stream", "websocket_direct", "session_api", "session_poll")
SCAFFOLD = "scaffold"
# Auth kinds runtime/layers/auth.py resolves on this machine: a login, a CSRF handshake, a derived
# multi-hop token. No generator runs one yet, so a config that authenticates this way gets the
# SCAFFOLD — the app is adaptor-driven from the start, with the handshake named in the file's
# header, and the repair loop (`adaptor test` → finish sendTurn → `adaptor store`) completes it.
# The alternative, a direct_api adaptor sending static headers, 401'd on every probe.
# shells/cli/ascend.py mirrors this tuple (a test pins the two equal).
DYNAMIC_AUTH_KINDS = ("oauth2", "csrf", "derived_multihop")
# Names Straiker reaches itself (runtime/discovery/egress.py ROUTED_SUFFIXES, restated here so the
# generator stays importable on its own). A tunnel name is the real host plus the suffix; the
# engine reaches a second host only through the same tunnel, under the same rule.
TUNNEL_SUFFIX = ".tun.straiker.ai"
PRIVATE_LINK_SUFFIX = ".pl.straiker.ai"
# Placeholders a derived URL may carry; the application's URL stops before the first one and the
# adaptor renders the rest on that origin per turn.
_PLACEHOLDER = re.compile(r"\{\{[A-Za-z_][A-Za-z0-9_]*\}\}")
# Where the engine's rendered payload is looked up for the prompt when the derived path misses.
PROMPT_FALLBACK = ["message", "prompt", "text", "input", "query", "q", "content", "question"]
DEFAULT_RESPONSE_TEMPLATE = {"response": RESPONSE_TOKEN}


# ----------------------------------------------------------------------------- the contract
def handshake_kind(cfg: Dict[str, Any]) -> Optional[str]:
    """The login handshake a config authenticates with (one of DYNAMIC_AUTH_KINDS), or None when
    its auth is static. `auth` is one block or a list of blocks; a list is a handshake when any
    block is one."""
    auth = (cfg or {}).get("auth")
    blocks = auth if isinstance(auth, list) else [auth] if isinstance(auth, dict) else []
    for b in blocks:
        kind = str((b or {}).get("type") or "") if isinstance(b, dict) else ""
        if kind in DYNAMIC_AUTH_KINDS:
            return kind
    return None


def transport_shape(cfg: Dict[str, Any]) -> str:
    """The transport the config describes — its adapter, normalised — among the shapes this
    module knows, else the scaffold. This is what decides where the address and the body come
    from; which GENERATOR runs is `shape_of`, which can still fall to the scaffold."""
    kind = str((cfg or {}).get("adapter") or "direct_api").lower()
    if kind == "api":
        kind = "direct_api"
    return kind if kind in SHAPES else SCAFFOLD


def shape_of(cfg: Dict[str, Any]) -> str:
    """Which generator a config gets: its adapter when one exists AND nothing stands in the way
    of a generated file running it, else the scaffold.

    A login handshake (DYNAMIC_AUTH_KINDS) is the one thing that stands in the way today: no
    generator mints a token or completes a CSRF dance, so the file is the scaffold with the
    handshake named in its header, and `plan()["finished"]` is False.
    """
    if handshake_kind(cfg):
        return SCAFFOLD
    return transport_shape(cfg)

# Python 3.9 forbids a backslash inside an f-string expression, so the fallback is named here.
NO_EXTRA_HEADERS = "(none beyond the application's)"


def raw_url(cfg: Dict[str, Any]) -> str:
    """The transport's real address, placeholders included, however the adapter spells it."""
    cfg = cfg or {}
    shape = transport_shape(cfg)
    if shape == "sse_stream":
        base = str(cfg.get("base_url") or "").rstrip("/")
        path = str(cfg.get("chat_path") or "")
        if base and path:
            return base + ("/" + path.lstrip("/"))
        return base or path or str(cfg.get("endpoint") or cfg.get("url") or "")
    if shape == "websocket_direct":
        return str(cfg.get("ws_url") or cfg.get("url") or "")
    if shape == "session_api":
        return str(cfg.get("message_endpoint") or cfg.get("endpoint") or cfg.get("url") or "")
    if shape == "session_poll":
        return str((cfg.get("send") or {}).get("url") or "")
    return str(cfg.get("endpoint") or cfg.get("url") or cfg.get("message_endpoint") or "")


def app_url(cfg: Dict[str, Any]) -> str:
    """The address the application is registered with: the real one, cut before any placeholder.

    `https://h/api/threads/{{CONV}}/stream` registers as `https://h/api/threads`; the adaptor
    renders the templated path on that origin itself (`targetUrl`), so the platform never sees a
    brace in a URL and the engine's egress allowlist still names the right host.
    """
    url = raw_url(cfg)
    m = _PLACEHOLDER.search(url)
    if not m:
        return url
    cut = url[:m.start()]
    scheme_end = cut.find("://")
    if cut.find("?", scheme_end + 3 if scheme_end >= 0 else 0) >= 0:
        # A placeholder inside the query string takes its whole parameter with it: `?conv=` is
        # not an address either.
        cut = re.sub(r"[?&][^?&]*$", "", cut)
    return cut.rstrip("/?&=")


def path_template(cfg: Dict[str, Any]) -> Optional[str]:
    """The path (+query) of the raw URL when it carries a placeholder, else None."""
    url = raw_url(cfg)
    if not _PLACEHOLDER.search(url):
        return None
    parts = urlsplit(url)
    path = parts.path or "/"
    return path + (f"?{parts.query}" if parts.query else "")


def body_template(cfg: Dict[str, Any]) -> Any:
    """The request body the shape sends, with `{{PROMPT}}` where the prompt goes."""
    cfg = cfg or {}
    shape = transport_shape(cfg)
    if shape == "sse_stream":
        return cfg.get("request_template") if cfg.get("request_template") is not None else {"message": PROMPT_TOKEN}
    if shape == "websocket_direct":
        return cfg.get("send_template") if cfg.get("send_template") is not None else {"type": "message", "text": PROMPT_TOKEN}
    if shape == "session_api":
        return cfg.get("message_body") if cfg.get("message_body") is not None else {"message": PROMPT_TOKEN}
    if shape == "session_poll":
        send = cfg.get("send") or {}
        return send.get("body") if send.get("body") is not None else {"message": PROMPT_TOKEN}
    body = cfg.get("body")
    if body is None:
        body = cfg.get("request_body")
    if body is None and isinstance(cfg.get("message"), dict):
        body = cfg["message"].get("body")
    if body is None:
        body = {"message": PROMPT_TOKEN}
    if isinstance(body, dict) and PROMPT_TOKEN not in json.dumps(body):
        field = cfg.get("prompt_field") or "prompt"
        body = {**{k: v for k, v in body.items() if k != field}, field: PROMPT_TOKEN}
    return body


def prompt_path(body: Any) -> List[str]:
    """Segments to the first `{{PROMPT}}` leaf of a body template (list indices as strings)."""
    def walk(v, path):
        if isinstance(v, dict):
            for k, x in v.items():
                found = walk(x, path + [str(k)])
                if found is not None:
                    return found
        elif isinstance(v, list):
            for i, x in enumerate(v):
                found = walk(x, path + [str(i)])
                if found is not None:
                    return found
        elif isinstance(v, str) and PROMPT_TOKEN in v:
            return path
        return None
    return walk(body, []) or []


def request_template(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """The application's request_template: what the engine renders into `turn.payload`.

    A direct target keeps its whole body (the same template a plain `api` app would carry); every
    other shape carries just the prompt key, because the adaptor holds the real body template and
    rebuilds it per turn (a session id, a conversation id and a uuid go in there too).
    """
    body = body_template(cfg)
    if transport_shape(cfg) == "direct_api" and isinstance(body, dict):
        return dict(body)
    path = prompt_path(body)
    key = path[0] if path and not path[0].isdigit() else "message"
    return {key: PROMPT_TOKEN}


def _mirror(path: str) -> Any:
    """`choices.0.message.content` -> {"choices": [{"message": {"content": "{{RESPONSE}}"}}]}."""
    node: Any = RESPONSE_TOKEN
    for seg in reversed([s for s in re.split(r"[.\[\]]+", str(path)) if s != ""]):
        node = [node] if seg.isdigit() else {seg: node}
    return node


def response_template(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Where the engine reads the reply: a mirror of the proven answer path for a direct target,
    `{"response": ...}` for every reassembled shape (the adaptor returns one string)."""
    cfg = cfg or {}
    if shape_of(cfg) == "direct_api" and cfg.get("response_path"):
        mirror = _mirror(cfg["response_path"])
        if isinstance(mirror, dict):
            return mirror
    return dict(DEFAULT_RESPONSE_TEMPLATE)


def reply_body_js(template: Any) -> str:
    """The JavaScript expression of the body `sendTurn` must return for this response_template:
    the `{{RESPONSE}}` leaf becomes `text`, everything else is kept literally."""
    def walk(v):
        if isinstance(v, dict):
            return "{ " + ", ".join(f"{json.dumps(str(k))}: {walk(x)}" for k, x in v.items()) + " }"
        if isinstance(v, list):
            return "[" + ", ".join(walk(x) for x in v) + "]"
        if isinstance(v, str) and "RESPONSE" in v:
            return "text"
        return json.dumps(v)
    return walk(template)


def reply_statement(template: Any) -> str:
    """The `return` the app's response_template asks for, as `ascend adaptor shape` prints it
    (runtime/adaptor.py decides); the code itself is built from `reply_body_js`."""
    shape = _adaptor_rules().reply_shape(template)
    if shape:
        return shape["statement"]
    return f"return {{ status_code: 200, body: {reply_body_js(template)} }};"


def _host(url: str) -> str:
    try:
        u = url if "://" in str(url) else f"https://{url}"
        return (urlsplit(u).hostname or "").lower()
    except ValueError:
        return ""


def routed_app(cfg: Dict[str, Any]) -> Tuple[str, str]:
    """("tunnel" | "private-link", the app's host) when the application's URL is a name Straiker
    routes, else ("", "")."""
    host = _host(app_url(cfg))
    if host.endswith(TUNNEL_SUFFIX):
        return "tunnel", host
    if host.endswith(PRIVATE_LINK_SUFFIX):
        return "private-link", host
    return "", ""


def _second_host_slots(cfg: Dict[str, Any]) -> List[Tuple[Dict[str, Any], str]]:
    """Every (container, key) a shape's extra URLs live under: the places a second host can be
    named, read by the generators and by `extra_domains` alike."""
    shape = transport_shape(cfg)
    slots: List[Tuple[Dict[str, Any], str]] = []
    if shape == "sse_stream":
        for step in ("create", "bootstrap"):
            if isinstance(cfg.get(step), dict):
                slots.append((cfg[step], "url"))
    elif shape == "session_api":
        slots.append((cfg, "session_endpoint"))
    elif shape == "session_poll":
        for step in ("create", "poll"):
            if isinstance(cfg.get(step), dict):
                slots.append((cfg[step], "url"))
        for step in cfg.get("bootstrap") or []:
            if isinstance(step, dict):
                slots.append((step, "url"))
    return slots


def tunnel_url(url: str) -> Tuple[str, str]:
    """A real URL as the engine reaches it through the customer's tunnel, plus the allow entry
    the agent needs: `https://auth.corp.internal:8443/v1` -> (`https://auth.corp.internal.tun.straiker.ai/v1`,
    `auth.corp.internal:8443`). The tunnel rule: the host rides inside the name, the port lives in
    the agent's allow list, plain http(s)/ws(s) only, http/ws only on port 80."""
    u = urlsplit(url)
    host = (u.hostname or "").lower()
    scheme = (u.scheme or "https").lower()
    try:
        port = u.port
    except ValueError:
        port = None
    if port is None:
        port = 80 if scheme in ("http", "ws") else 443
    secure = port != 80
    scheme = ("ws" if scheme.startswith("ws") else "http") + ("s" if secure else "")
    path = (u.path or "") + (f"?{u.query}" if u.query else "")
    return f"{scheme}://{host}{TUNNEL_SUFFIX}{path}", f"{host}:{port}"


def route_second_hosts(cfg: Dict[str, Any]) -> Tuple[Dict[str, Any], List[str]]:
    """The config with every second host spelled the way the engine reaches it, plus one note
    per host for the operator.

    An app on a tunnel name is reached through the customer's `ascend-tunnel` agent, and so is
    everything else inside that network: a second host the capture showed (a token mint, a
    transcript service) is only reachable as `<host>.tun.straiker.ai`, through the same agent,
    once that host is in the agent's allow list. The bare name in `_adaptor_domains` — and in the
    generated file — would have the engine dial a name it cannot resolve. A private-link name is
    opaque, so a second host behind one is left as written and the note says it must be routed.
    Nothing changes for an app on a public name.
    """
    kind, _own = routed_app(cfg)
    if not kind:
        return cfg, []
    out = json.loads(json.dumps(cfg or {}))        # a deep copy: the slots are rewritten in place
    notes: List[str] = []
    for holder, key in _second_host_slots(out):
        url = str(holder.get(key) or "")
        h = _host(url) if "://" in url else ""
        if not h or h.endswith((TUNNEL_SUFFIX, PRIVATE_LINK_SUFFIX)):
            continue
        if kind == "tunnel":
            routed, allow = tunnel_url(url)
            holder[key] = routed
            notes.append(f"{h} is reached through the tunnel as {_host(routed)}: the tunnel agent "
                         f"must allow it (--allow {allow}), or every call to it fails from the engine")
        else:
            notes.append(f"{h} is a second host behind a private link: the engine reaches it only "
                         f"if the link routes it, and _adaptor_domains lists it as written")
    return out, notes


def extra_domains(cfg: Dict[str, Any]) -> List[str]:
    """Every host the adaptor reaches beyond the application's URL — `_adaptor_domains` on the
    app, because the engine allowlists egress to the app's host and nothing else. On a tunnel
    app each one is the host's tunnel name (route_second_hosts)."""
    cfg, _notes = route_second_hosts(cfg or {})
    own = _host(app_url(cfg))
    out: List[str] = []
    for holder, key in _second_host_slots(cfg):
        u = str(holder.get(key) or "")
        h = _host(u) if "://" in u else ""
        if h and h != own and h not in out:
            out.append(h)
    return sorted(out)


def adaptor_params(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """`_adaptor_*` keys the application carries for the generated file's parameters."""
    out: Dict[str, Any] = {}
    tmo = (cfg or {}).get("timeout_ms")
    if isinstance(tmo, (int, float)) and tmo > 0:
        out["_adaptor_timeout_ms"] = int(tmo)
    return out


# ----------------------------------------------------------------------------- the JavaScript
def _js(value: Any) -> str:
    """A JavaScript literal for a JSON-ish value. ASCII-escaped, so U+2028/9 cannot break a
    string literal, and `{{…}}` placeholders survive untouched."""
    return json.dumps(value, ensure_ascii=True)


_COMMON = r'''
/** @typedef {import("./host").Host} Host */
/** @typedef {import("./host").Turn} Turn */

var PROMPT_PATH = __PROMPT_PATH__;
var PROMPT_FALLBACK = __PROMPT_FALLBACK__;

/** Duck-typed: the gate denies `.prototype`, and `Array` is not a name the isolate promises. */
function isArray(x) {
  return x !== null && typeof x === "object" && typeof x.length === "number" && typeof x.push === "function";
}

/** Walk a dot path ("a.b.0.c"), descending into JSON held in a string; null when a step is missing. */
function dotGet(obj, path) {
  if (!path) return obj;
  var cur = obj;
  var parts = String(path).split(".");
  for (var i = 0; i < parts.length; i++) {
    if (typeof cur === "string") cur = parseJson(cur);
    if (cur === null || typeof cur !== "object") return null;
    var k = parts[i];
    if (isArray(cur)) {
      var n = Number(k);
      if (k === "" || n !== n) return null;
      cur = cur[n];
    } else {
      cur = cur[k];
    }
    if (typeof cur === "undefined") return null;
  }
  return cur;
}

/** The prompt, wherever this application's template puts it. */
function promptOf(turn) {
  var p = turn.payload || {};
  if (typeof p === "string") return p;
  var v = PROMPT_PATH.length ? dotGet(p, PROMPT_PATH.join(".")) : null;
  if (typeof v === "string" && v) return v;
  for (var i = 0; i < PROMPT_FALLBACK.length; i++) {
    var w = p[PROMPT_FALLBACK[i]];
    if (typeof w === "string" && w) return w;
  }
  return JSON.stringify(p);
}

function jsonText(s) { return JSON.stringify(String(s)).slice(1, -1); }

/** Render a template (object or string) with {{NAME}} placeholders, JSON-safe. */
function render(template, vars) {
  var raw = JSON.stringify(template);
  for (var k in vars) raw = raw.split("{{" + k + "}}").join(jsonText(vars[k]));
  return JSON.parse(raw);
}

/** `base` plus the application's rendered headers; the app's win. */
function headersOf(turn, base) {
  var h = {};
  for (var k in base) h[k] = base[k];
  var th = turn.headers || {};
  for (var k2 in th) h[k2] = th[k2];
  return h;
}

function parseJson(text) {
  try { return JSON.parse(text); } catch (e) { return null; }
}

function errorText(e) { return String(e && e.message ? e.message : e).slice(0, 200); }

function preview(body) {
  var s = typeof body === "string" ? body : JSON.stringify(body);
  return String(s === null || typeof s === "undefined" ? "" : s).slice(0, 300);
}

/** The status mapping host.d.ts makes normative: 400/401/403 verbatim (the credential path
 *  pauses the run), anything else the target did wrong is a retryable 502. */
function targetStatus(status) {
  return status === 400 || status === 401 || status === 403 ? status : 502;
}

function failure(status, error, detail) {
  var body = { error: error };
  if (detail) body.detail = preview(detail);
  return { status_code: status, body: body };
}

/** The reply under the key the application's response_template expects. */
function reply(text, diag) {
  return {
    status_code: 200,
    body: __REPLY_BODY__,
    headers: { "Content-Type": "application/json" },
    _diag: diag || {},
  };
}

function originOf(url) {
  var s = String(url || "");
  var i = s.indexOf("://");
  if (i < 0) return s;
  var rest = s.slice(i + 3);
  var end = rest.length;
  var stops = ["/", "?", "#"];
  for (var j = 0; j < stops.length; j++) {
    var p = rest.indexOf(stops[j]);
    if (p >= 0 && p < end) end = p;
  }
  return s.slice(0, i + 3) + rest.slice(0, end);
}

/** The application's URL as given, or a templated path rendered on its origin. */
function targetUrl(host, pathTemplate, vars) {
  var ep = String(host.config.endpoint() || "");
  if (!pathTemplate) return ep;
  var path = pathTemplate;
  for (var k in vars) path = path.split("{{" + k + "}}").join(String(vars[k]));
  return originOf(ep) + path;
}

/** An absolute URL as given; a bare path on the application's origin. */
function absoluteUrl(host, url) {
  var s = String(url || "");
  if (s.indexOf("://") > 0) return s;
  return originOf(host.config.endpoint()) + (s.charAt(0) === "/" ? s : "/" + s);
}

function contains(list, v) {
  if (!list) return false;
  for (var i = 0; i < list.length; i++) if (list[i] === v) return true;
  return false;
}

/** The string at a path, JSON for a non-string, "" when absent. */
function textAt(obj, path) {
  var v = dotGet(obj, path);
  if (typeof v === "string") return v;
  return v === null || typeof v === "undefined" ? "" : JSON.stringify(v);
}

function timeoutOf(turn, fallback) {
  var params = turn.params || {};
  return Number(params.timeout_ms) || fallback;
}
'''

_DIRECT_API = r'''
var METHOD = __METHOD__;
var BODY = __BODY__;
var RESPONSE_PATH = __RESPONSE_PATH__;
var STOP_MARKER = __STOP_MARKER__;
var CARRY = __CARRY__;
var BASE_HEADERS = __BASE_HEADERS__;
var ANSWER_KEYS = ["response", "reply", "answer", "text", "message", "content", "output", "result"];

/** The answer: at RESPONSE_PATH when one was proven, else the obvious string in the body. */
function answerOf(parsed, raw) {
  if (RESPONSE_PATH) return parsed === null ? "" : textAt(parsed, RESPONSE_PATH);
  if (typeof parsed === "string") return parsed;
  if (parsed !== null && typeof parsed === "object" && !isArray(parsed)) {
    for (var i = 0; i < ANSWER_KEYS.length; i++) {
      var v = parsed[ANSWER_KEYS[i]];
      if (typeof v === "string" && v) return v;
    }
    var longest = "";
    for (var k in parsed) {
      if (typeof parsed[k] === "string" && parsed[k].length > longest.length) longest = parsed[k];
    }
    if (longest) return longest;
  }
  return String(raw || "");
}

/**
 * @param {Turn} turn
 * @param {Host} host
 * @returns {import("./host").Reply}
 */
function sendTurn(turn, host) {
  var timeoutMs = timeoutOf(turn, 60000);
  var prompt = promptOf(turn);
  var body = render(BODY, { PROMPT: prompt, USER_NAME: "ascend" });
  if (CARRY && CARRY.request_field && body !== null && typeof body === "object") {
    var carried = host.state.get("carry");
    if (carried) body[CARRY.request_field] = carried;
  }
  var opts = { method: METHOD, headers: headersOf(turn, BASE_HEADERS), timeoutMs: timeoutMs };
  if (METHOD !== "GET") opts.body = body;
  var res;
  try {
    res = host.http.request(host.config.endpoint(), opts);
  } catch (e) {
    return failure(502, "target unreachable", errorText(e));
  }
  if (res.status >= 400) {
    return failure(targetStatus(res.status), "target returned " + res.status, res.body);
  }
  var parsed = parseJson(res.body);
  var text = answerOf(parsed, res.body);
  if (STOP_MARKER && text) text = text.split(STOP_MARKER)[0];
  if (!text) {
    return failure(502, "no reply text at " + (RESPONSE_PATH || "(body)"),
                   parsed !== null && typeof parsed === "object" ? Object.keys(parsed).join(",") : res.body);
  }
  if (CARRY && CARRY.reply_path && parsed !== null) {
    var id = dotGet(parsed, CARRY.reply_path);
    if (id !== null && (typeof id === "string" || typeof id === "number")) host.state.set("carry", String(id));
  }
  host.log("info", "direct turn complete", { chars: text.length });
  return reply(text, { status: res.status });
}
'''

_SSE_STREAM = r'''
var METHOD = __METHOD__;
var CHAT_PATH = __CHAT_PATH__;
var BODY = __BODY__;
var STREAM = __STREAM__;
var CREATE = __CREATE__;
var BASE_HEADERS = __BASE_HEADERS__;
var CONV_SLOT = "conversation_id";
var MAX_FRAMES = 20000;
var MAX_CHARS = 2000000;

/** Split a stream body into frames: { event, json, raw } per data: frame (or per ndjson line). */
function framesOf(raw) {
  var out = [];
  var lines = String(raw || "").split("\n");
  var i, line;
  if (STREAM.format === "ndjson") {
    for (i = 0; i < lines.length; i++) {
      line = lines[i].trim();
      if (!line) continue;
      out.push({ event: "", json: parseJson(line), raw: line });
    }
    return out;
  }
  var ev = "";
  var data = [];
  for (i = 0; i <= lines.length; i++) {
    line = i < lines.length ? lines[i] : "";
    if (line.charAt(line.length - 1) === "\r") line = line.slice(0, -1);
    if (line === "") {
      if (data.length) {
        var txt = data.join("\n");
        out.push({ event: ev, json: parseJson(txt), raw: txt });
      }
      ev = "";
      data = [];
      continue;
    }
    if (line.charAt(0) === ":") continue;
    if (line.indexOf("event:") === 0) { ev = line.slice(6).trim(); continue; }
    if (line.indexOf("data:") === 0) {
      var d = line.slice(5);
      if (d.charAt(0) === " ") d = d.slice(1);
      data.push(d);
    }
  }
  return out;
}

function isDone(f) {
  var dw = STREAM.done_when;
  if (STREAM.done_events && STREAM.done_events.length && contains(STREAM.done_events, f.event)) return true;
  if (f.raw === "[DONE]" || f.raw === "DONE") return true;
  if (!dw) return false;
  if (dw.event) return f.event === dw.event;
  if (dw.contains) return f.raw.indexOf(dw.contains) >= 0;
  if (dw.path && f.json !== null) {
    var v = dotGet(f.json, dw.path);
    return v !== null && String(v) === String(dw.equals);
  }
  return false;
}

/** Reassemble the answer from the token frames; `done` is false when no terminal frame arrived. */
function reassemble(raw) {
  var fs = framesOf(raw);
  var text = "";
  var last = "";
  var done = false;
  var n = 0;
  for (var i = 0; i < fs.length && i < MAX_FRAMES && text.length < MAX_CHARS; i++) {
    var f = fs[i];
    n++;
    if (isDone(f)) { done = true; break; }
    var piece = "";
    if (STREAM.token_events && STREAM.token_events.length) {
      if (f.event && !contains(STREAM.token_events, f.event)) continue;
      piece = f.json === null ? f.raw : textAt(f.json, STREAM.text_path);
    } else if (f.json === null) {
      piece = f.raw;
    } else {
      var t = dotGet(f.json, STREAM.type_path);
      if (t === null && f.event && STREAM.token_types && STREAM.token_types.length) t = f.event;
      if (contains(STREAM.ignore_types, t)) continue;
      if (STREAM.token_types && STREAM.token_types.length && t !== null && !contains(STREAM.token_types, t)) continue;
      piece = textAt(f.json, STREAM.text_path);
    }
    if (piece) { text += piece; last = piece; }
  }
  return { text: STREAM.aggregate === "last" ? last : text, done: done, frames: n };
}

/** Open the conversation the stream belongs to, when the contract has a create step. */
function mintConversation(turn, host, timeoutMs, prompt, out) {
  var id = CREATE.id_mode === "client" ? "abv2-" + host.uuid().split("-").join("") : "";
  var vars = { PROMPT: prompt, CONV: id, UUID: host.uuid(), USER_NAME: "ascend" };
  var opts = { method: CREATE.method || "POST", headers: headersOf(turn, BASE_CREATE_HEADERS), timeoutMs: timeoutMs };
  if (CREATE.body !== null) opts.body = render(CREATE.body, vars);
  var res;
  try {
    res = host.http.request(absoluteUrl(host, CREATE.url), opts);
  } catch (e) {
    out.status = 0;
    out.error = errorText(e);
    return null;
  }
  out.status = res.status;
  if (res.status >= 400) { out.error = preview(res.body); return null; }
  if (CREATE.id_mode === "client") return id;
  var parsed = parseJson(res.body);
  var found = parsed === null ? null : dotGet(parsed, CREATE.id_path || "id");
  if (found === null || typeof found === "undefined" || found === "") {
    out.error = "no id at " + (CREATE.id_path || "id") + " in " + preview(res.body);
    return null;
  }
  return String(found);
}
var BASE_CREATE_HEADERS = { "Content-Type": "application/json", "Accept": "application/json" };

/**
 * @param {Turn} turn
 * @param {Host} host
 * @returns {import("./host").Reply}
 */
function sendTurn(turn, host) {
  var timeoutMs = timeoutOf(turn, 60000);
  var prompt = promptOf(turn);
  var conv = "";
  if (CREATE) {
    var out = { status: 0, error: "" };
    if (CREATE.per_prompt) {
      conv = mintConversation(turn, host, timeoutMs, prompt, out);
    } else {
      conv = host.state.getOrMint(CONV_SLOT, { ttlMs: 3600000, waitMs: 10000 }, function () {
        return mintConversation(turn, host, timeoutMs, prompt, out);
      });
    }
    if (!conv) {
      return failure(targetStatus(out.status), "could not open a conversation", out.error);
    }
  }
  var vars = { PROMPT: prompt, CONV: conv, USER_NAME: "ascend" };
  var res;
  try {
    res = host.http.request(targetUrl(host, CHAT_PATH, vars), {
      method: METHOD,
      headers: headersOf(turn, BASE_HEADERS),
      body: render(BODY, vars),
      timeoutMs: timeoutMs,
      partialOnTimeout: true,
    });
  } catch (e) {
    return failure(502, "target unreachable", errorText(e));
  }
  if (res.status >= 400) {
    return failure(targetStatus(res.status), "target returned " + res.status, res.body);
  }
  var got = reassemble(res.body);
  if (!got.text) {
    return failure(502, "no text frames in the stream", "frames=" + got.frames + " " + preview(res.body));
  }
  if (!got.done) host.log("warn", "stream ended without a terminal frame", { frames: got.frames });
  host.log("info", "stream turn complete", { frames: got.frames, chars: got.text.length, done: got.done });
  return reply(got.text.trim(), { frames: got.frames, done: got.done });
}
'''

_WEBSOCKET = r'''
var SEND = __SEND__;
var INIT_MESSAGES = __INIT_MESSAGES__;
var RESPONSE_PATH = __RESPONSE_PATH__;
var DONE_WHEN = __DONE_WHEN__;
var IDLE_MS = __IDLE_MS__;
var AGGREGATE = __AGGREGATE__;
var MAX_FRAMES = 5000;
var MAX_CHARS = 4000000;
var FRAME_KEYS = ["text", "content", "message", "delta", "token", "answer", "output"];

/** The socket: the application's URL when it is one, else the `_adaptor_ws_url` parameter. */
function socketUrl(turn, host) {
  var params = turn.params || {};
  var url = String(host.config.endpoint() || "");
  if (url.indexOf("ws") !== 0 && params.ws_url) url = String(params.ws_url);
  return url;
}

/** Handshake headers: the application's, minus the body ones a socket has no use for. */
function socketHeaders(turn) {
  var h = {};
  var th = turn.headers || {};
  for (var k in th) {
    var low = k.toLowerCase();
    if (low === "content-type" || low === "accept" || low === "content-length") continue;
    h[k] = th[k];
  }
  return h;
}

function pieceOf(frame) {
  if (typeof frame === "string") return frame;
  if (RESPONSE_PATH) return textAt(frame, RESPONSE_PATH);
  if (frame !== null && typeof frame === "object" && !isArray(frame)) {
    for (var i = 0; i < FRAME_KEYS.length; i++) {
      var v = frame[FRAME_KEYS[i]];
      if (typeof v === "string") return v;
      if (v !== null && typeof v === "object") {
        for (var j = 0; j < 3; j++) {
          var kk = ["text", "content", "value"][j];
          if (typeof v[kk] === "string") return v[kk];
        }
      }
    }
  }
  return "";
}

function frameDone(frame) {
  if (!DONE_WHEN) return false;
  if (DONE_WHEN.contains) return JSON.stringify(frame).indexOf(DONE_WHEN.contains) >= 0;
  if (DONE_WHEN.path) {
    var v = dotGet(frame, DONE_WHEN.path);
    return v !== null && String(v) === String(DONE_WHEN.equals);
  }
  return false;
}

/**
 * Opening the socket proves the address and the credential without starting a conversation.
 * @param {Turn} turn
 * @param {Host} host
 * @returns {import("./host").Reply}
 */
function checkReachability(turn, host) {
  var sock;
  try {
    sock = host.ws.connect(socketUrl(turn, host), { headers: socketHeaders(turn), recvTimeoutMs: 5000 });
  } catch (e) {
    return failure(502, "socket connect failed", errorText(e));
  }
  sock.close();
  return { status_code: 200, body: { ok: true } };
}

/**
 * @param {Turn} turn
 * @param {Host} host
 * @returns {import("./host").Reply}
 */
function sendTurn(turn, host) {
  var timeoutMs = timeoutOf(turn, 30000);
  var prompt = promptOf(turn);
  var vars = { PROMPT: prompt, USER_NAME: "ascend" };
  var sock;
  try {
    sock = host.ws.connect(socketUrl(turn, host), { headers: socketHeaders(turn), recvTimeoutMs: timeoutMs });
  } catch (e) {
    return failure(502, "socket connect failed", errorText(e));
  }
  // A reused socket already completed its handshake: replaying it would open a second session.
  if (!sock.reused) {
    for (var i = 0; i < INIT_MESSAGES.length; i++) sock.send(render(INIT_MESSAGES[i], vars));
  }
  sock.send(render(SEND, vars));

  var text = "";
  var last = "";
  var frames = 0;
  var ended = "";
  while (frames < MAX_FRAMES && text.length < MAX_CHARS) {
    // The first frame may take the target's whole thinking time; after that an idle gap ends the
    // turn when the contract has no terminal frame.
    var f = sock.recv({ timeoutMs: DONE_WHEN || !text ? timeoutMs : IDLE_MS });
    frames += 1;
    if (f.type === "text") {
      var frame = f.json !== null ? f.json : String(f.raw || "");
      var piece = pieceOf(frame);
      if (piece) { text += piece; last = piece; }
      if (frameDone(frame)) { ended = "done"; break; }
      continue;
    }
    if (f.type === "timeout" && text && !DONE_WHEN) { ended = "idle"; break; }
    ended = f.type + (f.detail ? ":" + String(f.detail).slice(0, 120) : "");
    break;
  }
  sock.close();
  var answer = AGGREGATE === "last" ? last : text;
  if (!answer) {
    return failure(502, "no reply text before the socket " + (ended || "went quiet"), "frames=" + frames);
  }
  host.log("info", "socket turn complete", { frames: frames, chars: answer.length, ended: ended });
  return reply(answer.trim(), { frames: frames, ended: ended });
}
'''

_SESSION_API = r'''
var SESSION_ENDPOINT = __SESSION_ENDPOINT__;
var SESSION_METHOD = __SESSION_METHOD__;
var SESSION_BODY = __SESSION_BODY__;
var SESSION_EXTRACT = __SESSION_EXTRACT__;
var SESSION_VARIABLE = __SESSION_VARIABLE__;
var SESSION_HEADER = __SESSION_HEADER__;
var SESSION_HEADER_VALUE = __SESSION_HEADER_VALUE__;
var MESSAGE_PATH = __MESSAGE_PATH__;
var MESSAGE_METHOD = __MESSAGE_METHOD__;
var MESSAGE_BODY = __MESSAGE_BODY__;
var RESPONSE_PATH = __RESPONSE_PATH__;
var WARMUP = __WARMUP__;
var BASE_HEADERS = __BASE_HEADERS__;
var SESSION_SLOT = "session_id";
var SESSION_TTL_MS = 3600000;

function sessionVars(prompt, id) {
  var vars = { PROMPT: prompt, UUID: "", USER_NAME: "ascend" };
  vars[SESSION_VARIABLE] = id;
  return vars;
}

/** Create a session; the id string, or null with the status and detail in `out`. */
function mintSession(turn, host, timeoutMs, out) {
  var vars = { UUID: host.uuid(), USER_NAME: "ascend" };
  var opts = { method: SESSION_METHOD, headers: headersOf(turn, BASE_HEADERS), timeoutMs: timeoutMs };
  if (SESSION_BODY !== null) opts.body = render(SESSION_BODY, vars);
  var res;
  try {
    res = host.http.request(absoluteUrl(host, SESSION_ENDPOINT), opts);
  } catch (e) {
    out.status = 0;
    out.error = errorText(e);
    return null;
  }
  out.status = res.status;
  if (res.status >= 400) { out.error = preview(res.body); return null; }
  var parsed = parseJson(res.body);
  var found = parsed === null ? null : dotGet(parsed, SESSION_EXTRACT);
  if (found === null || typeof found === "undefined" || found === "") {
    out.error = "no session id at " + SESSION_EXTRACT + " in " + preview(res.body);
    return null;
  }
  var id = String(found);
  host.log("info", "session created");
  if (WARMUP) {
    // A throwaway first turn: this target greets or asks consent before it answers anything.
    try {
      host.http.request(messageUrl(host, id), {
        method: MESSAGE_METHOD, headers: messageHeaders(turn, id),
        body: render(MESSAGE_BODY, sessionVars(WARMUP, id)), timeoutMs: timeoutMs,
      });
    } catch (e) {
      host.log("warn", "warm-up turn failed", { error: errorText(e) });
    }
  }
  return id;
}

function messageUrl(host, id) {
  var vars = {};
  vars[SESSION_VARIABLE] = id;
  var url = targetUrl(host, MESSAGE_PATH, vars);
  return url.split("{{" + SESSION_VARIABLE + "}}").join(id);
}

/** The message call's headers: the app's, plus the minted value under SESSION_HEADER when the
 *  target expects it there (`x-conv-token`, a per-conversation bearer) rather than in the URL
 *  or body. The mint call never carries it: there is nothing to carry yet. */
function messageHeaders(turn, id) {
  var h = headersOf(turn, BASE_HEADERS);
  if (SESSION_HEADER) {
    h[SESSION_HEADER] = String(SESSION_HEADER_VALUE).split("{{" + SESSION_VARIABLE + "}}").join(id);
  }
  return h;
}

/**
 * A session mint proves the credential and the host without a scored conversation.
 * @param {Turn} turn
 * @param {Host} host
 * @returns {import("./host").Reply}
 */
function checkReachability(turn, host) {
  var out = { status: 0, error: "" };
  var id = mintSession(turn, host, 15000, out);
  if (out.status === 401 || out.status === 403) {
    return { status_code: out.status, body: { ok: false, status: out.status } };
  }
  return { status_code: id ? 200 : 502, body: { ok: !!id, status: out.status, error: out.error } };
}

function sendMessage(turn, host, id, prompt, timeoutMs) {
  return host.http.request(messageUrl(host, id), {
    method: MESSAGE_METHOD,
    headers: messageHeaders(turn, id),
    body: render(MESSAGE_BODY, sessionVars(prompt, id)),
    timeoutMs: timeoutMs,
  });
}

/**
 * @param {Turn} turn
 * @param {Host} host
 * @returns {import("./host").Reply}
 */
function sendTurn(turn, host) {
  var timeoutMs = timeoutOf(turn, 60000);
  var prompt = promptOf(turn);
  var out = { status: 0, error: "" };
  var id = host.state.getOrMint(SESSION_SLOT, { ttlMs: SESSION_TTL_MS, waitMs: 10000 }, function () {
    return mintSession(turn, host, timeoutMs, out);
  });
  if (!id) return failure(targetStatus(out.status), "could not create a session", out.error);
  var res;
  try {
    res = sendMessage(turn, host, id, prompt, timeoutMs);
  } catch (e) {
    return failure(502, "target unreachable", errorText(e));
  }
  if (res.status === 401) {
    // The session we held is dead: drop it, mint once, retry once. A 401 straight after a fresh
    // mint is the credential failing, and is returned as such.
    host.state.set(SESSION_SLOT, null);
    out = { status: 0, error: "" };
    id = mintSession(turn, host, timeoutMs, out);
    if (!id) return failure(targetStatus(out.status) === 403 ? 403 : 401, "re-creating the session failed", out.error);
    host.state.set(SESSION_SLOT, id, { ttlMs: SESSION_TTL_MS });
    try {
      res = sendMessage(turn, host, id, prompt, timeoutMs);
    } catch (e) {
      return failure(502, "target unreachable", errorText(e));
    }
  }
  if (res.status >= 400) {
    return failure(targetStatus(res.status), "target returned " + res.status, res.body);
  }
  var parsed = parseJson(res.body);
  if (parsed === null) return failure(502, "target did not return JSON", res.body);
  var text = textAt(parsed, RESPONSE_PATH);
  if (!text) {
    return failure(502, "no reply text at " + RESPONSE_PATH,
                   typeof parsed === "object" ? Object.keys(parsed).join(",") : res.body);
  }
  host.log("info", "session turn complete", { chars: text.length });
  return reply(text.trim(), { status: res.status });
}
'''

_SESSION_POLL = r'''
var BOOTSTRAP = __BOOTSTRAP__;
var CREATE = __CREATE__;
var SEND_METHOD = __SEND_METHOD__;
var SEND_PATH = __SEND_PATH__;
var SEND_BODY = __SEND_BODY__;
var POLL = __POLL__;
var BASE_HEADERS = __BASE_HEADERS__;
var CONV_SLOT = "conversation_id";
var MAX_POLLS = 600;

function stepHeaders(turn, step) {
  var h = headersOf(turn, BASE_HEADERS);
  var extra = step && step.headers ? step.headers : {};
  for (var k in extra) h[k] = extra[k];
  return h;
}

/** Bootstrap, then create the conversation; its id, or null with the status in `out`. */
function mintConversation(turn, host, timeoutMs, prompt, out) {
  var vars = { PROMPT: prompt, CONV: "", UUID: host.uuid(), USER_NAME: "ascend" };
  for (var i = 0; i < BOOTSTRAP.length; i++) {
    var step = BOOTSTRAP[i];
    var sopts = { method: step.method || "POST", headers: stepHeaders(turn, step), timeoutMs: timeoutMs };
    if (step.body !== null && typeof step.body !== "undefined") sopts.body = render(step.body, vars);
    try {
      host.http.request(absoluteUrl(host, step.url), sopts);
    } catch (e) {
      if (step.required !== false) { out.status = 0; out.error = "bootstrap step " + i + " failed: " + errorText(e); return null; }
    }
  }
  var opts = { method: CREATE.method || "POST", headers: stepHeaders(turn, CREATE), timeoutMs: timeoutMs };
  if (CREATE.body !== null && typeof CREATE.body !== "undefined") opts.body = render(CREATE.body, vars);
  var res;
  try {
    res = host.http.request(absoluteUrl(host, CREATE.url), opts);
  } catch (e) {
    out.status = 0;
    out.error = errorText(e);
    return null;
  }
  out.status = res.status;
  if (res.status >= 400) { out.error = preview(res.body); return null; }
  var parsed = parseJson(res.body);
  var found = parsed === null ? null : dotGet(parsed, CREATE.extract || "conversation_id");
  if (found === null || typeof found === "undefined" || found === "") {
    out.error = "no conversation id at " + (CREATE.extract || "conversation_id") + " in " + preview(res.body);
    return null;
  }
  return String(found);
}

/** The bot's turns in the transcript so far, oldest first. */
function botTurns(turn, host, conv, timeoutMs) {
  var vars = { CONV: conv, UUID: host.uuid(), USER_NAME: "ascend" };
  var opts = { method: POLL.method || "GET", headers: stepHeaders(turn, POLL), timeoutMs: timeoutMs };
  if (POLL.body !== null && typeof POLL.body !== "undefined") opts.body = render(POLL.body, vars);
  var res;
  try {
    res = host.http.request(absoluteUrl(host, String(POLL.url).split("{{CONV}}").join(conv)), opts);
  } catch (e) {
    return [];
  }
  if (res.status >= 400) return [];
  var parsed = parseJson(res.body);
  var arr = parsed === null ? null : dotGet(parsed, POLL.list_path || "messages");
  if (!isArray(arr)) return [];
  var out = [];
  for (var i = 0; i < arr.length; i++) {
    var t = arr[i];
    if (t === null || typeof t !== "object") continue;
    var role = String(t[POLL.role_field || "role"] || "").toLowerCase();
    if (!contains(POLL.bot_roles, role)) continue;
    var text = textAt(t, POLL.text_path || "text");
    if (text) out.push(text);
  }
  return out;
}

/**
 * Opening a conversation proves the credential and the host without a scored turn.
 * @param {Turn} turn
 * @param {Host} host
 * @returns {import("./host").Reply}
 */
function checkReachability(turn, host) {
  var out = { status: 0, error: "" };
  var conv = mintConversation(turn, host, 15000, "", out);
  if (out.status === 401 || out.status === 403) {
    return { status_code: out.status, body: { ok: false, status: out.status } };
  }
  return { status_code: conv ? 200 : 502, body: { ok: !!conv, status: out.status, error: out.error } };
}

/**
 * @param {Turn} turn
 * @param {Host} host
 * @returns {import("./host").Reply}
 */
function sendTurn(turn, host) {
  var timeoutMs = timeoutOf(turn, 30000);
  var prompt = promptOf(turn);
  var out = { status: 0, error: "" };
  var conv = host.state.getOrMint(CONV_SLOT, { ttlMs: 3600000, waitMs: 10000 }, function () {
    return mintConversation(turn, host, timeoutMs, prompt, out);
  });
  if (!conv) return failure(targetStatus(out.status), "could not open a conversation", out.error);

  // Watermark: only a bot turn newer than these is this prompt's answer.
  var baseline = botTurns(turn, host, conv, timeoutMs).length;
  var vars = { PROMPT: prompt, CONV: conv, UUID: host.uuid(), USER_NAME: "ascend" };
  var res;
  try {
    res = host.http.request(targetUrl(host, SEND_PATH, vars), {
      method: SEND_METHOD, headers: stepHeaders(turn, null), body: render(SEND_BODY, vars), timeoutMs: timeoutMs,
    });
  } catch (e) {
    return failure(502, "target unreachable", errorText(e));
  }
  if (res.status >= 400) {
    return failure(targetStatus(res.status), "send returned " + res.status, res.body);
  }

  var interval = Number(POLL.interval_ms) || 1000;
  var deadline = host.now() + (Number(POLL.timeout_ms) || 60000);
  var stability = Number(POLL.stability_ms) || 0;
  var lastText = "";
  var lastChange = 0;
  var polls = 0;
  while (host.now() < deadline && polls < MAX_POLLS) {
    host.sleep(interval);
    polls += 1;
    var turns = botTurns(turn, host, conv, timeoutMs);
    if (turns.length <= baseline) continue;
    var text = turns[turns.length - 1];
    if (text !== lastText) { lastText = text; lastChange = host.now(); }
    if (stability <= 0 || host.now() - lastChange >= stability) {
      host.log("info", "poll turn complete", { polls: polls, chars: text.length });
      return reply(String(text).trim(), { polls: polls });
    }
  }
  if (lastText) return reply(String(lastText).trim(), { polls: polls, note: "returned on timeout" });
  return failure(502, "no bot turn appeared in the transcript", "polls=" + polls);
}
'''


def _header(shape: str, url: str, statement: str, note: str = "") -> str:
    lines = [
        "// @ts-check",
        "// Generated by `ascend target add` from the contract it derived and proved for this target.",
        "// The hosted ADAPTOR: the Ascend engine runs it in an isolate, one turn per call, so nothing",
        "// runs on an operator's machine during the assessment. Edit it like any adaptor and re-prove",
        "// it with `ascend adaptor gate | test | store | verify` (docs/CUSTOM_ADAPTOR.md).",
        "//",
        f"//   shape   {shape}",
        f"//   target  {url}  (the application's URL: read from host.config.endpoint(), never a literal here)",
        f"//   reply   {statement}",
    ]
    if note:
        lines += ["//", f"//   {note}"]
    return "\n".join(lines) + "\n"


def _fill(template: str, values: Dict[str, str]) -> str:
    out = template
    for k, v in values.items():
        out = out.replace(f"__{k}__", v)
    return out


def _base_headers(body: Any, accept: str) -> Dict[str, str]:
    ct = "text/plain" if isinstance(body, str) else "application/json"
    return {"Content-Type": ct, "Accept": accept}


def _common(cfg: Dict[str, Any], rt: Dict[str, Any]) -> str:
    body = body_template(cfg)
    return _fill(_COMMON, {
        "PROMPT_PATH": _js(prompt_path(body) if shape_of(cfg) == "direct_api" else prompt_path(request_template(cfg))),
        "PROMPT_FALLBACK": _js(PROMPT_FALLBACK),
        "REPLY_BODY": reply_body_js(rt),
    })


def _gen_direct_api(cfg: Dict[str, Any]) -> str:
    body = body_template(cfg)
    carry = cfg.get("carry") if isinstance(cfg.get("carry"), dict) else None
    return _fill(_DIRECT_API, {
        "METHOD": _js(str(cfg.get("method") or "POST").upper()),
        "BODY": _js(body),
        "RESPONSE_PATH": _js(str(cfg.get("response_path") or "")),
        "STOP_MARKER": _js(cfg.get("stop_marker") or None),
        "CARRY": _js({"reply_path": carry.get("reply_path"), "request_field": carry.get("request_field")}
                     if carry else None),
        "BASE_HEADERS": _js(_base_headers(body, "application/json")),
    })


def _gen_sse_stream(cfg: Dict[str, Any]) -> str:
    body = body_template(cfg)
    stream = dict(cfg.get("stream") or {})
    fmt = str(stream.get("format") or "sse").lower()
    js_stream = {
        "format": "ndjson" if fmt == "ndjson" else "sse",
        "text_path": stream.get("text_path") or "content",
        "type_path": stream.get("type_path") or "type",
        "token_types": list(stream.get("token_types") or []),
        "ignore_types": list(stream.get("ignore_types") or ["status", "ping", "keepalive"]),
        "done_when": stream.get("done_when") if isinstance(stream.get("done_when"), dict) else None,
        "token_events": list(stream.get("token_events") or []),
        "done_events": list(stream.get("done_events") or []),
        "aggregate": stream.get("aggregate") or "concat",
    }
    create = cfg.get("create") if isinstance(cfg.get("create"), dict) and (cfg.get("create") or {}).get("url") else None
    js_create = None
    if create:
        js_create = {"url": create.get("url"), "method": str(create.get("method") or "POST").upper(),
                     "body": create.get("body") if create.get("body") is not None else None,
                     "id_path": create.get("id_path") or "id",
                     "id_mode": create.get("id_mode") or "server",
                     "per_prompt": bool(create.get("per_prompt"))}
    return _fill(_SSE_STREAM, {
        "METHOD": _js(str(cfg.get("method") or "POST").upper()),
        "CHAT_PATH": _js(path_template(cfg)),
        "BODY": _js(body),
        "STREAM": _js(js_stream),
        "CREATE": _js(js_create),
        "BASE_HEADERS": _js(_base_headers(body, "text/event-stream" if fmt != "ndjson" else "application/x-ndjson")),
    })


def _gen_websocket(cfg: Dict[str, Any]) -> str:
    done = cfg.get("done_when") if isinstance(cfg.get("done_when"), dict) else None
    return _fill(_WEBSOCKET, {
        "SEND": _js(body_template(cfg)),
        "INIT_MESSAGES": _js(list(cfg.get("init_messages") or [])),
        "RESPONSE_PATH": _js(str(cfg.get("response_path") or "")),
        "DONE_WHEN": _js(done),
        "IDLE_MS": _js(int(cfg.get("idle_ms") or 1500)),
        "AGGREGATE": _js(cfg.get("aggregate") or "concat"),
    })


def _gen_session_api(cfg: Dict[str, Any]) -> str:
    body = body_template(cfg)
    warm = cfg.get("warmup_message") or cfg.get("warmup") or cfg.get("session_greeting") or None
    return _fill(_SESSION_API, {
        "SESSION_ENDPOINT": _js(str(cfg.get("session_endpoint") or "")),
        "SESSION_METHOD": _js(str(cfg.get("session_method") or "POST").upper()),
        "SESSION_BODY": _js(cfg.get("session_body") if cfg.get("session_body") is not None else {}),
        "SESSION_EXTRACT": _js(str(cfg.get("session_extract") or "sessionId")),
        "SESSION_VARIABLE": _js(str(cfg.get("session_variable") or "SESSION_ID")),
        "SESSION_HEADER": _js(str(cfg["session_header"]) if cfg.get("session_header") else None),
        "SESSION_HEADER_VALUE": _js(str(cfg.get("session_header_value") or "{{SESSION_ID}}")),
        "MESSAGE_PATH": _js(path_template(cfg)),
        "MESSAGE_METHOD": _js(str(cfg.get("message_method") or "POST").upper()),
        "MESSAGE_BODY": _js(body),
        "RESPONSE_PATH": _js(str(cfg.get("response_path") or "messages.0.message")),
        "WARMUP": _js(str(warm) if warm else None),
        "BASE_HEADERS": _js(_base_headers(body, "application/json")),
    })


def _gen_session_poll(cfg: Dict[str, Any]) -> str:
    create = dict(cfg.get("create") or {})
    send = dict(cfg.get("send") or {})
    poll = dict(cfg.get("poll") or {})
    body = body_template(cfg)
    js_poll = {
        "url": poll.get("url") or "", "method": str(poll.get("method") or "GET").upper(),
        "headers": poll.get("headers") or {}, "body": poll.get("body"),
        "list_path": poll.get("list_path") or "messages", "role_field": poll.get("role_field") or "role",
        "bot_roles": [str(r).lower() for r in (poll.get("bot_roles") or ["assistant", "bot", "agent", "ai"])],
        "text_path": poll.get("text_path") or "text",
        "interval_ms": int(poll.get("interval_ms") or 1000),
        "timeout_ms": int(poll.get("timeout_ms") or 60000),
        "stability_ms": int(poll.get("stability_ms") or 0),
    }
    js_create = {"url": create.get("url") or "", "method": str(create.get("method") or "POST").upper(),
                 "headers": create.get("headers") or {}, "body": create.get("body") if create.get("body") is not None else {},
                 "extract": create.get("extract") or "conversation_id"}
    steps = [{"url": s.get("url") or "", "method": str(s.get("method") or "POST").upper(),
              "headers": s.get("headers") or {}, "body": s.get("body"),
              "required": s.get("required", True)} for s in (cfg.get("bootstrap") or []) if isinstance(s, dict)]
    return _fill(_SESSION_POLL, {
        "BOOTSTRAP": _js(steps),
        "CREATE": _js(js_create),
        "SEND_METHOD": _js(str(send.get("method") or "POST").upper()),
        "SEND_PATH": _js(path_template(cfg)),
        "SEND_BODY": _js(body),
        "POLL": _js(js_poll),
        "BASE_HEADERS": _js(_base_headers(body, "application/json")),
    })


def _adaptor_rules():
    """runtime/adaptor.py, whichever way this package was imported (flat `runtime/` on the path in
    the CLI and the tests; the package form elsewhere)."""
    try:
        import adaptor as AD  # noqa: PLC0415
    except ImportError:  # pragma: no cover - the package form
        from runtime import adaptor as AD  # noqa: PLC0415
    return AD


def unfinished_why(cfg: Dict[str, Any]) -> Optional[str]:
    """Why a config gets the scaffold rather than a finished adaptor, in one line; None when a
    generator covers it. The handshake comes first: a target that logs in is unfinished for that
    reason even when its transport has a generator."""
    kind = handshake_kind(cfg)
    if kind:
        return (f"no generated adaptor runs the {kind!r} handshake this target authenticates with: "
                f"the file is the onboarding scaffold with the login named in its header")
    if transport_shape(cfg) == SCAFFOLD:
        return f"no generator covers the {str((cfg or {}).get('adapter'))!r} adapter"
    return None


def _gen_scaffold(cfg: Dict[str, Any]) -> str:
    """Everything else: the shipped onboarding scaffold, with the captured request described so a
    person (or an agent) can finish `sendTurn`. Header names and body KEYS only — never a value."""
    src = _adaptor_rules().template_js("scaffold")
    body = body_template(cfg)
    keys = sorted(body.keys()) if isinstance(body, dict) else ["(text body)"]
    header_names = sorted((cfg.get("headers") or {}).keys())
    kind = handshake_kind(cfg)
    if kind:
        first_line = (f"// UNFINISHED: this target authenticates with a '{kind}' handshake, which no "
                      f"generated adaptor runs yet.")
    else:
        first_line = f"// UNFINISHED: the derived adapter is '{cfg.get('adapter')}', which no generator covers yet."
    lines = [
        first_line,
        "// What the capture showed, to finish sendTurn() from (docs/CUSTOM_ADAPTOR.md has the loop):",
        f"//   method   {str(cfg.get('method') or 'POST').upper()}",
        f"//   body     keys {', '.join(keys)}  (the prompt rides in {'.'.join(prompt_path(body)) or 'the body'})",
        f"//   headers  {', '.join(header_names) or NO_EXTRA_HEADERS}",
    ]
    if kind:
        lines.append(f"//   auth     {kind}: run the login in sendTurn() (host.state.getOrMint keeps the "
                     f"token per conversation; on a 401 drop it, mint again, retry once)")
    lines.append("//   next     ascend adaptor test <this file> --app '<app>'   then   ascend adaptor store")
    note = "\n".join(lines)
    first, rest = src.split("\n", 1) if "\n" in src else (src, "")
    return f"{first}\n{note}\n{rest}"


_GENERATORS = {
    "direct_api": _gen_direct_api,
    "sse_stream": _gen_sse_stream,
    "websocket_direct": _gen_websocket,
    "session_api": _gen_session_api,
    "session_poll": _gen_session_poll,
}


def generate_adaptor(config: Dict[str, Any]) -> str:
    """The adaptor source for a derived config: one file, one exported `sendTurn`. On a tunnel
    app every second host is spelled as its tunnel name first (route_second_hosts), so the file
    dials what the engine can reach."""
    cfg, _notes = route_second_hosts(dict(config or {}))
    shape = shape_of(cfg)
    rt = response_template(cfg)
    statement = reply_statement(rt)
    if shape == SCAFFOLD:
        return _gen_scaffold(cfg)
    note = ""
    if extra_domains(cfg):
        note = f"domains  {', '.join(extra_domains(cfg))}  (listed in the application's _adaptor_domains)"
    return (_header(shape, app_url(cfg), statement, note)
            + _common(cfg, rt)
            + _GENERATORS[shape](cfg))


def plan(config: Dict[str, Any]) -> Dict[str, Any]:
    """Everything the CLI needs to register the adaptor app, computed once and consistently:
    the shape, the address, both templates, the extra domains (and what to tell the operator
    about each on a tunnel app), the parameters, the source, and whether the file is finished —
    with the reason in words when it is not."""
    cfg, domain_notes = route_second_hosts(dict(config or {}))
    rt = response_template(cfg)
    return {
        "shape": shape_of(cfg),
        "url": app_url(cfg),
        "raw_url": raw_url(cfg),
        "request_template": request_template(cfg),
        "response_template": rt,
        "reply_statement": reply_statement(rt),
        "domains": extra_domains(cfg),
        "domain_notes": domain_notes,
        "params": adaptor_params(cfg),
        "source": generate_adaptor(cfg),
        "finished": shape_of(cfg) != SCAFFOLD,
        "unfinished_why": unfinished_why(cfg),
    }


__all__ = ["SHAPES", "SCAFFOLD", "PROMPT_TOKEN", "DYNAMIC_AUTH_KINDS", "handshake_kind",
           "transport_shape", "shape_of", "raw_url", "app_url", "path_template", "body_template",
           "prompt_path", "request_template", "response_template", "reply_body_js", "routed_app",
           "tunnel_url", "route_second_hosts", "extra_domains", "adaptor_params", "unfinished_why",
           "generate_adaptor", "plan"]
