"""
codegen.py — turn a discovered contract into a per-app ADAPTER, as code.

Ascend -> bridge -> adapter -> target.  Every target gets its own adapter. For the common request patterns
we generate a small, self-contained Python module (stdlib + requests) that a person can read and
edit; for a target that fits none of them we still emit that module as a scaffold with the real
captured request in it, so a human (or a coding agent) finishes `send_prompt`.

The generated module implements one function:

    def send_prompt(prompt: str) -> str

which is exactly what runtime/adapters/custom_module.py runs. So a bespoke adapter and a built-in
one reach the bridge through the same path. Nothing generated is trusted until it answers the live
target (the hard gate in discovery/validate.py).
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, Optional

PROMPT_TOKEN = "{{PROMPT}}"


def _py(obj: Any) -> str:
    """A PYTHON literal for a JSON-ish value, stably formatted for a readable module.

    `json.dumps` was used here and it is not Python: a `true`, `false` or `null` anywhere in a
    config (verify_tls, a done rule's `equals`, an unset subprotocol) became a NameError the moment
    the generated file ran. MEASURED 2026-10-02 against the Target Lab: all four modules died on
    line 21-68 before sending anything. pprint writes True/False/None and quotes strings."""
    import pprint
    return pprint.pformat(obj, indent=4, width=100, sort_dicts=False)


def _body_fn(body: Any) -> str:
    """Render a _body(prompt) that rebuilds the request body with the prompt substituted.

    The captured body carries the {{PROMPT}} token where the prompt goes. We emit the body as a
    literal and replace the token at call time, so the operator sees the exact shape the app wants.
    """
    if isinstance(body, str):
        lit = _py(body)
        return (f"def _body(prompt):\n"
                f"    return {lit}.replace({_py(PROMPT_TOKEN)}, prompt)\n")
    # dict/other: JSON-encode, token-replace in the encoded string, decode back — this substitutes
    # the prompt no matter how deeply nested the field is, without walking the structure.
    lit = _py(body if body is not None else {"message": PROMPT_TOKEN})
    return (f"_BODY_TEMPLATE = {lit}\n\n\n"
            f"def _body(prompt):\n"
            f"    raw = json.dumps(_BODY_TEMPLATE)\n"
            f"    raw = raw.replace({_py(PROMPT_TOKEN)}, json.dumps(prompt)[1:-1])\n"
            f"    return json.loads(raw)\n")


def _extract_fn_direct(response_path: Optional[str]) -> str:
    if not response_path:
        return ("def _extract(data, raw_text):\n"
                "    # no response_path was pinned: fall back to the whole body\n"
                "    if isinstance(data, str):\n"
                "        return data\n"
                "    return raw_text\n")
    parts = response_path.split(".")
    return (f"_RESPONSE_PATH = {_py(parts)}\n\n\n"
            "def _extract(data, raw_text):\n"
            "    cur = data\n"
            "    for key in _RESPONSE_PATH:\n"
            "        if isinstance(cur, list):\n"
            "            try:\n"
            "                cur = cur[int(key)]\n"
            "            except (ValueError, IndexError):\n"
            "                return raw_text\n"
            "        elif isinstance(cur, dict) and key in cur:\n"
            "            cur = cur[key]\n"
            "        else:\n"
            "            return raw_text\n"
            "    return cur if isinstance(cur, str) else json.dumps(cur)\n")


SECRET_HEADERS = {"authorization", "cookie", "x-api-key", "api-key", "x-auth-token", "x-access-token", "x-csrf-token",
                  "x-xsrf-token", "proxy-authorization", "x-amz-security-token", "x-lab-code"}
NOISE_HEADERS = {"content-length", "host", "connection", "accept-encoding"}


def safe_headers(headers: Dict[str, Any]) -> tuple[Dict[str, Any], list[str]]:
    """The headers a generated module may carry, and the environment names it will expect.

    MEASURED 2026-10-02 on a Target Lab capture: the Referer header held the access code in its
    query string, so a module generated from the raw config carried the credential it was meant to
    keep out. So: query strings are cut from Referer and Origin; browser fingerprint headers are
    dropped; a credential header whose value is a literal (not an env: reference) is replaced by
    `env:ASCEND_SECRET_<HEADER>` and named, so the operator sets it instead of shipping it."""
    out: Dict[str, Any] = {}
    lifted: list[str] = []
    for k, v in (headers or {}).items():
        lk = str(k).lower()
        if lk.startswith(("sec-ch-ua", "sec-fetch-")) or lk in NOISE_HEADERS:
            continue
        if lk in ("referer", "origin") and isinstance(v, str) and "?" in v:
            v = v.split("?", 1)[0]
        if lk in SECRET_HEADERS and isinstance(v, str) and not v.startswith(("env:", "literal:")):
            name = "ASCEND_SECRET_" + "".join(ch if ch.isalnum() else "_" for ch in str(k).upper())
            v, lifted = f"env:{name}", lifted + [name]
        out[k] = v
    return out, lifted


def lift_query_credentials(url: str) -> tuple[str, list[Dict[str, Any]]]:
    """`url` without any credential-shaped query parameter, and the auth blocks that put each one back
    from the environment at run time. MEASURED 2026-10-02: a WebSocket config carried the Target Lab
    access code in `ws_url`'s query string, and the generated module embedded it. Uses the CLI's own
    classifier and secret naming, so the environment name is the one the credential store uses."""
    from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode
    if not isinstance(url, str) or "?" not in url:
        return url, []
    try:
        from runtime.discovery.classify import _looks_secret_param, secret_var_name
    except Exception:  # noqa: BLE001 - a fallback that errs on the side of lifting
        def _looks_secret_param(name, value):
            return name.lower() in {"code", "key", "token", "api_key", "apikey", "access_token", "sig", "signature", "secret", "auth"}
        def secret_var_name(u, header):
            host = urlsplit(u).netloc.upper()
            return "ASCEND_SECRET_" + "".join(ch if ch.isalnum() else "_" for ch in f"{host}_{header}".upper())
    parts = urlsplit(url)
    kept, blocks = [], []
    for name, value in parse_qsl(parts.query, keep_blank_values=True):
        if value.startswith("env:"):
            blocks.append({"type": "static", "mode": "api_key", "in": "query", "name": name, "value_ref": value})
        elif _looks_secret_param(name, value):
            blocks.append({"type": "static", "mode": "api_key", "in": "query", "name": name,
                           "value_ref": "env:" + secret_var_name(url, "query:" + name)})
        else:
            kept.append((name, value))
    return urlunsplit(parts._replace(query=urlencode(kept))), blocks


def _lift_urls(cfg: Dict[str, Any], keys: tuple) -> Dict[str, Any]:
    """A copy of `cfg` whose URL fields carry no credential, with the lifted ones added to `auth`."""
    out = dict(cfg)
    extra: list = []
    for k in keys:
        if isinstance(out.get(k), str):
            out[k], blocks = lift_query_credentials(out[k])
            extra += [b for b in blocks if b not in extra]
    if extra:
        auth = out.get("auth")
        auth = [auth] if isinstance(auth, dict) else list(auth or [])
        out["auth"] = auth + extra
    return out


def _header_block(headers: Dict[str, Any]) -> str:
    clean, lifted = safe_headers(headers)
    note = ("# set in the environment before running: " + ", ".join(lifted) + "\n") if lifted else ""
    return note + f"HEADERS = {_py(clean)}\n"


def _preamble(name: str, source: str, url: str, adapter_kind: str) -> str:
    return (
        f'"""Adapter for {name} — generated by `ascend adapter build` (from {source}).\n\n'
        f"Ascend -> bridge -> adapter (this file) -> your target.\n"
        f"This is the app's OWN adapter. Edit send_prompt() to handle anything the app needs;\n"
        f"re-prove it any time with:  ascend adapter validate --config {name}\n"
        f'"""\n'
        f"import json\n"
        f"import requests\n\n\n"
        f"META = {{\n"
        f"    \"target\": {_py(url)},\n"
        f"    \"kind\": {_py(adapter_kind)},\n"
        f"    \"generated_from\": {_py(source)},\n"
        f"}}\n\n\n"
    )



_COMMON_RUNTIME = r'''import os
import sys


def _env(value):
    """`env:NAME` -> the environment value; anything else is returned as written."""
    if isinstance(value, str) and value.startswith("env:"):
        name = value[4:]
        got = os.environ.get(name)
        if got is None or got == "":
            raise RuntimeError(f"set {name} in the environment: this adapter never embeds a secret")
        return got
    return value


def _secret(ref, allow_literal=False):
    """A secret REFERENCE, resolved the way the Ascend bridge resolves it: `env:NAME`, or
    {"value_ref": "env:NAME"}; `literal:TEXT` only where a non-secret constant is allowed."""
    if isinstance(ref, dict):
        ref = ref.get("value_ref", ref.get("value"))
    if isinstance(ref, str) and ref.startswith("literal:"):
        if not allow_literal:
            raise RuntimeError("literal: values are not allowed for secrets; use env:NAME")
        return ref[len("literal:"):]
    if not (isinstance(ref, str) and ref.startswith("env:")):
        raise RuntimeError(f"secret references must be env:NAME so no credential lives in this file, got {ref!r}")
    return _env(ref)


def _headers():
    return {k: _env(v) for k, v in HEADERS.items()}


def _with_query(url, params):
    from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode
    parts = urlsplit(url)
    kept = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k not in params]
    return urlunsplit(parts._replace(query=urlencode(kept + list(params.items()))))


_TOKENS = {}


def _oauth2_token(a):
    """An OAuth2 grant at the token endpoint: client_credentials, password or refresh."""
    import requests
    key = json.dumps(a, sort_keys=True)
    if key in _TOKENS:
        return _TOKENS[key]
    grant = a.get("grant", "client_credentials")
    if grant == "client_credentials":
        data = {"grant_type": "client_credentials", "client_id": _secret(a.get("client_id_ref"), True), "client_secret": _secret(a.get("client_secret_ref"))}
    elif grant == "password":
        data = {"grant_type": "password", "client_id": _secret(a.get("client_id_ref"), True), "username": _secret(a.get("username_ref"), True), "password": _secret(a.get("password_ref"))}
        if a.get("client_secret_ref"):
            data["client_secret"] = _secret(a["client_secret_ref"])
    elif grant == "refresh":
        data = {"grant_type": "refresh_token", "refresh_token": _secret(a.get("refresh_token_ref")), "client_id": _secret(a.get("client_id_ref"), True)}
        if a.get("client_secret_ref"):
            data["client_secret"] = _secret(a["client_secret_ref"])
    else:
        raise RuntimeError(f"unknown oauth2 grant {grant!r}")
    if a.get("scope"):
        data["scope"] = a["scope"]
    for k, v in (a.get("extra") or {}).items():
        data[k] = _secret(v, True) if isinstance(v, str) and v.startswith(("env:", "literal:")) else v
    r = requests.post(a["token_url"], data=data, timeout=20)
    if r.status_code >= 400:
        raise RuntimeError(f"oauth2 token request failed: HTTP {r.status_code} {r.text[:200]}")
    token = (r.json() or {}).get(a.get("token_field", "access_token"))
    if not token:
        raise RuntimeError("oauth2 response carried no access token")
    _TOKENS[key] = token
    return token


def _apply_auth(url, headers):
    """The contract's `auth` block, placed the way the Ascend bridge places it: static credentials as
    headers, cookies or query parameters; an OAuth2 grant exchanged for a bearer token."""
    blocks = AUTH if isinstance(AUTH, list) else ([AUTH] if AUTH else [])
    cookies = {}
    for a in blocks:
        if not isinstance(a, dict):
            continue
        kind, mode = a.get("type", "static"), a.get("mode", "bearer")
        if kind in (None, "none"):
            continue
        if kind == "oauth2":
            headers[a.get("header", "Authorization")] = f"{a.get('prefix', 'Bearer')} {_oauth2_token(a)}".strip()
        elif kind != "static":
            raise RuntimeError(f"auth type {kind!r} (csrf, multi-hop) needs the Ascend runtime; this standalone module covers static and oauth2")
        elif mode == "bearer":
            headers[a.get("name", "Authorization")] = f"{a.get('prefix', 'Bearer')} {_secret(a.get('value_ref') or a.get('value'))}".strip()
        elif mode == "api_key":
            key, name = _secret(a.get("value_ref") or a.get("value")), a.get("name", "X-API-Key")
            if a.get("in", "header") == "query":
                url = _with_query(url, {name: key})
            else:
                headers[name] = key
        elif mode == "basic":
            import base64
            blob = f"{_secret(a.get('username_ref'), True)}:{_secret(a.get('password_ref'))}".encode()
            headers["Authorization"] = "Basic " + base64.b64encode(blob).decode()
        elif mode == "cookie":
            cookies[a.get("name", "session")] = _secret(a.get("value_ref") or a.get("value"))
        elif mode == "custom":
            headers[a.get("name", "Authorization")] = str(a.get("template", "{{VALUE}}")).replace("{{VALUE}}", _secret(a.get("value_ref") or a.get("value")))
        elif mode == "headers":
            for hname, ref in (a.get("headers") or {}).items():
                headers[str(hname)] = _secret(ref)
        else:
            raise RuntimeError(f"unknown static auth mode {mode!r}")
    if cookies:
        cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
        headers["Cookie"] = f"{headers['Cookie']}; {cookie_str}" if headers.get("Cookie") else cookie_str
    return url, headers


def _dot(data, path):
    """Walk a dot-path; a string that is itself JSON is decoded and the walk continues."""
    cur = data
    for part in str(path or "").split("."):
        if part == "":
            continue
        if isinstance(cur, str):
            try:
                cur = json.loads(cur)
            except ValueError:
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


def _render(template, **values):
    """A body template with {{PROMPT}} / {{SESSION_ID}} / {{CONV}} / {{UUID}} filled in, however deep."""
    import uuid
    raw = template if isinstance(template, str) else json.dumps(template)
    values.setdefault("UUID", str(uuid.uuid4()))
    for key, val in values.items():
        raw = raw.replace("{{" + key + "}}", json.dumps(str(val))[1:-1])
    return raw if isinstance(template, str) else json.loads(raw)


def _text(value, fallback=""):
    if value is None:
        return fallback
    return value if isinstance(value, str) else json.dumps(value)


'''


def _common_block() -> str:
    """Helpers every generated module carries, so the file stands alone and never embeds a secret:
    every `env:NAME` (headers, auth blocks, query credentials, OAuth2 client secrets) is read from
    the environment when the module runs, and a missing one fails loudly with the name to set."""
    return _COMMON_RUNTIME


def _main_block() -> str:
    return (
        "\n\nif __name__ == \"__main__\":\n"
        "    print(send_prompt(\" \".join(sys.argv[1:]) or \"hello\"))\n"
    )


def _auth_literal(cfg: Dict[str, Any]) -> str:
    auth = cfg.get("auth")
    if isinstance(auth, dict):
        auth = [auth]
    return f"AUTH = {_py([a for a in (auth or []) if isinstance(a, dict)])}\n"


def _preamble_v2(name: str, source: str, url: str, adapter_kind: str, imports: str = "import json\nimport requests\n") -> str:
    return (
        f'"""Adapter for {name} — {adapter_kind}, generated by Ascend (from {source}).\n\n'
        f"Ascend -> bridge -> adapter (this file) -> your target. Stands alone: python {name}.py \"hello\".\n"
        f"Secrets are never written here: every `env:` reference is read from the environment at run time.\n"
        f"Re-prove it any time with:  ascend adapter validate --config {name}\n"
        f'"""\n'
        + imports + "\n\n"
        f"META = {{\n"
        f"    \"target\": {_py(url)},\n"
        f"    \"kind\": {_py(adapter_kind)},\n"
        f"    \"generated_from\": {_py(source)},\n"
        f"}}\n\n\n"
    )


def _direct_api_module(name, source, cfg) -> str:
    url = cfg.get("endpoint") or cfg.get("url") or ""
    method = cfg.get("method", "POST")
    body = cfg.get("body")
    if body is None and isinstance(cfg.get("message"), dict):
        body = cfg["message"].get("body")
    if body is None:
        body = {"message": PROMPT_TOKEN}
    return (
        _preamble_v2(name, source, url, "direct_api")
        + f"URL = {_py(url)}\n"
        + f"METHOD = {_py(method)}\n"
        + _header_block(cfg.get("headers") or {})
        + _auth_literal(cfg)
        + f"BODY = {_py(body)}\n"
        + f"RESPONSE_PATH = {_py(cfg.get('response_path') or '')}\n"
        + f"TIMEOUT = {int(cfg.get('timeout_ms', 30000)) // 1000}\n"
        + f"VERIFY_TLS = {_py(bool(cfg.get('verify_tls', True)))}\n\n\n"
        + _common_block()
        + "def send_prompt(prompt: str) -> str:\n"
        "    url, headers = _apply_auth(URL, _headers())\n"
        "    headers.setdefault(\"Content-Type\", \"application/json\")\n"
        "    body = _render(BODY, PROMPT=prompt)\n"
        "    kw = {\"data\": body.encode(\"utf-8\")} if isinstance(body, str) else {\"json\": body}\n"
        "    r = requests.request(METHOD, url, headers=headers, timeout=TIMEOUT, verify=VERIFY_TLS, **kw)\n"
        "    r.raise_for_status()\n"
        "    try:\n"
        "        data = r.json()\n"
        "    except ValueError:\n"
        "        return r.text\n"
        "    if not RESPONSE_PATH:\n"
        "        return data if isinstance(data, str) else r.text\n"
        "    return _text(_dot(data, RESPONSE_PATH), r.text)\n"
        + _main_block()
    )


def _session_api_module(name, source, cfg) -> str:
    """Create a session, then send through it — the create-then-send shape."""
    var = cfg.get("session_variable", "SESSION_ID")
    return (
        _preamble_v2(name, source, cfg.get("message_endpoint") or "", "session_api")
        + f"SESSION_ENDPOINT = {_py(cfg.get('session_endpoint') or '')}\n"
        + f"MESSAGE_ENDPOINT = {_py(cfg.get('message_endpoint') or '')}   # {{{{{var}}}}} is filled from the create reply\n"
        + f"SESSION_VARIABLE = {_py(var)}\n"
        + f"SESSION_BODY = {_py(cfg.get('session_body') or {})}\n"
        + f"SESSION_EXTRACT = {_py(cfg.get('session_extract', 'sessionId'))}\n"
        + f"MESSAGE_BODY = {_py(cfg.get('message_body') or {})}\n"
        + f"RESPONSE_PATH = {_py(cfg.get('response_path', 'messages.0.message'))}\n"
        + f"WARMUP = {_py(cfg.get('warmup_message') or cfg.get('warmup') or cfg.get('session_greeting') or '')}\n"
        + _header_block(cfg.get("headers") or {})
        + _auth_literal(cfg)
        + f"TIMEOUT = {int(cfg.get('timeout_ms', 30000)) // 1000}\n"
        + f"VERIFY_TLS = {_py(bool(cfg.get('verify_tls', True)))}\n\n\n"
        + _common_block()
        + "def _post(url, body, headers):\n"
        "    url, headers = _apply_auth(url, dict(headers))\n"
        "    r = requests.post(url, json=body, headers=headers, timeout=TIMEOUT, verify=VERIFY_TLS)\n"
        "    r.raise_for_status()\n"
        "    return r.json()\n\n\n"
        "def send_prompt(prompt: str) -> str:\n"
        "    headers = {\"Content-Type\": \"application/json\", **_headers()}\n"
        "    # 1. create the session and read its id\n"
        "    created = _post(SESSION_ENDPOINT, _render(SESSION_BODY), headers)\n"
        "    session_id = _dot(created, SESSION_EXTRACT)\n"
        "    if session_id in (None, \"\"):\n"
        "        raise RuntimeError(f\"no {SESSION_EXTRACT!r} in the create reply: {json.dumps(created)[:300]}\")\n"
        "    endpoint = MESSAGE_ENDPOINT.replace(\"{{\" + SESSION_VARIABLE + \"}}\", str(session_id))\n"
        "    # 2. an optional throwaway opener, so a greeting or consent banner is not the answer\n"
        "    if WARMUP:\n"
        "        try:\n"
        "            _post(endpoint, _render(MESSAGE_BODY, PROMPT=WARMUP, **{SESSION_VARIABLE: session_id}), headers)\n"
        "        except Exception:  # noqa: BLE001 - the warm-up is best effort\n"
        "            pass\n"
        "    # 3. the prompt, through the session\n"
        "    reply = _post(endpoint, _render(MESSAGE_BODY, PROMPT=prompt, **{SESSION_VARIABLE: session_id}), headers)\n"
        "    text = _dot(reply, RESPONSE_PATH)\n"
        "    if text is None:\n"
        "        raise RuntimeError(f\"no reply at {RESPONSE_PATH!r}: {json.dumps(reply)[:300]}\")\n"
        "    return _text(text).strip()\n"
        + _main_block()
    )


def _sse_stream_module(name, source, cfg) -> str:
    """POST, then reassemble a streamed reply: SSE, NDJSON or plain text, with the frame rules the
    contract pinned (token types, text path, done rule, named events)."""
    top = {k: cfg[k] for k in ("format", "token_types", "text_path", "done_when", "aggregate", "idle_ms", "type_path",
                               "token_events", "done_events", "ignore_types", "first_frame_ms") if k in cfg}
    stream = {**top, **(cfg.get("stream") or {})}
    base_url = cfg.get("base_url") or ""
    return (
        _preamble_v2(name, source, base_url + str(cfg.get("chat_path") or ""), "sse_stream")
        + f"BASE_URL = {_py(base_url)}\n"
        + f"CHAT_PATH = {_py(cfg.get('chat_path') or '')}\n"
        + f"METHOD = {_py(cfg.get('method', 'POST'))}\n"
        + _header_block(cfg.get("headers") or {})
        + _auth_literal(cfg)
        + f"REQUEST_TEMPLATE = {_py(cfg.get('request_template') or {'message': PROMPT_TOKEN})}\n"
        + f"CREATE = {_py(cfg.get('create') or {})}        # optional: mint a conversation first ({{{{CONV}}}})\n"
        + f"BOOTSTRAP = {_py(cfg.get('bootstrap') or {})}  # optional: a GET that sets cookies / a CSRF token\n"
        + f"STREAM = {_py(stream)}\n"
        + f"TIMEOUT = {int(cfg.get('timeout_ms', 90000)) // 1000}\n"
        + f"VERIFY_TLS = {_py(bool(cfg.get('verify_tls', True)))}\n\n\n"
        + _common_block()
        + "DEFAULT_TOKEN_TYPES = [\"token\", \"delta\", \"content_block_delta\"]\n"
        "DEFAULT_IGNORE_TYPES = [\"status\", \"ping\", \"keepalive\"]\n"
        "DEFAULT_DONE_WHEN = {\"path\": \"type\", \"equals\": \"done\"}\n"
        "DONE_SENTINELS = {\"[DONE]\", \"DONE\"}\n\n\n"
        "def _join(base, path):\n"
        "    return path if str(path).startswith(\"http\") else base.rstrip(\"/\") + \"/\" + str(path).lstrip(\"/\")\n\n\n"
        "def _extract(frame):\n"
        "    if isinstance(frame, str):\n"
        "        return frame\n"
        "    path = STREAM.get(\"text_path\", \"content\")\n"
        "    if path:\n"
        "        v = _dot(frame, path)\n"
        "        if v is not None:\n"
        "            return _text(v)\n"
        "    if isinstance(frame, dict):\n"
        "        for k in (\"content\", \"text\", \"delta\", \"token\", \"message\", \"answer\", \"output\"):\n"
        "            v = frame.get(k)\n"
        "            if isinstance(v, str):\n"
        "                return v\n"
        "            if isinstance(v, dict):\n"
        "                for kk in (\"text\", \"content\", \"value\"):\n"
        "                    if isinstance(v.get(kk), str):\n"
        "                        return v[kk]\n"
        "    return \"\"\n\n\n"
        "def _is_done(frame):\n"
        "    rule = STREAM.get(\"done_when\", DEFAULT_DONE_WHEN)\n"
        "    if not rule:\n"
        "        return False\n"
        "    if \"contains\" in rule:\n"
        "        return rule[\"contains\"] in json.dumps(frame)\n"
        "    return rule.get(\"path\") is not None and _dot(frame, rule[\"path\"]) == rule.get(\"equals\")\n\n\n"
        "def _handle(payload, event, chunks):\n"
        "    \"\"\"One frame. Appends its text; returns True when the stream is done.\"\"\"\n"
        "    token_events, done_events = STREAM.get(\"token_events\"), STREAM.get(\"done_events\")\n"
        "    if not payload:\n"
        "        return bool(event) and bool(done_events) and event in done_events\n"
        "    if token_events or done_events:\n"
        "        is_done = bool(done_events) and event in (done_events or [])\n"
        "        if event is not None and not ((event in (token_events or [])) or is_done):\n"
        "            return False\n"
        "        try:\n"
        "            text = _extract(json.loads(payload))\n"
        "        except ValueError:\n"
        "            text = payload\n"
        "        if text:\n"
        "            chunks.append(text)\n"
        "        return is_done\n"
        "    if payload in DONE_SENTINELS:\n"
        "        return True\n"
        "    try:\n"
        "        frame = json.loads(payload)\n"
        "    except ValueError:\n"
        "        chunks.append(payload)\n"
        "        return False\n"
        "    ftype = _dot(frame, STREAM.get(\"type_path\", \"type\")) if STREAM.get(\"type_path\", \"type\") else None\n"
        "    explicit = STREAM.get(\"token_types\")\n"
        "    if ftype is None and event and explicit:\n"
        "        ftype = event\n"
        "    if ftype in (STREAM.get(\"ignore_types\") or DEFAULT_IGNORE_TYPES):\n"
        "        return False\n"
        "    done = _is_done(frame)\n"
        "    if ftype is None or ftype in (explicit or DEFAULT_TOKEN_TYPES):\n"
        "        text = _extract(frame)\n"
        "        if text:\n"
        "            chunks.append(text)\n"
        "    return done\n\n\n"
        "def _read(resp):\n"
        "    fmt = STREAM.get(\"format\", \"sse\")\n"
        "    chunks, data_lines, event = [], [], [None]\n"
        "    def flush():\n"
        "        ev, event[0] = event[0], None\n"
        "        if not data_lines:\n"
        "            return bool(ev) and bool(STREAM.get(\"done_events\")) and ev in STREAM[\"done_events\"]\n"
        "        payload = \"\".join(data_lines)\n"
        "        data_lines.clear()\n"
        "        return _handle(payload, ev, chunks)\n"
        "    for raw in resp.iter_lines(decode_unicode=False):\n"
        "        line = \"\" if not raw else (raw.decode(\"utf-8\", \"replace\") if isinstance(raw, (bytes, bytearray)) else raw)\n"
        "        if fmt == \"ndjson\":\n"
        "            if line.strip() and _handle(line.strip(), None, chunks):\n"
        "                break\n"
        "            continue\n"
        "        if fmt in (\"plaintext\", \"raw\", \"text\"):\n"
        "            if line and line.strip() in DONE_SENTINELS:\n"
        "                break\n"
        "            if line:\n"
        "                chunks.append(line)\n"
        "            continue\n"
        "        if not line.strip():\n"
        "            if flush():\n"
        "                break\n"
        "            continue\n"
        "        if line.startswith(\":\"):\n"
        "            continue\n"
        "        if line.startswith(\"data:\"):\n"
        "            data_lines.append(line[5:].lstrip())\n"
        "        elif line.startswith(\"event:\"):\n"
        "            event[0] = line[6:].strip()\n"
        "    else:\n"
        "        flush()\n"
        "    return (chunks[-1] if chunks else \"\") if STREAM.get(\"aggregate\", \"concat\") == \"last\" else \"\".join(chunks)\n\n\n"
        "def send_prompt(prompt: str) -> str:\n"
        "    session = requests.Session()\n"
        "    headers = {\"Content-Type\": \"application/json\", \"Accept\": \"text/event-stream\", **_headers()}\n"
        "    if BOOTSTRAP.get(\"url\"):\n"
        "        boot = session.get(_join(BASE_URL, BOOTSTRAP[\"url\"]), headers=_headers(), timeout=10, verify=VERIFY_TLS)\n"
        "        token = boot.headers.get(BOOTSTRAP.get(\"csrf_header\", \"X-CSRF-Token\")) or session.cookies.get(BOOTSTRAP.get(\"csrf_cookie\", \"XSRF-TOKEN\"))\n"
        "        if token:\n"
        "            headers[BOOTSTRAP.get(\"csrf_header\", \"X-CSRF-Token\")] = token\n"
        "    path, conv = CHAT_PATH, None\n"
        "    if CREATE.get(\"url\"):\n"
        "        import uuid\n"
        "        conv = f\"abv2-{uuid.uuid4().hex}\" if CREATE.get(\"id_mode\") == \"client\" else None\n"
        "        payload = _render(CREATE[\"body\"], PROMPT=prompt, CONV=conv or \"\") if CREATE.get(\"body\") is not None else None\n"
        "        url, hdrs = _apply_auth(_join(BASE_URL, CREATE[\"url\"]), dict(headers))\n"
        "        r = session.request(CREATE.get(\"method\", \"POST\"), url, json=payload if not isinstance(payload, str) else None,\n"
        "                            data=payload if isinstance(payload, str) else None, headers=hdrs, timeout=10, verify=VERIFY_TLS)\n"
        "        r.raise_for_status()\n"
        "        if conv is None:\n"
        "            conv = _text(_dot(r.json(), CREATE.get(\"id_path\", \"id\")))\n"
        "        path = CHAT_PATH.replace(\"{{CONV}}\", conv)\n"
        "    body = _render(REQUEST_TEMPLATE, PROMPT=prompt, CONV=conv or \"\")\n"
        "    url, headers = _apply_auth(_join(BASE_URL, path), headers)\n"
        "    first_wait = float(STREAM.get(\"first_frame_ms\") or (TIMEOUT - 2) * 1000) / 1000\n"
        "    resp = session.request(METHOD, url, data=(body if isinstance(body, str) else json.dumps(body)).encode(\"utf-8\"), headers=headers,\n"
        "                           stream=True, timeout=(10, max(1.0, first_wait)), verify=VERIFY_TLS)\n"
        "    if resp.status_code >= 400:\n"
        "        raise RuntimeError(f\"HTTP {resp.status_code}: {resp.text[:300]}\")\n"
        "    try:\n"
        "        return _read(resp).strip()\n"
        "    finally:\n"
        "        resp.close()\n"
        + _main_block()
    )


def _websocket_module(name, source, cfg) -> str:
    """Connect, send one frame, assemble the frames that come back until the idle gap or the done rule."""
    ws_url = cfg.get("ws_url") or cfg.get("url") or ""
    return (
        _preamble_v2(name, source, ws_url, "websocket_direct", imports="import asyncio\nimport json\n")
        + f"WS_URL = {_py(ws_url)}\n"
        + _header_block(cfg.get("headers") or {})
        + _auth_literal(cfg)
        + f"SUBPROTOCOLS = {_py(cfg.get('subprotocols') or None)}\n"
        + f"INIT_MESSAGES = {_py(cfg.get('init_messages') or [])}\n"
        + f"SEND_TEMPLATE = {_py(cfg.get('send_template') or {'type': 'message', 'text': PROMPT_TOKEN})}\n"
        + f"RESPONSE_PATH = {_py(cfg.get('response_path') or '')}\n"
        + f"DONE_WHEN = {_py(cfg.get('done_when') or {})}\n"
        + f"AGGREGATE = {_py(cfg.get('aggregate', 'concat'))}\n"
        + f"IDLE_S = {float(cfg.get('idle_ms', 1500)) / 1000}\n"
        + f"FIRST_FRAME_S = {_py((float(cfg['first_frame_ms']) / 1000) if cfg.get('first_frame_ms') else None)}\n"
        + f"TIMEOUT = {int(cfg.get('timeout_ms', 60000)) // 1000}\n\n\n"
        + _common_block()
        + "def _encode(frame, prompt):\n"
        "    return _render(frame, PROMPT=prompt) if isinstance(frame, str) else json.dumps(_render(frame, PROMPT=prompt))\n\n\n"
        "def _decode(raw):\n"
        "    if isinstance(raw, (bytes, bytearray)):\n"
        "        raw = raw.decode(\"utf-8\", \"ignore\")\n"
        "    try:\n"
        "        return json.loads(raw)\n"
        "    except (ValueError, TypeError):\n"
        "        return raw\n\n\n"
        "def _error_frame(frame):\n"
        "    if isinstance(frame, dict) and isinstance(frame.get(\"message\"), str) and (\"requestId\" in frame or \"connectionId\" in frame) and len(frame) <= 4:\n"
        "        return frame[\"message\"][:200]\n"
        "    return None\n\n\n"
        "def _extract(frame):\n"
        "    if isinstance(frame, str):\n"
        "        return frame\n"
        "    if RESPONSE_PATH:\n"
        "        return _text(_dot(frame, RESPONSE_PATH))\n"
        "    if isinstance(frame, dict):\n"
        "        for k in (\"text\", \"content\", \"message\", \"delta\", \"token\", \"answer\", \"output\"):\n"
        "            v = frame.get(k)\n"
        "            if isinstance(v, str):\n"
        "                return v\n"
        "            if isinstance(v, dict):\n"
        "                for kk in (\"text\", \"content\", \"value\"):\n"
        "                    if isinstance(v.get(kk), str):\n"
        "                        return v[kk]\n"
        "    return \"\"\n\n\n"
        "def _is_done(frame):\n"
        "    if not DONE_WHEN:\n"
        "        return False\n"
        "    if \"contains\" in DONE_WHEN:\n"
        "        return DONE_WHEN[\"contains\"] in json.dumps(frame)\n"
        "    return DONE_WHEN.get(\"path\") is not None and _dot(frame, DONE_WHEN[\"path\"]) == DONE_WHEN.get(\"equals\")\n\n\n"
        "async def _converse(prompt):\n"
        "    import websockets\n"
        "    url, headers = _apply_auth(WS_URL, _headers())\n"
        "    kw = {\"subprotocols\": SUBPROTOCOLS, \"open_timeout\": 10, \"max_size\": 10 * 1024 * 1024}\n"
        "    try:\n"
        "        ws_cm = websockets.connect(url, additional_headers=headers, **kw)\n"
        "    except TypeError:\n"
        "        ws_cm = websockets.connect(url, extra_headers=headers, **kw)\n"
        "    chunks, frames, error = [], 0, None\n"
        "    first_wait = FIRST_FRAME_S if FIRST_FRAME_S else max(IDLE_S, TIMEOUT - 5.0)\n"
        "    async with ws_cm as ws:\n"
        "        for m in INIT_MESSAGES:\n"
        "            await ws.send(_encode(m, prompt))\n"
        "        await ws.send(_encode(SEND_TEMPLATE, prompt))\n"
        "        while True:\n"
        "            try:\n"
        "                raw = await asyncio.wait_for(ws.recv(), timeout=first_wait if not frames else IDLE_S)\n"
        "            except (asyncio.TimeoutError, Exception):  # noqa: BLE001 - the idle gap or a close ends the answer\n"
        "                break\n"
        "            frames += 1\n"
        "            frame = _decode(raw)\n"
        "            err = _error_frame(frame)\n"
        "            if err:\n"
        "                error = err\n"
        "                continue\n"
        "            text = _extract(frame)\n"
        "            if text:\n"
        "                chunks.append(text)\n"
        "            if _is_done(frame) or sum(len(c) for c in chunks) > 4 * 1024 * 1024:\n"
        "                break\n"
        "    if not chunks:\n"
        "        raise RuntimeError(f\"socket error frame: {error}\" if error else (f\"{frames} frame(s) but no answer text (check RESPONSE_PATH)\" if frames else f\"no frame within {first_wait:.0f}s\"))\n"
        "    return (chunks[-1] if AGGREGATE == \"last\" else \"\".join(chunks)).strip()\n\n\n"
        "def send_prompt(prompt: str) -> str:\n"
        "    return asyncio.run(asyncio.wait_for(_converse(prompt), timeout=TIMEOUT))\n"
        + _main_block()
    )


def _openai_compatible_module(name, source, cfg) -> str:
    endpoint = str(cfg.get("endpoint") or cfg.get("url") or "")
    return (
        _preamble_v2(name, source, endpoint, "openai_compatible")
        + f"ENDPOINT = {_py(endpoint)}    # a base URL or the full /v1/chat/completions URL\n"
        + f"MODEL = {_py(cfg.get('model') or '')}        # empty: the first model GET /v1/models lists\n"
        + f"SYSTEM_PROMPT = {_py(cfg.get('system_prompt') or '')}\n"
        + f"MAX_TOKENS = {int(cfg.get('max_tokens') or 512)}\n"
        + f"TEMPERATURE = {_py(cfg.get('temperature'))}\n"
        + _header_block(cfg.get("headers") or {})
        + _auth_literal(cfg)
        + f"TIMEOUT = {int(cfg.get('timeout_ms', 60000)) // 1000}\n"
        + f"VERIFY_TLS = {_py(bool(cfg.get('verify_tls', True)))}\n\n\n"
        + _common_block()
        + "def _chat_url(endpoint):\n"
        "    from urllib.parse import urlsplit, urlunsplit\n"
        "    p = urlsplit(endpoint.strip())\n"
        "    path = p.path.rstrip(\"/\")\n"
        "    if not path.endswith(\"/chat/completions\"):\n"
        "        path = (path if path.endswith(\"/v1\") else path + \"/v1\") + \"/chat/completions\"\n"
        "    return urlunsplit((p.scheme, p.netloc, path, p.query, \"\"))\n\n\n"
        "def _models_url(endpoint):\n"
        "    from urllib.parse import urlsplit, urlunsplit\n"
        "    p = urlsplit(_chat_url(endpoint))\n"
        "    return urlunsplit((p.scheme, p.netloc, p.path[: -len(\"/chat/completions\")] + \"/models\", p.query, \"\"))\n\n\n"
        "def _model(headers):\n"
        "    if MODEL:\n"
        "        return MODEL\n"
        "    url, headers = _apply_auth(_models_url(ENDPOINT), dict(headers))\n"
        "    r = requests.get(url, headers=headers, timeout=min(TIMEOUT, 20), verify=VERIFY_TLS)\n"
        "    r.raise_for_status()\n"
        "    rows = (r.json() or {}).get(\"data\") or []\n"
        "    if not rows:\n"
        "        raise RuntimeError(\"no models listed: set MODEL\")\n"
        "    return str(rows[0].get(\"id\"))\n\n\n"
        "def send_prompt(prompt: str) -> str:\n"
        "    headers = {\"Content-Type\": \"application/json\", **_headers()}\n"
        "    messages = ([{\"role\": \"system\", \"content\": SYSTEM_PROMPT}] if SYSTEM_PROMPT else []) + [{\"role\": \"user\", \"content\": prompt}]\n"
        "    body = {\"model\": _model(headers), \"messages\": messages, \"stream\": False, \"max_tokens\": MAX_TOKENS}\n"
        "    if TEMPERATURE is not None:\n"
        "        body[\"temperature\"] = float(TEMPERATURE)\n"
        "    url, headers = _apply_auth(_chat_url(ENDPOINT), headers)\n"
        "    r = requests.post(url, json=body, headers=headers, timeout=TIMEOUT, verify=VERIFY_TLS)\n"
        "    if r.status_code >= 400:\n"
        "        raise RuntimeError(f\"HTTP {r.status_code}: {r.text[:300]}\")\n"
        "    data = r.json()\n"
        "    choice = (data.get(\"choices\") or [{}])[0] or {}\n"
        "    content = (choice.get(\"message\") or {}).get(\"content\") if isinstance(choice.get(\"message\"), dict) else choice.get(\"text\")\n"
        "    if isinstance(content, list):\n"
        "        content = \"\".join(str(p.get(\"text\") or \"\") for p in content if isinstance(p, dict))\n"
        "    if not isinstance(content, str) or not content:\n"
        "        raise RuntimeError(f\"no assistant text in the completion: {json.dumps(data)[:300]}\")\n"
        "    return content\n"
        + _main_block()
    )


def _sentinel_module(name, source, cfg) -> str:
    url = cfg.get("url") or cfg.get("endpoint") or ""
    method = cfg.get("method", "POST")
    body = cfg.get("message", {}).get("body") if isinstance(cfg.get("message"), dict) else cfg.get("body")
    extract = cfg.get("extract") or {}
    events_path = (extract.get("events_path") or "").split(".") if extract.get("events_path") else []
    return (
        _preamble(name, source, url, "sentinel_stream")
        + f"URL = {_py(url)}\n"
        + f"METHOD = {_py(method)}\n"
        + _header_block(cfg.get("headers") or {})
        + f"TIMEOUT = {int(cfg.get('timeout_ms', 30000)) // 1000}\n"
        + f"BEGIN = {_py(cfg.get('begin_marker'))}\n"
        + f"END = {_py(cfg.get('end_marker'))}\n"
        + f"EVENTS_PATH = {_py(events_path)}\n"
        + f"TEXT_FIELD = {_py(extract.get('text_field', 'text'))}\n"
        + f"MESSAGE_PATH = {_py(extract.get('message_path') or '')}\n\n\n"
        + _body_fn(body)
        + "\n\n"
        "def _frames(raw):\n"
        "    import re\n"
        "    for m in re.findall(re.escape(BEGIN) + r'(.*?)' + re.escape(END), raw, re.S):\n"
        "        try:\n"
        "            yield json.loads(m.strip())\n"
        "        except ValueError:\n"
        "            continue\n\n\n"
        "def _text_from(obj):\n"
        "    cur = obj\n"
        "    for key in EVENTS_PATH:\n"
        "        if isinstance(cur, dict) and key in cur:\n"
        "            cur = cur[key]\n"
        "        else:\n"
        "            return None\n"
        "    events = cur if isinstance(cur, list) else [cur]\n"
        "    out = []\n"
        "    for ev in events:\n"
        "        node = ev.get(MESSAGE_PATH, ev) if (MESSAGE_PATH and isinstance(ev, dict)) else ev\n"
        "        if isinstance(node, dict) and isinstance(node.get(TEXT_FIELD), str):\n"
        "            out.append(node[TEXT_FIELD])\n"
        "    return ' '.join(out) if out else None\n\n\n"
        "def send_prompt(prompt: str) -> str:\n"
        "    r = requests.request(METHOD, URL, headers=HEADERS, json=_body(prompt), timeout=TIMEOUT)\n"
        "    r.raise_for_status()\n"
        "    parts = [t for t in (_text_from(f) for f in _frames(r.text)) if t]\n"
        "    return parts[-1] if parts else r.text\n"
        + _main_block()
    )


def _scaffold_module(name, source, cfg) -> str:
    """For a target that fits no known pattern: emit the real captured request + a clear TODO."""
    url = cfg.get("url") or cfg.get("endpoint") or ""
    return (
        _preamble(name, source, url, "custom")
        + f"URL = {_py(url)}\n"
        + f"METHOD = {_py(cfg.get('method', 'POST'))}\n"
        + _header_block(cfg.get("headers") or {})
        + f"TIMEOUT = {int(cfg.get('timeout_ms', 30000)) // 1000}\n\n\n"
        + _body_fn(cfg.get("body") or (cfg.get("message", {}) or {}).get("body"))
        + "\n\n"
        "def send_prompt(prompt: str) -> str:\n"
        "    # This target did not match a known pattern. The captured request is above.\n"
        "    # Finish this function: send `prompt`, return the app's reply as a string.\n"
        "    # `ascend adapter build --agent` can write this for you from the captured evidence.\n"
        "    r = requests.request(METHOD, URL, headers=HEADERS, json=_body(prompt), timeout=TIMEOUT)\n"
        "    r.raise_for_status()\n"
        "    raise NotImplementedError('finish send_prompt: extract the reply from r')\n"
    )


def generate_adapter_module(name: str, config: Dict[str, Any], source: str = "build") -> str:
    """Produce the source of a per-app adapter module from a discovered config.

    Chooses a generator by the discovered adapter kind; falls back to a scaffold that still carries
    the real request. The result is always a module exposing send_prompt(prompt) -> str.
    """
    config = _lift_urls(config, ("url", "endpoint", "ws_url", "base_url", "chat_path", "session_endpoint", "message_endpoint"))
    src = _generate(name, config, source)
    names = sorted(set(re.findall(r"env:([A-Za-z_][A-Za-z0-9_]*)", src.replace(_COMMON_RUNTIME, ""))))   # the contract's names, not the helpers' docstrings
    if names and "Re-prove it any time with:" in src:
        src = src.replace("Re-prove it any time with:", "Set before running: " + ", ".join(names) + "\nRe-prove it any time with:", 1)
    return src


def _generate(name: str, config: Dict[str, Any], source: str) -> str:
    kind = (config.get("adapter") or "").lower()
    if kind == "sentinel_stream":
        return _sentinel_module(name, source, config)
    if kind in ("direct_api", "", "api"):
        return _direct_api_module(name, source, config)
    # The transports an operator meets in the field each get a self-contained module (owner,
    # 2026-10-02: "I need to be able to just copy and paste adapter code or give the file to an
    # engineer if it needs hosting"). Browser capture and the platform presets still run through
    # their built-in handlers and the hand-over bundle; those fall to the scaffold.
    if kind == "session_api":
        return _session_api_module(name, source, config)
    if kind == "sse_stream":
        return _sse_stream_module(name, source, config)
    if kind == "websocket_direct":
        return _websocket_module(name, source, config)
    if kind == "openai_compatible":
        return _openai_compatible_module(name, source, config)
    return _scaffold_module(name, source, config)


def browser_config_from_recipe(url: str, recipe: Dict[str, Any]) -> Dict[str, Any]:
    """A `browser` adapter config from what the capture actually did to the live widget.

    The capture already opened the widget, found the input, sent a prompt, and read the reply — so
    it knows the launcher, the chat frame, the input selector, how to send, and where the reply
    renders. This turns that into the adapter that DRIVES a real browser per probe, which is the
    only thing that works on a target whose HTTP endpoint refuses replay (anti-automation).
    """
    cfg: Dict[str, Any] = {
        "adapter": "browser",
        "_note": "driven through a real browser per probe (the HTTP endpoint refuses replay). "
                 "Generated by `adapter build --url`; tune selectors with `adapter show`.",
        "url": url,
        "headless": False,
        "pre_actions": [{"action": "dismiss_cookie", "description": "accept a consent/cookie gate if prompted",
                         **({"selectors": [recipe["consent"]]} if recipe.get("consent") else {})},
                        {"action": "wait", "ms": 2500}],
    }
    if recipe.get("launcher"):
        cfg["pre_actions"].append({"action": "click", "selector": recipe["launcher"],
                                   "timeout_ms": 20000, "description": "open the chat widget"})
        cfg["pre_actions"].append({"action": "wait", "ms": 4000})
    # the chat frame, matched by URL (robust for nested widgets)
    furl = recipe.get("input_frame_url") or ""
    if furl:
        needle = _frame_needle(furl, url)
        if needle:
            cfg["iframe"] = {"url_contains": needle}
    inp = recipe.get("input_selector") or "textarea, input[type='text']"
    cfg["wait_for_widget"] = {"selector": inp, "timeout_ms": 25000}
    cfg["input"] = {"selector": inp}
    send = recipe.get("send") or "enter"
    cfg["send"] = {"method": "enter"} if send == "enter" else {"method": "click", "selector": send}
    resp: Dict[str, Any] = {
        "wait_strategy": recipe.get("reply_strategy", "text_settle"),
        "container_selector": recipe.get("reply_container",
                                         "[class*='message'], [class*='bubble'], [class*='chat']"),
        "timeout_ms": 45000,
        "stabilization_delay_ms": 3000,
        "poll_interval_ms": 700,
    }
    cfg["response"] = resp
    return cfg


def _frame_needle(frame_url: str, page_url: str) -> str:
    """A distinctive path substring of the chat frame's URL, for iframe.url_contains.

    Prefer the frame's own path (e.g. '/chat/support'); avoid matching the host page itself.
    """
    from urllib.parse import urlsplit
    try:
        fp = urlsplit(frame_url)
        path = (fp.path or "").rstrip("/")
        if path and len(path) > 1:
            # last two path segments, distinctive enough to pick the chat frame out of many
            segs = [s for s in path.split("/") if s]
            return "/".join(segs[-2:]) if len(segs) >= 2 else segs[-1]
        # no path: fall back to the frame host if it differs from the page host
        if fp.netloc and fp.netloc not in page_url:
            return fp.netloc
    except Exception:
        pass
    return ""
