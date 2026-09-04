"""
layers.auth — Layer 2 (Auth) and Layer 3 (Auth lifecycle).

Layer 2 answers "how is *one* request authorized?" and Layer 3 answers "how do
those credentials stay valid over a long run?". Both are expressed as small
config blocks and turned into concrete header/cookie/query material to attach to
outgoing requests.

    config["auth"]            -> AuthProvider   (Layer 2)
    config["auth_lifecycle"]  -> AuthLifecycle  (Layer 3)

Hard rules
----------
* **Secrets are never inline.** Every credential value is a *reference*, resolved
  from the environment at materialize time: ``{"value_ref": "env:MY_TOKEN"}`` or
  the shorthand string ``"env:MY_TOKEN"``. A literal-looking value is rejected by
  :func:`resolve_secret_ref` so a real secret can never be committed to a config
  file. (An explicit ``"literal:..."`` escape hatch exists for non-secret
  constants only, and is discouraged.)
* **Lazy network.** Importing this module does nothing. Static auth
  (bearer/api-key/basic/cookie) needs no network at all. The dynamic providers
  (``oauth2``, ``csrf``, ``derived_multihop``) only reach the network inside
  :meth:`AuthProvider.materialize`, and every request carries a timeout.

Auth kinds (Layer 2)
--------------------
``none``
    No secret on the wire.
``static``
    A constant secret. ``mode`` is one of ``bearer`` | ``api_key`` | ``basic`` |
    ``cookie`` | ``custom``. For ``api_key`` the ``in`` field selects
    ``header`` (default) or ``query`` and ``name`` names the field.
``oauth2``
    Fetch a token from ``token_url``. ``grant`` is
    ``client_credentials`` | ``password`` | ``refresh``. The access token becomes
    an ``Authorization: Bearer`` header downstream.
``csrf``
    GET ``bootstrap_url``, extract a token (by JSON ``path`` or ``regex``), then
    echo it in a header (``into_header``) or a body variable.
``derived_multihop``
    A chain of ``steps``. Each step issues a request, extracts a value (JSON
    ``path`` or ``regex``) into a named variable, and later steps + the final
    downstream headers may reference earlier variables via ``{{VAR}}``.

Lifecycle kinds (Layer 3): ``static`` | ``refresh_on_ttl`` | ``reauth_on_401`` |
``cookie_rotation`` — see :class:`AuthLifecycle`.
"""
from __future__ import annotations

import base64
import binascii
import json
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

DEFAULT_TIMEOUT_S = 20.0


class AuthError(RuntimeError):
    """Raised for malformed auth config or a failed credential resolution."""


# --------------------------------------------------------------------------- #
# Secret references                                                           #
# --------------------------------------------------------------------------- #
def resolve_secret_ref(ref: Any, *, allow_literal: bool = False) -> str:
    """Resolve a secret *reference* to its value without ever inlining secrets.

    Accepts either a bare string (``"env:NAME"``) or a wrapper dict
    (``{"value_ref": "env:NAME"}``). Supported schemes:

    * ``env:NAME``     -> ``os.environ["NAME"]`` (raises if unset/empty).
    * ``literal:TEXT`` -> ``TEXT``, only when ``allow_literal`` is True. Intended
      for non-secret constants (a fixed user id), never for credentials.

    A plain value with no recognised scheme is refused — this is the guardrail
    that stops a real token being pasted into a config file.
    """
    if isinstance(ref, dict):
        ref = ref.get("value_ref", ref.get("value"))
    if not isinstance(ref, str) or not ref:
        raise AuthError(f"secret reference must be a non-empty string/value_ref, got {ref!r}")

    if ref.startswith("env:"):
        name = ref[len("env:"):]
        val = os.environ.get(name)
        if val is None or val == "":
            raise AuthError(f"environment variable {name!r} is not set (referenced by {ref!r})")
        return val
    if ref.startswith("literal:"):
        if not allow_literal:
            raise AuthError("literal: values are not allowed for secrets; use env: references")
        return ref[len("literal:"):]
    raise AuthError(
        f"unrecognised secret reference {ref!r}; use 'env:NAME' "
        f"(inline literals are forbidden so secrets stay out of configs)"
    )


def _render_vars(template: Any, variables: Dict[str, str]) -> Any:
    """Substitute ``{{VAR}}`` placeholders in a (possibly nested) structure."""
    if isinstance(template, str):
        out = template
        for k, v in variables.items():
            out = out.replace("{{" + k + "}}", str(v))
        return out
    if isinstance(template, dict):
        return {k: _render_vars(v, variables) for k, v in template.items()}
    if isinstance(template, list):
        return [_render_vars(v, variables) for v in template]
    return template


def _extract(data: Any, path: str) -> Any:
    """Dot-path extraction over nested dict/list (mirrors the adapters' helper)."""
    cur = data
    for part in path.split("."):
        if cur is None:
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


def _extract_value(source_text: str, source_json: Any, spec: Dict[str, Any]) -> Optional[str]:
    """Pull a value out of a response using a ``path`` or ``regex`` spec."""
    if "path" in spec and source_json is not None:
        val = _extract(source_json, spec["path"])
        return None if val is None else str(val)
    if "regex" in spec:
        m = re.search(spec["regex"], source_text or "")
        if m:
            return m.group(1) if m.groups() else m.group(0)
    return None


# --------------------------------------------------------------------------- #
# Materialized auth                                                           #
# --------------------------------------------------------------------------- #
@dataclass
class AuthMaterial:
    """The concrete artifacts an :class:`AuthProvider` produces for a request.

    ``headers`` / ``cookies`` / ``params`` are ready to merge onto a request;
    ``body_vars`` are named values (e.g. a CSRF token) an adapter can inject into
    a request body template via ``{{VAR}}``.
    """

    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    params: Dict[str, str] = field(default_factory=dict)
    body_vars: Dict[str, str] = field(default_factory=dict)

    def merge_into_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Return a shallow copy of ``config`` with auth headers/params folded in.

        Used by discovery's validator to run a composed config against the live
        target without ever writing the secret into the config on disk.
        """
        merged = dict(config)
        merged_headers = dict(config.get("headers") or {})
        merged_headers.update(self.headers)
        if self.cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
            existing = merged_headers.get("Cookie")
            merged_headers["Cookie"] = f"{existing}; {cookie_str}" if existing else cookie_str
        merged["headers"] = merged_headers
        if self.params:
            merged_params = dict(config.get("params") or {})
            merged_params.update(self.params)
            merged["params"] = merged_params
            # No adapter reads `params`; every URL-driven one reads `endpoint`/`url`. Folding the
            # parameters into the query string here is the one seam that reaches all of them —
            # without it `mode: api_key, in: query` resolved correctly and never left the machine.
            for key in ("endpoint", "url"):
                if isinstance(merged.get(key), str) and merged[key]:
                    merged[key] = _with_query(merged[key], self.params)
        return merged


def _with_query(url: str, params: Dict[str, str]) -> str:
    """`url` with `params` set in its query string (replacing same-named parameters)."""
    from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode
    parts = urlsplit(url)
    kept = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k not in params]
    return urlunsplit(parts._replace(query=urlencode(kept + list(params.items()))))


# --------------------------------------------------------------------------- #
# Auth provider (Layer 2)                                                     #
# --------------------------------------------------------------------------- #
class AuthProvider:
    """Turns an ``auth`` config block into :class:`AuthMaterial`.

    Build with :meth:`from_config`. Call :meth:`materialize` to produce the
    headers/cookies for a request. Static kinds resolve with no network; dynamic
    kinds (``oauth2``/``csrf``/``derived_multihop``) issue timed HTTP requests
    only when ``materialize`` runs.
    """

    KINDS = ("none", "static", "oauth2", "csrf", "derived_multihop")

    def __init__(self, auth_config: Optional[Dict[str, Any]]) -> None:
        self.config: Dict[str, Any] = auth_config or {"type": "none"}
        self.kind: str = self.config.get("type", "none")
        if self.kind not in self.KINDS:
            raise AuthError(f"unknown auth type {self.kind!r}; valid={self.KINDS}")
        # Cache of last materialization (used by lifecycle refresh decisions).
        self._cached: Optional[AuthMaterial] = None
        self._cached_token: Optional[str] = None

    @classmethod
    def from_config(cls, config: Optional[Dict[str, Any]]) -> "AuthProvider":
        """Build from a *full* adapter config (reads its ``auth`` block)."""
        block = (config or {}).get("auth") if config else None
        if block is None and config is not None and "type" in (config or {}):
            block = config
        return cls(block)

    # -- public API -------------------------------------------------------- #
    @property
    def needs_network(self) -> bool:
        """True if :meth:`materialize` will make an HTTP request."""
        return self.kind in ("oauth2", "csrf", "derived_multihop")

    @property
    def token(self) -> Optional[str]:
        """The last bearer/access token obtained (for JWT-exp lifecycle checks)."""
        return self._cached_token

    def materialize(self, *, timeout_s: float = DEFAULT_TIMEOUT_S,
                    verify_tls: bool = True) -> AuthMaterial:
        """Produce request auth material, performing network I/O if required."""
        if self.kind == "none":
            self._cached = AuthMaterial()
        elif self.kind == "static":
            self._cached = self._materialize_static()
        elif self.kind == "oauth2":
            self._cached = self._materialize_oauth2(timeout_s, verify_tls)
        elif self.kind == "csrf":
            self._cached = self._materialize_csrf(timeout_s, verify_tls)
        elif self.kind == "derived_multihop":
            self._cached = self._materialize_multihop(timeout_s, verify_tls)
        else:  # pragma: no cover - guarded in __init__
            raise AuthError(f"unhandled auth kind {self.kind!r}")
        return self._cached

    # -- static ------------------------------------------------------------ #
    def _materialize_static(self) -> AuthMaterial:
        cfg = self.config
        mode = cfg.get("mode", "bearer")
        mat = AuthMaterial()
        if mode == "bearer":
            token = resolve_secret_ref(cfg.get("value_ref") or cfg.get("value"))
            self._cached_token = token
            mat.headers[cfg.get("name", "Authorization")] = f"{cfg.get('prefix', 'Bearer')} {token}".strip()
        elif mode == "api_key":
            key = resolve_secret_ref(cfg.get("value_ref") or cfg.get("value"))
            name = cfg.get("name", "X-API-Key")
            if cfg.get("in", "header") == "query":
                mat.params[name] = key
            else:
                mat.headers[name] = key
        elif mode == "basic":
            user = resolve_secret_ref(cfg.get("username_ref"), allow_literal=True)
            pw = resolve_secret_ref(cfg.get("password_ref"))
            blob = base64.b64encode(f"{user}:{pw}".encode()).decode()
            mat.headers["Authorization"] = f"Basic {blob}"
        elif mode == "cookie":
            val = resolve_secret_ref(cfg.get("value_ref") or cfg.get("value"))
            mat.cookies[cfg.get("name", "session")] = val
        elif mode == "custom":
            val = resolve_secret_ref(cfg.get("value_ref") or cfg.get("value"))
            template = cfg.get("template", "{{VALUE}}")
            mat.headers[cfg.get("name", "Authorization")] = template.replace("{{VALUE}}", val)
        else:
            raise AuthError(f"unknown static auth mode {mode!r}")
        return mat

    # -- oauth2 ------------------------------------------------------------ #
    def _materialize_oauth2(self, timeout_s: float, verify_tls: bool) -> AuthMaterial:
        import requests  # lazy

        cfg = self.config
        grant = cfg.get("grant", "client_credentials")
        token_url = cfg.get("token_url")
        if not token_url:
            raise AuthError("oauth2 auth requires 'token_url'")

        data: Dict[str, str] = {}
        if grant == "client_credentials":
            data = {
                "grant_type": "client_credentials",
                "client_id": resolve_secret_ref(cfg.get("client_id_ref"), allow_literal=True),
                "client_secret": resolve_secret_ref(cfg.get("client_secret_ref")),
            }
        elif grant == "password":
            data = {
                "grant_type": "password",
                "client_id": resolve_secret_ref(cfg.get("client_id_ref"), allow_literal=True),
                "username": resolve_secret_ref(cfg.get("username_ref"), allow_literal=True),
                "password": resolve_secret_ref(cfg.get("password_ref")),
            }
            if cfg.get("client_secret_ref"):
                data["client_secret"] = resolve_secret_ref(cfg["client_secret_ref"])
        elif grant == "refresh":
            data = {
                "grant_type": "refresh_token",
                "refresh_token": resolve_secret_ref(cfg.get("refresh_token_ref")),
                "client_id": resolve_secret_ref(cfg.get("client_id_ref"), allow_literal=True),
            }
            if cfg.get("client_secret_ref"):
                data["client_secret"] = resolve_secret_ref(cfg["client_secret_ref"])
        else:
            raise AuthError(f"unknown oauth2 grant {grant!r}")

        if cfg.get("scope"):
            data["scope"] = cfg["scope"]
        data.update(cfg.get("extra", {}) or {})

        resp = requests.post(token_url, data=data, timeout=timeout_s, verify=verify_tls)
        if resp.status_code >= 400:
            raise AuthError(f"oauth2 token request failed: HTTP {resp.status_code} {resp.text[:200]}")
        payload = resp.json()
        token = payload.get(cfg.get("token_field", "access_token"))
        if not token:
            raise AuthError(f"oauth2 response missing access token (field={cfg.get('token_field', 'access_token')})")
        self._cached_token = token
        mat = AuthMaterial()
        mat.headers[cfg.get("header", "Authorization")] = f"{cfg.get('prefix', 'Bearer')} {token}".strip()
        return mat

    # -- csrf -------------------------------------------------------------- #
    def _materialize_csrf(self, timeout_s: float, verify_tls: bool) -> AuthMaterial:
        import requests  # lazy

        cfg = self.config
        url = cfg.get("bootstrap_url")
        if not url:
            raise AuthError("csrf auth requires 'bootstrap_url'")
        sess = requests.Session()
        resp = sess.get(url, timeout=timeout_s, verify=verify_tls,
                        headers=cfg.get("bootstrap_headers", {}) or {})
        if resp.status_code >= 400:
            raise AuthError(f"csrf bootstrap failed: HTTP {resp.status_code}")
        source_json: Any = None
        try:
            source_json = resp.json()
        except ValueError:
            source_json = None
        token = _extract_value(resp.text, source_json, cfg.get("extract", {}))
        if not token:
            raise AuthError("csrf token not found in bootstrap response (check extract path/regex)")
        mat = AuthMaterial()
        # Carry any session cookies set during bootstrap.
        for c in sess.cookies:
            mat.cookies[c.name] = c.value
        into_header = cfg.get("into_header")
        into_var = cfg.get("into_var", "CSRF_TOKEN")
        if into_header:
            mat.headers[into_header] = token
        mat.body_vars[into_var] = token
        return mat

    # -- derived_multihop -------------------------------------------------- #
    def _materialize_multihop(self, timeout_s: float, verify_tls: bool) -> AuthMaterial:
        import requests  # lazy

        cfg = self.config
        steps: List[Dict[str, Any]] = cfg.get("steps") or []
        if not steps:
            raise AuthError("derived_multihop auth requires a non-empty 'steps' list")

        sess = requests.Session()
        variables: Dict[str, str] = {}
        # Seed variables from any env-backed inputs declared up front.
        for name, ref in (cfg.get("inputs") or {}).items():
            variables[name] = resolve_secret_ref(ref, allow_literal=True)

        for i, step in enumerate(steps):
            method = step.get("method", "POST").upper()
            url = _render_vars(step.get("url", ""), variables)
            if not url:
                raise AuthError(f"derived_multihop step {i} missing 'url'")
            headers = _render_vars(step.get("headers", {}) or {}, variables)
            json_body = _render_vars(step.get("json"), variables) if step.get("json") is not None else None
            data_body = _render_vars(step.get("data"), variables) if step.get("data") is not None else None

            resp = sess.request(method, url, headers=headers, json=json_body,
                                data=data_body, timeout=timeout_s, verify=verify_tls)
            if resp.status_code >= 400:
                raise AuthError(f"derived_multihop step {i} ({url}) failed: HTTP {resp.status_code}")
            source_json: Any = None
            try:
                source_json = resp.json()
            except ValueError:
                source_json = None
            for ex in step.get("extract", []) or []:
                var = ex.get("var")
                if not var:
                    raise AuthError(f"derived_multihop step {i} extract entry missing 'var'")
                val = _extract_value(resp.text, source_json, ex)
                if val is None:
                    raise AuthError(f"derived_multihop step {i} could not extract {var!r}")
                variables[var] = val

        # Final material: render the downstream attach spec with the variables.
        attach = cfg.get("attach", {}) or {}
        mat = AuthMaterial()
        mat.headers = _render_vars(attach.get("headers", {}) or {}, variables)
        mat.cookies = _render_vars(attach.get("cookies", {}) or {}, variables)
        mat.params = _render_vars(attach.get("params", {}) or {}, variables)
        # Also carry session cookies picked up along the way.
        for c in sess.cookies:
            mat.cookies.setdefault(c.name, c.value)
        mat.body_vars = variables
        # Best-effort: remember a bearer-ish token for lifecycle checks.
        for hv in mat.headers.values():
            if isinstance(hv, str) and hv.lower().startswith("bearer "):
                self._cached_token = hv.split(" ", 1)[1]
                break
        return mat


# --------------------------------------------------------------------------- #
# Auth lifecycle (Layer 3)                                                    #
# --------------------------------------------------------------------------- #
def _jwt_exp(token: Optional[str]) -> Optional[int]:
    """Return the ``exp`` (unix seconds) from a JWT without verifying it.

    Pure/no-network: base64url-decodes the middle segment and reads ``exp``.
    Returns ``None`` for anything that is not a well-formed JWT with an ``exp``.
    """
    if not token or token.count(".") != 2:
        return None
    payload_b64 = token.split(".")[1]
    padding = "=" * (-len(payload_b64) % 4)
    try:
        raw = base64.urlsafe_b64decode(payload_b64 + padding)
        claims = json.loads(raw)
    except (binascii.Error, ValueError, TypeError):
        return None
    exp = claims.get("exp")
    return int(exp) if isinstance(exp, (int, float)) else None


class AuthLifecycle:
    """Layer 3: decide *when* credentials must be refreshed / re-acquired.

    Kinds:

    ``static``
        Long-lived secret; :meth:`needs_refresh` is always False.
    ``refresh_on_ttl``
        Refresh once a fixed ``ttl_s`` has elapsed since the last refresh, or
        (when handed a JWT) once the token's ``exp`` is within ``skew_s``.
    ``reauth_on_401``
        :meth:`should_reauth` returns True when a response status matches the
        configured challenge (default 401), so the caller re-runs auth + retries.
    ``cookie_rotation``
        Refresh on a fixed ``interval_s``, and whenever a response delivers a new
        ``Set-Cookie`` (tracked via :meth:`note_response`).

    All decisions are pure functions of the config plus the small amount of state
    fed in via :meth:`mark_refreshed` / :meth:`note_response`. No network here.
    """

    KINDS = ("static", "refresh_on_ttl", "reauth_on_401", "cookie_rotation")

    def __init__(self, lifecycle_config: Optional[Dict[str, Any]]) -> None:
        cfg = lifecycle_config or {"type": "static"}
        self.kind: str = cfg.get("type", "static")
        if self.kind not in self.KINDS:
            raise AuthError(f"unknown auth_lifecycle type {self.kind!r}; valid={self.KINDS}")
        self.config = cfg
        self.ttl_s: Optional[float] = cfg.get("ttl_s")
        self.skew_s: float = float(cfg.get("skew_s", 30))
        self.interval_s: Optional[float] = cfg.get("interval_s")
        self.challenge_statuses = set(cfg.get("challenge_statuses", [401])) \
            if self.kind == "reauth_on_401" else set()
        self._last_refresh: Optional[float] = None
        self._cookie_dirty: bool = False
        self._token: Optional[str] = None

    @classmethod
    def from_config(cls, config: Optional[Dict[str, Any]]) -> "AuthLifecycle":
        """Build from a *full* adapter config (reads ``auth_lifecycle``)."""
        block = (config or {}).get("auth_lifecycle") if config else None
        if block is None and config is not None and "type" in (config or {}):
            block = config
        return cls(block)

    def mark_refreshed(self, *, token: Optional[str] = None, now: Optional[float] = None) -> None:
        """Record that credentials were just (re)acquired."""
        self._last_refresh = now if now is not None else time.time()
        self._cookie_dirty = False
        if token is not None:
            self._token = token

    def note_response(self, status_code: int, headers: Optional[Dict[str, str]] = None) -> None:
        """Feed a live response back in (for cookie-rotation detection)."""
        if self.kind == "cookie_rotation" and headers:
            # Case-insensitive Set-Cookie check.
            if any(k.lower() == "set-cookie" for k in headers):
                self._cookie_dirty = True

    def should_reauth(self, status_code: int) -> bool:
        """True if this response status is an auth challenge to retry after re-auth."""
        return self.kind == "reauth_on_401" and status_code in self.challenge_statuses

    def needs_refresh(self, *, now: Optional[float] = None) -> bool:
        """True if credentials should be refreshed before the next request."""
        now = now if now is not None else time.time()
        if self.kind == "static":
            return False
        if self.kind == "reauth_on_401":
            return False  # driven by should_reauth() on the response path
        if self.kind == "refresh_on_ttl":
            # Prefer a concrete JWT exp when we have one.
            exp = _jwt_exp(self._token)
            if exp is not None:
                return now >= (exp - self.skew_s)
            if self._last_refresh is None:
                return True  # never acquired yet
            if self.ttl_s is None:
                return False
            return (now - self._last_refresh) >= self.ttl_s
        if self.kind == "cookie_rotation":
            if self._cookie_dirty:
                return True
            if self._last_refresh is None:
                return True
            if self.interval_s is None:
                return False
            return (now - self._last_refresh) >= self.interval_s
        return False  # pragma: no cover
