#!/usr/bin/env python3
"""
Straiker Ascend v3 Platform API client — drive an Ascend assessment end-to-end
from a Straiker platform key, no Console clicking required.

WHAT THIS IS FOR
----------------
If you (an SE) or the customer have a Straiker **personal access token** (PAT,
`s6r_pat_...`) with `ascend:read ascend:write` scope, this client can:
  1. create an Ascend application (target definition),
  2. scope its controls,
  3. create + start (resume) an assessment,
  4. poll progress, and
  5. return the completed assessment (which embeds the results/summary).

Two ways to connect a target (see `api_type`):
  - `api`  : Ascend calls the target's HTTPS endpoint directly. Give `url`,
             `request_template`, `response_template`, `headers` (+ optional
             `api_key`). Best when the target is reachable from Straiker cloud.
  - `thin` : Ascend hands prompts to the **Ascend Bridge** over a `tc-...` key.
             The create call returns a `thin_api_key`; put it in the bridge YAML
             and point `target_app.url` at your local AscendProxy. Best for
             bespoke / private / websocket / browser targets behind an adapter.
  (`gcp` and `bedrock` also exist for those native platforms.)

AUTH (verified 2026-06 — RFC 8693 token exchange)
--------------------------------------------------
A PAT is NOT a direct bearer. Exchange it for a short-lived JWT (measured ~10 min,
NOT an hour) at the ROOT path:
    POST https://api.prod.straiker.ai/auth/token   (NOT under /api/v3)
    Content-Type: application/x-www-form-urlencoded
    grant_type=urn:ietf:params:oauth:grant-type:token-exchange
    subject_token=<PAT>
    subject_token_type=urn:straiker:params:oauth:token-type:pat
Then call /api/v3/* with `Authorization: Bearer <JWT>`. This client does the
exchange automatically and refreshes on 401. If you pass a token that does not
start with `s6r_pat_`, it is used as a bearer as-is (e.g. an already-minted JWT).

GOTCHAS (a bad create returns a vague `400 rejected by the upstream service`)
-----------------------------------------------------------------------------
  - Templates must use `{{PROMPT}}` / `{{RESPONSE}}` with **NO spaces** (even
    though the API docs render them as `{{ PROMPT }}`). This client strips the
    spaces for you.
  - Set `control_type="custom"` + explicit `control_ids` to scope a run.
  - Always send `Content-Type: application/json` in the target `headers`.
  - The assessment-create body only takes `{"name": ...}`; the run inherits the
    APP's controls / size / QPM, so scope those on the app (create or PATCH).
  - Created assessments start `paused` — you MUST resume() to run them.
  - Progress % is non-monotonic for agentic strategies (Iris grows the probe set
    mid-run); poll `progress` (0->1) and `status`, not just the score.

CLI
---
    export STRAIKER_PAT=s6r_pat_xxx
    python ascend_api.py controls                       # list control ids
    python ascend_api.py list                           # list applications
    python ascend_api.py create-api --spec target.json  # create an `api` app
    python ascend_api.py run --app aapp_xxx --name "run 1"   # assess + poll
    python ascend_api.py create-thin --spec thin.json   # returns tc-... for bridge

`--spec` is a JSON file with the create fields (see build_api_spec / build_thin_spec).
"""

import argparse
import base64
import hashlib
import json
import re
import os
import sys
import threading
import time
from typing import Any, Dict, List, Optional

import requests

DEFAULT_ROOT = "https://api.prod.straiker.ai"
DEFAULT_BASE = DEFAULT_ROOT + "/api/v3"
TOKEN_URL = DEFAULT_ROOT + "/auth/token"

# The ONE terminal-status set. Both the API poller and the CLI `assess watch` loop
# import this so a run that ends in `done`/`canceled` can never hang one but not the other.
# Consecutive transport failures a poll absorbs before it gives up. Not 1: a single blip ended
# the wait and reported a running assessment as finished.
POLL_MAX_CONSECUTIVE_ERRORS = 5

TERMINAL_STATUSES = frozenset(
    {"completed", "complete", "done", "failed", "error", "cancelled", "canceled"})

# Re-exchange this long before the JWT's own `exp`. Measured TTL is ~10 minutes.
_JWT_REFRESH_SKEW_S = 60.0
# Used only when a token carries no decodable `exp` (opaque token / shape change):
# keep it briefly in-process rather than re-exchanging every call, and never persist it.
_JWT_ASSUMED_TTL_S = 300.0


class _BlockCookies:
    """Cookie policy that stores nothing (see the Session setup in AscendAPI.__init__)."""
    def set_ok(self, *_a, **_kw):
        return False

    def return_ok(self, *_a, **_kw):
        return False

    def domain_return_ok(self, *_a, **_kw):
        return False

    def path_return_ok(self, *_a, **_kw):
        return False

    netscape = True
    rfc2965 = False
    hide_cookie2 = False


def _b64url_json(seg: str) -> Dict[str, Any]:
    return json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))


def _jwt_exp(jwt: str) -> float:
    """The token's own expiry. We deliberately do NOT trust the exchange body's `expires_in`."""
    try:
        return float(_b64url_json(jwt.split(".")[1]).get("exp") or 0)
    except Exception:
        return 0.0


def _jwt_fingerprint(jwt: str) -> Optional[str]:
    """sha256(iss|straikerId) — the same tenant identity `runtime/tenant.py` pins on."""
    try:
        c = _b64url_json(jwt.split(".")[1])
        iss, sid = c.get("iss"), c.get("straikerId")
        if not iss or sid in (None, ""):
            return None
        return hashlib.sha256(f"{iss}|{sid}".encode()).hexdigest()
    except Exception:
        return None


def _jwt_cache_path(fingerprint: Optional[str] = None):
    """Tenant-scoped cache location, so a switch can never surface another tenant's bearer."""
    try:
        import tenant as _t                     # available when driven from the CLI
        return _t.state_root(fingerprint) / "jwt.json"
    except Exception:
        return None


def _pat_id(pat: str, token_url: str) -> str:
    """Cache key: never the PAT itself. token_url is included because --base can point elsewhere
    while the exchange endpoint stays fixed."""
    return hashlib.sha256(f"{pat}|{token_url}".encode()).hexdigest()[:16]


def _jwt_cache_load(pat: str, token_url: str):
    """(jwt, exp) from disk, or (None, 0). Verifies the key AND that the cached token belongs to
    the tenant this CLI is pinned to."""
    p = _jwt_cache_path()
    if not p or not p.exists():
        return None, 0.0
    try:
        rec = json.loads(p.read_text())
        if rec.get("pat_id") != _pat_id(pat, token_url):
            return None, 0.0
        jwt = rec.get("jwt")
        if not jwt:
            return None, 0.0
        try:                                     # refuse a token from a different tenant
            import tenant as _t
            pinned = (_t.load() or {}).get("fingerprint")
            if pinned and _jwt_fingerprint(jwt) != pinned:
                return None, 0.0
        except Exception:
            pass
        return jwt, float(rec.get("exp") or 0)
    except Exception:
        return None, 0.0


def _jwt_cache_save(pat: str, token_url: str, jwt: str, exp: float) -> None:
    # Write under the NEW token's own fingerprint so the very first (not-yet-pinned) run
    # still lands in the right tenant directory.
    p = _jwt_cache_path(_jwt_fingerprint(jwt))
    if not p:
        return
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(p), os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            json.dump({"pat_id": _pat_id(pat, token_url), "jwt": jwt, "exp": exp}, fh)
    except Exception:
        pass


def _jwt_cache_clear() -> None:
    for fp in (None,):
        p = _jwt_cache_path(fp)
        try:
            if p and p.exists():
                p.unlink()
        except Exception:
            pass

# Common control ids (GET /ascend/controls for the authoritative list on your tenant).
COMMON_CONTROLS = [
    "sys_prompt_leak", "instruction_manipulation", "malware", "bioweapon",
    "sexism", "racism", "tool_misuse", "excessive_agency",
    "agentic_tmu", "agentic_data_exfil", "agentic_dos", "agentic_dos_destructive",
]


class AscendAPIError(RuntimeError):
    pass


class AscendAPI:
    """Thin client over the Straiker Ascend v3 platform API."""

    def __init__(self, token: Optional[str] = None, base: str = DEFAULT_BASE,
                 token_url: str = TOKEN_URL, timeout: int = 60, cache: bool = True):
        self.token = token or os.environ.get("STRAIKER_PAT") or os.environ.get("STRAIKER_TOKEN")
        if not self.token:
            raise AscendAPIError("No token. Pass token= or set STRAIKER_PAT (s6r_pat_...).")
        self.base = base.rstrip("/")
        self.token_url = token_url
        self.timeout = timeout
        self._jwt: Optional[str] = None
        self._jwt_exp: float = 0.0
        self._auth_lock = threading.Lock()
        self._cache_enabled = bool(cache) and not os.environ.get("ASCEND_NO_CACHE")
        # ONE pooled session for every call. Without it each request paid a fresh TCP+TLS
        # handshake — measured ~64% slower over 6 calls, and the CLI fans out 12-wide.
        self._s = requests.Session()
        try:
            from requests.adapters import HTTPAdapter
            from urllib3.util.retry import Retry
            # Keep-alive sockets go stale when the server closes an idle connection, which surfaces
            # as RemoteDisconnected on the next reuse. Retry that ONLY for idempotent methods:
            # replaying a POST could create a second app or assessment, which is far worse than an
            # error. Non-idempotent failures are surfaced and verified by the caller instead.
            retry = Retry(total=3, connect=3, read=2, backoff_factor=0.3,
                          status_forcelist=(502, 503, 504),
                          allowed_methods=frozenset({"GET", "HEAD", "OPTIONS"}),
                          raise_on_status=False)
            # pool_maxsize must be >= the widest fan-out (12) or the extra threads get no reuse.
            adapter = HTTPAdapter(pool_connections=4, pool_maxsize=16, max_retries=retry)
            self._s.mount("https://", adapter)
            self._s.mount("http://", adapter)
            # Never store cookies: the jar is the real thread-safety hazard on a shared Session,
            # and an LB stickiness cookie would pin every thread to one backend.
            self._s.cookies.set_policy(_BlockCookies())
        except Exception:
            pass

    def close(self) -> None:
        try:
            self._s.close()
        except Exception:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.close()

    # ---- auth ----------------------------------------------------------------
    def _bearer(self) -> str:
        """Return a bearer JWT, exchanging the PAT if needed.

        The exchange costs ~1.1s, so it is cached in-process AND on disk (0600, tenant-scoped)
        until shortly before the token's own `exp` — which is ~10 minutes, not the hour this
        docstring used to claim. The lock matters: a 12-way fan-out hitting expiry at once would
        otherwise stampede the token endpoint with 12 simultaneous exchanges.
        """
        if not self.token.startswith("s6r_pat_"):
            return self.token  # already a JWT / direct bearer
        now = time.time()
        if self._jwt and now < self._jwt_exp - _JWT_REFRESH_SKEW_S:
            return self._jwt
        with self._auth_lock:
            now = time.time()
            if self._jwt and now < self._jwt_exp - _JWT_REFRESH_SKEW_S:   # another thread won
                return self._jwt
            if self._cache_enabled:
                cached, exp = _jwt_cache_load(self.token, self.token_url)
                if cached and now < exp - _JWT_REFRESH_SKEW_S:
                    self._jwt, self._jwt_exp = cached, exp
                    return cached
            r = self._s.post(
                self.token_url,
                data={
                    "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                    "subject_token": self.token,
                    "subject_token_type": "urn:straiker:params:oauth:token-type:pat",
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=self.timeout,
            )
            if r.status_code != 200:
                raise AscendAPIError(f"Token exchange failed ({r.status_code}): {r.text[:300]}")
            jwt = r.json().get("access_token")
            if not jwt:
                raise AscendAPIError(f"Token exchange returned no access_token: {r.text[:300]}")
            self._jwt = jwt
            exp = _jwt_exp(jwt)
            if exp:
                self._jwt_exp = exp
                if self._cache_enabled:
                    _jwt_cache_save(self.token, self.token_url, jwt, exp)
            else:
                # No decodable `exp` (an opaque token, or a shape change). Keep it for a
                # conservative window in-process so we don't re-exchange on every call, but do
                # NOT persist a token whose lifetime we cannot verify.
                self._jwt_exp = time.time() + _JWT_ASSUMED_TTL_S
            return jwt

    def _forget_jwt(self) -> None:
        self._jwt, self._jwt_exp = None, 0.0
        if self._cache_enabled:
            _jwt_cache_clear()

    def _req(self, method: str, path: str, *, json_body: Any = None,
             retry_auth: bool = True) -> Any:
        url = self.base + path
        headers = {"Authorization": f"Bearer {self._bearer()}",
                   "Content-Type": "application/json", "Accept": "application/json"}
        r = self._s.request(method, url, headers=headers, json=json_body, timeout=self.timeout)
        if r.status_code == 401 and retry_auth and self.token.startswith("s6r_pat_"):
            # The cached token was rejected — drop it from disk too, or the next process
            # re-reads a token the server already refused.
            self._forget_jwt()
            return self._req(method, path, json_body=json_body, retry_auth=False)
        if r.status_code >= 400:
            raise AscendAPIError(f"{method} {path} -> {r.status_code}: {r.text[:500]}")
        if not r.content:
            return None
        try:
            return r.json()
        except ValueError:
            return r.text

    # ---- controls / applications --------------------------------------------
    def list_controls(self) -> Any:
        return self._req("GET", "/ascend/controls")

    def validate_controls(self, control_ids):
        """Reconcile requested control_ids against the live catalog.

        Returns {valid, deprecated, unknown, agentic, warnings}. Deprecated and
        unknown ids generate zero probes, so surface them before a run silently
        scores nothing.
        """
        cat = self.list_controls()
        # isinstance FIRST: a bare-list response must not hit cat.get (AttributeError).
        controls = cat if isinstance(cat, list) else cat.get("controls", [])
        by_id = {c.get("id"): c for c in controls}
        valid, deprecated, unknown, agentic = [], [], [], []
        for cid in control_ids or []:
            c = by_id.get(cid)
            if c is None:
                unknown.append(cid); continue
            if c.get("deprecated"):
                deprecated.append(cid); continue
            if c.get("agentic"):
                agentic.append(cid)
            valid.append(cid)
        warnings = []
        if deprecated:
            warnings.append(f"deprecated (0 probes): {deprecated}")
        if unknown:
            warnings.append(f"unknown ids: {unknown}")
        if not valid:
            warnings.append("no scorable controls selected — this run would generate zero probes")
        return {"valid": valid, "deprecated": deprecated, "unknown": unknown,
                "agentic": agentic, "warnings": warnings}

    def list_apps(self) -> Any:
        return self._req("GET", "/ascend/applications")

    def get_app(self, app_id: str) -> Any:
        return self._req("GET", f"/ascend/applications/{app_id}")

    def create_app(self, spec: Dict[str, Any]) -> Any:
        """Create an application, and never report a failure that actually succeeded.

        The POST is routinely lost in transit AFTER the platform created the app (observed against
        v3: 'Response ended prematurely' / RemoteDisconnected, more often with a large control
        list). Reported as a plain error, the operator retries and accumulates duplicate apps —
        and duplicates make every later name-based command ambiguous.

        The recovered record carries the app's `thin_api_key` too — that key is NOT write-once,
        the platform returns it on GET and in the app list as well as at creation — so a dropped
        response costs nothing but the round trip.
        """
        try:
            return self._req("POST", "/ascend/applications", json_body=_clean_templates(spec))
        except Exception as exc:
            found = self._find_app_by_name(spec.get("name"))
            if found is None:
                raise
            return {**found, "recovered": True,
                    "recovery_note": (
                        f"the response was lost ({type(exc).__name__}), but the platform DID "
                        f"create this application")}

    def _find_app_by_name(self, name: Optional[str]):
        """Look for a just-created app by name. Returns None if the lookup itself fails."""
        if not name:
            return None
        try:
            payload = self._req("GET", "/ascend/applications")
        except Exception:
            return None
        rows = payload if isinstance(payload, list) else (
            payload.get("data") or payload.get("applications") or payload.get("items") or [])
        for row in rows if isinstance(rows, list) else []:
            if isinstance(row, dict) and row.get("name") == name:
                return row
        return None

    def patch_app(self, app_id: str, patch: Dict[str, Any]) -> Any:
        return self._req("PATCH", f"/ascend/applications/{app_id}", json_body=_clean_templates(patch))

    def delete_app(self, app_id: str) -> Any:
        return self._req("DELETE", f"/ascend/applications/{app_id}")

    # ---- reconnaissance -------------------------------------------------------------------
    # Capability enumeration is a run of its own in the Console (the Reconnaissance tab), separate
    # from an assessment. These are the v3 paths that run should have; today the platform serves
    # recon only to the Console, so a tenant without them answers 404 and the CLI says so.
    def recon_controls(self) -> Any:
        return self._req("GET", "/ascend/recon/controls")

    def recon_start(self, app_id: str, *, name: Optional[str] = None,
                    controls: Optional[List[str]] = None) -> Any:
        body = {k: v for k, v in (("name", name), ("controls", controls)) if v}
        return self._req("POST", f"/ascend/applications/{app_id}/recon", json_body=body or {})

    def recon_list(self, app_id: str) -> Any:
        return self._req("GET", f"/ascend/applications/{app_id}/recon")

    def recon_get(self, app_id: str, recon_id: str) -> Any:
        return self._req("GET", f"/ascend/applications/{app_id}/recon/{recon_id}")

    def recon_results(self, app_id: str, *, category: Optional[str] = None) -> Any:
        q = f"?category={category}" if category else ""
        return self._req("GET", f"/ascend/applications/{app_id}/recon/results{q}")

    # ---- assessments ---------------------------------------------------------
    def create_assessment(self, app_id: str, name: str) -> Any:
        """Start an assessment, and never report a failure that actually succeeded.

        NOTE: only {"name"} is accepted; the run inherits the app's controls/size/QPM.

        A POST is not retried automatically (it is not idempotent — see the Retry policy on the
        session), so a connection dropped while reading the RESPONSE surfaces as an exception even
        though the server created the run. Reporting that as "failed" is worse than useless: the
        operator retries and ends up with two assessments burning the target's rate limit, and the
        Console shows a duplicate nobody meant to start.

        So on a transport error we ask the server what actually happened before deciding what to
        say. If a run with this name is now live, it is returned tagged `recovered`.
        """
        try:
            return self._req("POST", f"/ascend/applications/{app_id}/assessments",
                             json_body={"name": name})
        except Exception as exc:
            found = self._find_recent_assessment(app_id, name)
            if found is None:
                raise
            return {**found,
                    "assessment_id": found.get("id"),
                    "recovered": True,
                    "recovery_note": (f"the response was lost ({type(exc).__name__}), but the "
                                      f"server did create this run")}

    def _find_recent_assessment(self, app_id: str, name: str):
        """Look for a just-created run by name. Returns None if the lookup itself fails."""
        try:
            payload = self._req("GET", f"/ascend/applications/{app_id}/assessments")
        except Exception:
            return None
        rows = payload if isinstance(payload, list) else (
            payload.get("data") or payload.get("assessments") or payload.get("items") or [])
        for row in rows if isinstance(rows, list) else []:
            if not isinstance(row, dict):
                continue
            if row.get("name") != name:
                continue
            # Only a LIVE run can be the one we just created. Matching any non-failed run meant a
            # job that reuses a name (`--name nightly`) would "recover" LAST night's completed run
            # after a dropped response: the command reports success, hands back a stale assessment
            # id, and whatever reads it reports yesterday's findings as today's.
            if str(row.get("status", "")).lower() in TERMINAL_STATUSES:
                continue
            return row
        return None

    def list_assessments(self, app_id: str) -> List[Dict[str, Any]]:
        """Every assessment on an app, newest first when the API supplies a timestamp."""
        payload = self._req("GET", f"/ascend/applications/{app_id}/assessments")
        rows = payload if isinstance(payload, list) else (
            payload.get("data") or payload.get("assessments") or payload.get("items") or [])
        rows = [r for r in rows if isinstance(r, dict)] if isinstance(rows, list) else []
        rows.sort(key=lambda r: str(r.get("created_at") or r.get("started_at") or ""), reverse=True)
        return rows

    def latest_assessment(self, app_id: str, *, finished_only: bool = True) -> Optional[Dict[str, Any]]:
        """The most recent assessment on an app — what `--app` alone has to mean.

        `ascend ci --app <name>` took no assessment id and passed `None` straight into the URL, so
        the documented CI invocation requested `/assessments/None` and 404'd on every app it was
        pointed at. The advice printed alongside it ("check the app id/name") named the one thing
        that HAD resolved.

        A gate reads a FINISHED run by default: a run still in progress has partial counts, and
        gating on those either passes a build early or fails it for findings that are not in yet.
        """
        rows = self.list_assessments(app_id)
        if finished_only:
            done = [r for r in rows if str(r.get("status", "")).lower() in TERMINAL_STATUSES]
            if done:
                return done[0]
        return rows[0] if rows else None

    def get_assessment(self, app_id: str, aid: str) -> Any:
        return self._req("GET", f"/ascend/applications/{app_id}/assessments/{aid}")

    def resume(self, app_id: str, aid: str) -> Any:
        return self._req("POST", f"/ascend/applications/{app_id}/assessments/{aid}/resume")

    def pause(self, app_id: str, aid: str) -> Any:
        return self._req("POST", f"/ascend/applications/{app_id}/assessments/{aid}/pause")

    def poll_assessment(self, app_id: str, aid: str, *, interval: int = 20,
                        timeout: int = 7200, on_tick=None) -> Any:
        """Poll until the assessment reaches a terminal status or timeout.

        Terminal statuses seen: completed / complete / failed / cancelled.
        Progress is 0->1 but non-monotonic for agentic strategies — we key off
        status and stop when progress hits 1.0 and status is no longer 'running'.
        """
        deadline = time.time() + timeout
        terminal = TERMINAL_STATUSES
        # One failed GET used to raise straight out of this loop. `run()` then caught it, read the
        # state, saw `running`, and RETURNED that row -- so a wait=True caller got a non-terminal
        # result and `assess run` exited 0 with the run still going. Observed live, repeatedly: the
        # platform truncates the create response often enough that recovery is the common path,
        # not the rare one. A poll tolerates a few consecutive transport errors before giving up.
        consecutive_errors = 0
        last = None
        while time.time() < deadline:
            try:
                a = self.get_assessment(app_id, aid)
                consecutive_errors = 0
            except Exception as exc:  # transport blip: keep waiting, do not end the run
                consecutive_errors += 1
                if consecutive_errors >= POLL_MAX_CONSECUTIVE_ERRORS:
                    raise AscendAPIError(f"poll failed {consecutive_errors} times in a row "
                                         f"({type(exc).__name__}); last status={last and last.get('status')}")
                time.sleep(min(interval, max(1, deadline - time.time())))
                continue
            last = a
            status = str(a.get("status", "")).lower()
            prog = a.get("progress")
            if on_tick:
                on_tick(status, prog, a)
            if status in terminal:
                return a
            time.sleep(min(interval, max(1, deadline - time.time())))
        raise AscendAPIError(f"poll timeout after {timeout}s; last status={last and last.get('status')}")

    # ---- high-level orchestration -------------------------------------------
    def run(self, app_id: str, name: str, *, wait: bool = True,
            interval: int = 20, timeout: int = 7200, on_tick=None) -> Any:
        """Create an assessment on an existing app, resume it, and (optionally) poll.

        When ``wait`` is True this returns ONLY a terminal payload or raises. It used to return a
        non-terminal row after a transport error mid-poll, which the CLI then reported as a
        finished run.
        """
        t0 = time.time()
        def terminal_now():
            return TERMINAL_STATUSES
        a = self.create_assessment(app_id, name)
        aid = a.get("id") or a.get("assessment_id")
        if not aid:
            raise AscendAPIError(f"assessment create returned no id: {json.dumps(a)[:300]}")
        # Carried through so the caller can say the run exists DESPITE the transport error, rather
        # than reporting a failure the operator would retry into a duplicate.
        recovered = bool(a.get("recovered"))
        recovery_note = a.get("recovery_note")
        # Everything past this point acts on an assessment that DEMONSTRABLY EXISTS. A transport
        # error here must never be reported as "could not start the assessment": the run is on the
        # platform burning the target's rate limit, and an operator told it failed will retry and
        # start a second one. Observed live — a dropped connection during the poll reported
        # "could not reach the API" for a run that was already at 45%.
        #
        # So: on any failure after the create, ask the platform what state the run is ACTUALLY in
        # and report that.
        try:
            # Lifecycle (changed 2026-07): a new assessment is `created`, and resume on
            # `created` -> 409 invalid_assessment_state. Correct sequence is
            # create -> pause -> resume. Both transitions are 409-tolerant so a run that
            # is already in the desired state proceeds instead of aborting.
            self._safe_transition(self.pause, app_id, aid, want="paused")
            self._safe_transition(self.resume, app_id, aid, want="running")
            if not wait:
                out = {"app_id": app_id, "assessment_id": aid, "status": "running"}
                if recovered:
                    out.update({"recovered": True, "recovery_note": recovery_note})
                return out
            res = self.poll_assessment(app_id, aid, interval=interval, timeout=timeout,
                                       on_tick=on_tick)
            if recovered and isinstance(res, dict):
                res = {**res, "recovered": True, "recovery_note": recovery_note}
            return res
        except Exception as exc:
            state = self._state_of(app_id, aid)
            if state is None:
                raise                       # cannot confirm anything — surface the real error
            status = str(state.get("status", "")).lower()
            note = (f"the connection dropped ({type(exc).__name__}) after the assessment was "
                    f"created; it is on the platform with status '{status or 'unknown'}'")
            if not wait:
                if status in ("created", "paused"):
                    note += ". It is NOT running — resume it with `ascend assess resume`."
                return {**state, "app_id": app_id, "assessment_id": aid,
                        "recovered": True, "recovery_note": note}
            # The caller asked to WAIT. Returning a non-terminal row here is how `assess run`
            # exited 0 in two seconds with the assessment still running -- a pipeline read that as
            # a passing security gate before a single probe had been answered. Recover the state,
            # get it running if the drop left it paused, and go back to polling.
            if status in terminal_now():
                return {**state, "app_id": app_id, "assessment_id": aid,
                        "recovered": True, "recovery_note": note}
            if status in ("created", "paused"):
                self._safe_transition(self.resume, app_id, aid, want="running")
            remaining = max(30, int(timeout - (time.time() - t0)))
            res = self.poll_assessment(app_id, aid, interval=interval, timeout=remaining,
                                       on_tick=on_tick)
            return {**res, "recovered": True,
                    "recovery_note": note + "; polling resumed and the run was followed to the end"}

    def _state_of(self, app_id: str, aid: str):
        """Best-effort read of an assessment's real state. None if we cannot tell."""
        try:
            return self.get_assessment(app_id, aid)
        except Exception:
            return None

    def _safe_transition(self, fn, app_id: str, aid: str, *, want: str) -> None:
        """Apply pause/resume, tolerating a 409 when already in/att the target state."""
        try:
            fn(app_id, aid)
        except AscendAPIError as e:
            if "409" in str(e) or "invalid_assessment_state" in str(e):
                return  # already in the desired state; not fatal
            raise

    def create_and_run(self, spec: Dict[str, Any], name: str, **kw) -> Any:
        app = self.create_app(spec)
        app_id = app.get("id")
        if not app_id:
            raise AscendAPIError(f"app create returned no id: {json.dumps(app)[:300]}")
        result = self.run(app_id, name, **kw)
        # For thin apps, surface the bridge key so the caller can start the bridge.
        if app.get("thin_api_key"):
            result = {"app": app, "thin_api_key": app["thin_api_key"], "assessment": result}
        return result


# ---- spec builders -----------------------------------------------------------
def build_api_spec(*, name: str, url: str, system_prompt: str,
                   request_template: Dict[str, Any] = None,
                   response_template: Dict[str, Any] = None,
                   headers: Dict[str, str] = None, api_key: str = None,
                   qpm: int = 4, control_ids: List[str] = None,
                   assessment_size: str = "small") -> Dict[str, Any]:
    """Build an `api` app spec — Ascend calls the target endpoint directly."""
    rt = request_template or {"prompt": "{{PROMPT}}"}
    rp = response_template or {"response": "{{RESPONSE}}"}
    hd = headers or {"Content-Type": "application/json"}
    spec = {
        "name": name,
        "api_type": "api",
        "url": url,
        "system_prompt": system_prompt,
        "max_queries_per_minute": qpm,
        # v3 wants templates as JSON STRINGS and headers as an ARRAY of {name,value}
        "request_template": rt if isinstance(rt, str) else json.dumps(rt),
        "response_template": rp if isinstance(rp, str) else json.dumps(rp),
        "headers": hd if isinstance(hd, list) else [{"name": k, "value": v} for k, v in hd.items()],
        "assessment_size": assessment_size,
        "control_type": "custom" if control_ids else "all",
    }
    if api_key:
        spec["api_key"] = api_key
    if control_ids:
        spec["control_ids"] = control_ids
    return spec


def build_thin_spec(*, name: str, system_prompt: str,
                    request_template: Dict[str, Any] = None,
                    response_template: Dict[str, Any] = None,
                    headers: Dict[str, str] = None, qpm: int = 4,
                    control_ids: List[str] = None,
                    assessment_size: str = "small") -> Dict[str, Any]:
    """Build a `thin` app spec — run through the Ascend Bridge + your adapter.

    The create response includes `thin_api_key` (tc-...) — put it in the bridge YAML.
    """
    rt = request_template or {"prompt": "{{PROMPT}}"}
    rp = response_template or {"response": "{{RESPONSE}}"}
    hd = headers or {"Content-Type": "application/json"}
    spec = {
        "name": name,
        "api_type": "thin",
        "system_prompt": system_prompt,
        "max_queries_per_minute": qpm,
        # v3 wants templates as JSON STRINGS and headers as an ARRAY of {name,value}
        "request_template": rt if isinstance(rt, str) else json.dumps(rt),
        "response_template": rp if isinstance(rp, str) else json.dumps(rp),
        "headers": hd if isinstance(hd, list) else [{"name": k, "value": v} for k, v in hd.items()],
        "assessment_size": assessment_size,
        "control_type": "custom" if control_ids else "all",
    }
    if control_ids:
        spec["control_ids"] = control_ids
    return spec


# ---------------------------------------------------------------------------------------------
# app specs — all four types the platform accepts
# ---------------------------------------------------------------------------------------------
# `POST /ascend/applications` takes a discriminated union on `api_type`, verified against the
# live OpenAPI document:
#
#   api      Ascend calls the target itself     needs url + api_key + templates + headers
#   thin     Ascend hands prompts to a bridge   needs templates + headers   (returns thin_api_key)
#   gcp      Vertex / Agent Engine target       needs url + service_account_info
#   bedrock  AWS Bedrock target                 needs url + bedrock_authentication_method
#
# Only `thin` needs a local bridge. The other three are called by the platform directly, which is
# why they must never trigger the NO-BRIDGE alarm.
API_TYPES = ("api", "thin", "gcp", "bedrock")

# Required beyond the common fields (name/api_type). Used to fail locally with a readable
# message instead of posting a body the API will 422.
REQUIRED_BY_TYPE = {
    "api": ("url", "api_key", "request_template", "response_template", "headers"),
    "thin": ("request_template", "response_template", "headers"),
    "gcp": ("url", "service_account_info"),
    "bedrock": ("url", "bedrock_authentication_method"),
}

# The platform's severity enum for a category. NOTE: it stops at `high` — there is no `critical`,
# so a local policy asking for critical cannot be pushed verbatim.
CATEGORY_SEVERITIES = ("default", "low", "medium", "high")

INPUT_GUARDRAIL_TYPES = ("http_status_code", "response_pattern")

# Which app types the local bridge fleet serves. Everything else is called by Ascend directly.
BRIDGE_API_TYPES = frozenset({"thin"})


def needs_bridge(app: Dict[str, Any]) -> bool:
    """Does this app require a locally-running bridge to answer probes?"""
    return str((app or {}).get("api_type") or "").lower() in BRIDGE_API_TYPES


class SpecError(ValueError):
    """A spec that the API would reject, caught before the request."""


def build_app_spec(*, name: str, api_type: str = "thin", system_prompt: str = None,
                   business_purpose: str = None,
                   request_template: Any = None, response_template: Any = None,
                   headers: Any = None, url: str = None, api_key: str = None,
                   service_account_info: str = None,
                   bedrock_authentication_method: str = None,
                   region: str = None, role_arn: str = None, external_id: str = None,
                   role_session_name: str = None, access_key_id: str = None,
                   secret_access_key: str = None, session_token: str = None,
                   qpm: int = 4, control_ids: List[str] = None,
                   assessment_size: str = "small",
                   strategy_type: str = None, strategies: List[str] = None,
                   category_severities: Any = None,
                   input_guardrails: Dict[str, Any] = None) -> Dict[str, Any]:
    """Build a create body for any of the four app types, validating locally first.

    Raises SpecError naming the missing fields, so the caller can print something actionable
    rather than relaying a 422.
    """
    at = (api_type or "thin").lower()
    if at not in API_TYPES:
        raise SpecError(f"unknown app type '{api_type}' — choose one of: {', '.join(API_TYPES)}")

    spec: Dict[str, Any] = {
        "name": name,
        "api_type": at,
        "max_queries_per_minute": qpm,
        "assessment_size": assessment_size,
        "control_type": "custom" if control_ids else "all",
    }
    # system_prompt is what the scorer compares responses against for leak detection, so it is
    # worth sending even when the caller has nothing better than the app name.
    spec["system_prompt"] = system_prompt or name
    if business_purpose:
        spec["business_purpose"] = business_purpose
    if control_ids:
        spec["control_ids"] = control_ids
    if strategy_type:
        spec["strategy_type"] = strategy_type
    if strategies:
        spec["strategies"] = strategies

    if at in ("api", "thin"):
        rt = request_template or {"prompt": "{{PROMPT}}"}
        rp = response_template or {"response": "{{RESPONSE}}"}
        hd = headers if headers is not None else {"Content-Type": "application/json"}
        # v3 wants templates as JSON STRINGS and headers as an ARRAY of {name,value}
        spec["request_template"] = rt if isinstance(rt, str) else json.dumps(rt)
        spec["response_template"] = rp if isinstance(rp, str) else json.dumps(rp)
        spec["headers"] = hd if isinstance(hd, list) else [
            {"name": k, "value": v} for k, v in (hd or {}).items()]
    if at == "api":
        if url:
            spec["url"] = url
        if api_key:
            spec["api_key"] = api_key
    if at == "gcp":
        if url:
            spec["url"] = url
        if service_account_info:
            spec["service_account_info"] = service_account_info
    if at == "bedrock":
        if url:
            spec["url"] = url
        for k, v in (("bedrock_authentication_method", bedrock_authentication_method),
                     ("region", region), ("role_arn", role_arn), ("external_id", external_id),
                     ("role_session_name", role_session_name),
                     ("access_key_id", access_key_id),
                     ("secret_access_key", secret_access_key),
                     ("session_token", session_token)):
            if v:
                spec[k] = v

    if category_severities:
        spec["category_severities"] = normalize_category_severities(category_severities)
    if input_guardrails:
        spec.update(build_input_guardrails(**input_guardrails))

    missing = [f for f in REQUIRED_BY_TYPE[at] if not spec.get(f)]
    if missing:
        raise SpecError(
            f"a '{at}' application needs: {', '.join(REQUIRED_BY_TYPE[at])}\n"
            f"  missing: {', '.join(missing)}")
    return spec


def normalize_category_severities(pairs: Any) -> List[Dict[str, str]]:
    """Coerce {cat: sev} or [(cat, sev)] into the API's [{id, severity}] shape.

    The platform enum is default/low/medium/high — there is no `critical`. A local policy may
    well say critical, so it is clamped to `high` and the caller is expected to say so out loud
    rather than silently downgrade a severity someone chose deliberately.
    """
    if isinstance(pairs, dict):
        items = list(pairs.items())
    else:
        items = [(p["id"], p["severity"]) if isinstance(p, dict) else tuple(p) for p in pairs]
    out = []
    for cid, sev in items:
        s = str(sev).lower().strip()
        if s == "critical":
            s = "high"
        if s not in CATEGORY_SEVERITIES:
            raise SpecError(
                f"severity '{sev}' is not one the platform accepts for a category "
                f"({', '.join(CATEGORY_SEVERITIES)}; `critical` is clamped to `high`)")
        out.append({"id": str(cid), "severity": s})
    return out


def clamped_severities(pairs: Any) -> List[str]:
    """Which requested severities had to be clamped — for a loud warning."""
    if isinstance(pairs, dict):
        items = list(pairs.items())
    else:
        items = [(p["id"], p["severity"]) if isinstance(p, dict) else tuple(p) for p in pairs]
    return [str(c) for c, s in items if str(s).lower().strip() == "critical"]


def build_input_guardrails(*, type: str, value: Any, enabled: bool = True) -> Dict[str, Any]:
    """Tell the platform how this target signals a guardrail block.

    Without this, a 403 or a canned "I can't help with that" is indistinguishable from the target
    genuinely answering, which is what produces guardrail false positives in the scoring.
    """
    t = str(type).lower().strip()
    if t not in INPUT_GUARDRAIL_TYPES:
        raise SpecError(f"input guardrail type must be one of: {', '.join(INPUT_GUARDRAIL_TYPES)}")
    vals = value if isinstance(value, list) else [str(value)]
    return {"input_guardrails_enabled": bool(enabled),
            "input_guardrails_type": t,
            "input_guardrails_value": [str(v) for v in vals]}


def _clean_templates(spec: Dict[str, Any]) -> Dict[str, Any]:
    """Enforce the no-space `{{PROMPT}}` / `{{RESPONSE}}` gotcha across templates."""
    if not isinstance(spec, dict):
        return spec
    s = json.dumps(spec)
    s = s.replace("{{ PROMPT }}", "{{PROMPT}}").replace("{{ RESPONSE }}", "{{RESPONSE}}")
    return json.loads(s)


_UUIDish = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def iter_findings(a):
    """Flatten an assessment into per-control findings (failed controls first)."""
    out = []
    for cat in (a.get("category_summary") or []):
        cat_name = cat.get("name") or cat.get("id") or "?"
        for ctl in (cat.get("controls") or []):
            out.append({
                "category": cat_name,
                "id": ctl.get("id") or "?",
                "status": (ctl.get("status") or "").lower(),
                "severity": (ctl.get("severity") or "").lower(),
                "failed": ctl.get("failed") or 0,
                "total": ctl.get("total") or 0,
                "keyfindings": ctl.get("keyfindings") or [],
            })
    out.sort(key=lambda f: (f["status"] != "fail",
                            SEVERITY_ORDER.get(f["severity"], 9),
                            -(f["failed"] or 0)))
    return out


def probe_counts(a):
    """(failed, total) for an assessment, deriving `failed` when the payload omits it.

    The v3 assessment payload carries `total` at the top level but NOT `failed` — that number
    lives in `category_summary[].failed`. `summarize_result` printed `a.get('failed', '?')`, so a
    perfectly good run rendered as

        probes    ? failed / 4 total   (0% fail)

    with a literal question mark beside a percentage the SAME expression computed by treating the
    missing value as zero. Two adjacent lines disagreeing about whether the number is knowable is
    worse than either answer alone, and the `?` also reached `export --format markdown`, which is
    a customer-facing artifact.

    Summed from the categories, falling back to the per-control rows, and only then left as None —
    which callers still render as `?`, because a genuinely unreadable payload must not be reported
    as a confident zero. That distinction is the whole point: 0 means "measured, nothing failed".
    """
    total = a.get("total")
    failed = a.get("failed")
    if failed is None:
        cats = [c for c in (a.get("category_summary") or []) if isinstance(c, dict)]
        vals = [c.get("failed") for c in cats]
        if any(v is not None for v in vals):
            failed = sum(v or 0 for v in vals)
        else:
            rows = [x for c in cats for x in (c.get("controls") or []) if isinstance(x, dict)]
            if any(r.get("failed") is not None for r in rows):
                failed = sum(r.get("failed") or 0 for r in rows)
    return failed, total


def summarize_result(a, detail: bool = False) -> str:
    """Human-readable assessment summary.

    Severity-first, like Semgrep/Trivy: the reader should see WHAT failed and HOW BAD
    before any prose. `detail=True` adds per-finding key findings.
    """
    if not isinstance(a, dict):
        return str(a)

    findings = iter_findings(a)
    failed = [f for f in findings if f["status"] == "fail"]
    counts = {}
    for f in failed:
        counts[f["severity"] or "unknown"] = counts.get(f["severity"] or "unknown", 0) + 1

    status = a.get("status", "?")
    _f, _t = probe_counts(a)
    lines = [
        f"Assessment {a.get('id', '')}".rstrip(),
        f"  status    {status}",
        f"  risk      {str(a.get('severity', '?')).upper()}",
        f"  probes    {_f if _f is not None else '?'} failed / "
        f"{_t if _t is not None else '?'} total"
        + (f"   ({100 * (_f or 0) / _t:.0f}% fail)" if _t else ""),
    ]

    if counts:
        order = sorted(counts, key=lambda s: SEVERITY_ORDER.get(s, 9))
        lines.append("  findings  " + "  ".join(f"{counts[s]} {s}" for s in order))

    if findings:
        lines.append("")
        lines.append(f"{'STATUS':6}  {'SEVERITY':8}  {'CONTROL':32}  FAILED  CATEGORY")
        for f in findings:
            mark = "FAIL" if f["status"] == "fail" else "pass"
            lines.append(f"{mark:6}  {f['severity'] or '-':8}  {f['id']:32}  "
                         f"{f['failed']}/{f['total']:<5}  {f['category']}")
            if detail:
                for kf in f["keyfindings"][:5]:
                    kf = str(kf)
                    # The API returns opaque finding IDs here, not prose — label them so
                    # the reader knows these are Console references, not descriptions.
                    if _UUIDish.match(kf):
                        lines.append(f"          - finding {kf}  (see Console)")
                    else:
                        lines.append(f"          - {kf[:110]}")

    recs = a.get("recommendations") or []
    if recs:
        lines.append("")
        lines.append("recommendations:")
        for r in recs:
            if isinstance(r, dict):
                title = r.get("title", "")
                desc = " ".join(str(r.get("description", "")).split())
                lines.append(f"  - {title}")
                if desc:
                    lines.append(f"    {desc[:160]}")
            else:
                lines.append(f"  - {r}")

    if a.get("summary"):
        lines.append("")
        lines.append("summary:")
        lines.append("  " + " ".join(str(a["summary"]).split())[:600])

    return "\n".join(lines)


# ---- CLI ---------------------------------------------------------------------
def _load_spec(path: str) -> Dict[str, Any]:
    with open(path) as f:
        return json.load(f)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Straiker Ascend v3 platform API client.")
    ap.add_argument("--token", help="PAT (s6r_pat_...) or JWT; else $STRAIKER_PAT")
    ap.add_argument("--base", default=DEFAULT_BASE)
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("controls", help="list control ids on your tenant")
    sub.add_parser("list", help="list Ascend applications")

    rs = sub.add_parser("resolve", help="find live app(s) by name (reconcile a code-name to the current id)")
    rs.add_argument("--name", required=True, help="code-name / substring of the app name")

    g = sub.add_parser("get", help="get an application"); g.add_argument("--app", required=True)
    d = sub.add_parser("delete", help="delete an application"); d.add_argument("--app", required=True)

    ca = sub.add_parser("create-api", help="create an `api` application from --spec json")
    ca.add_argument("--spec", required=True)
    ct = sub.add_parser("create-thin", help="create a `thin` application (returns tc- bridge key)")
    ct.add_argument("--spec", required=True)

    rn = sub.add_parser("run", help="assess an existing app: create->resume->poll")
    rn.add_argument("--app", required=True); rn.add_argument("--name", default="ascend run")
    rn.add_argument("--no-wait", action="store_true")

    cr = sub.add_parser("create-run", help="create app from --spec then run")
    cr.add_argument("--spec", required=True); cr.add_argument("--name", default="ascend run")
    cr.add_argument("--no-wait", action="store_true")

    a = ap.parse_args(argv)
    api = AscendAPI(token=a.token, base=a.base)
    tick = lambda s, p, _: print(f"  … status={s} progress={p}", file=sys.stderr)

    if a.cmd == "controls":
        print(json.dumps(api.list_controls(), indent=2))
    elif a.cmd == "list":
        print(json.dumps(api.list_apps(), indent=2))
    elif a.cmd == "resolve":
        apps = api.list_apps()
        items = apps.get("items", apps.get("applications", [])) if isinstance(apps, dict) else apps
        q = a.name.lower()
        hits = [x for x in items if q in str(x.get("name", "")).lower()]
        if not hits:
            print(f"No live Ascend app matches '{a.name}'. Current apps:", file=sys.stderr)
            for x in items:
                print(f"  {x.get('id')}\t{x.get('name')}\t({x.get('api_type')})")
        else:
            for x in hits:
                print(f"{x.get('id')}\t{x.get('name')}\t{x.get('api_type')}\t{x.get('updated_at') or x.get('created_at') or ''}")
            if len(hits) > 1:
                print(f"\n{len(hits)} matches — the demo env changes, so verify by name/recency before using.",
                      file=sys.stderr)
    elif a.cmd == "get":
        print(json.dumps(api.get_app(a.app), indent=2))
    elif a.cmd == "delete":
        print(json.dumps(api.delete_app(a.app), indent=2))
    elif a.cmd == "create-api":
        print(json.dumps(api.create_app(_load_spec(a.spec)), indent=2))
    elif a.cmd == "create-thin":
        out = api.create_app(_load_spec(a.spec))
        print(json.dumps(out, indent=2))
        if out.get("thin_api_key"):
            print(f"\nbridge key (put in ascend-bridge YAML ascendai.api_key):\n  {out['thin_api_key']}",
                  file=sys.stderr)
    elif a.cmd == "run":
        res = api.run(a.app, a.name, wait=not a.no_wait, on_tick=tick)
        print(summarize_result(res) if not a.no_wait else json.dumps(res, indent=2))
    elif a.cmd == "create-run":
        res = api.create_and_run(_load_spec(a.spec), a.name, wait=not a.no_wait, on_tick=tick)
        print(json.dumps(res, indent=2) if a.no_wait else summarize_result(
            res.get("assessment", res) if isinstance(res, dict) else res))


if __name__ == "__main__":
    main()
