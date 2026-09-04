"""
test_auth_runtime_fixes.py — three defects in the auth runtime that were wired but wrong.

These are the parts of `runtime/layers/auth.py` / `call_target.py` that DID run, and ran
incorrectly. Found while mapping the auth architecture for the `target add` parity work:

1. **The JWT-`exp` refresh branch was dead in production.** `AuthProvider.token` has always
   recorded the token it obtained, and `AuthLifecycle.needs_refresh()` has always preferred a
   real JWT `exp` over the wall-clock `ttl_s` guess — but `call_target.py` called
   `mark_refreshed()` without `token=` at both refresh points, so `AuthLifecycle._token` was
   `None` for every run and the accurate branch never executed. A short-lived JWT refreshed late.
   `merge_auth` now stamps the provider's token onto the merged config as `_auth_token`, and both
   call sites hand it to the lifecycle.

2. **`oauth2.extra` bypassed `resolve_secret_ref`.** Values were merged into the token POST raw —
   the one place in the file a secret could be written inline and reach the wire, contradicting
   the rule in the module header. `env:`/`literal:` refs are now resolved; bare strings still pass
   through, because `extra` legitimately carries non-secret parameters (audience, resource).

3. **A non-JSON 2xx from the token endpoint raised a bare decode error.** Every other auth
   failure surfaces as a one-line `AuthError` annotation; this one produced a traceback.

On mocking: the offline suite mocks transport by design (`tests/conftest.py`: "No sockets"), and
these tests stub `requests.post` to reach ERROR PATHS a live endpoint cannot be asked to produce.
They are cheap regression guards. The gate that proves the materializers talk to something real
is `scripts/live_matrix.py` against `agent-forge`, and it is run by hand before a release.
"""
import re
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
for p in ("runtime", "control"):
    sys.path.insert(0, str(REPO / p))
from layers import auth as A          # noqa: E402
import dispatch                        # noqa: E402

CT = (REPO / "runtime" / "call_target.py").read_text()
DP = (REPO / "runtime" / "dispatch.py").read_text()


class _Resp:
    def __init__(self, status=200, text="", payload=None):
        self.status_code, self.text, self._payload = status, text, payload

    def json(self):
        if self._payload is None:
            raise ValueError("not json")
        return self._payload


def _oauth(monkeypatch, resp, **extra_cfg):
    import requests
    seen = {}
    def fake_post(url, data=None, **kw):
        seen["url"], seen["data"] = url, dict(data or {})
        return resp
    monkeypatch.setattr(requests, "post", fake_post)
    monkeypatch.setenv("CID", "client-1")
    monkeypatch.setenv("CSEC", "s3cret")
    cfg = {"type": "oauth2", "grant": "client_credentials", "token_url": "https://idp/token",
           "client_id_ref": "env:CID", "client_secret_ref": "env:CSEC", **extra_cfg}
    return A.AuthProvider(cfg), seen


class TestTheTokenReachesTheLifecycle:
    def test_merge_auth_stamps_the_token_it_obtained(self, monkeypatch):
        prov, _ = _oauth(monkeypatch, _Resp(payload={"access_token": "tok-123"}))
        monkeypatch.setattr(A, "AuthProvider", lambda block: prov)
        merged = dispatch.merge_auth({"auth": {"type": "oauth2", "token_url": "x"}})
        assert merged.get("_auth_token") == "tok-123", (
            "merge_auth returns only a dict; without stamping the token nothing downstream can "
            "ever see it, and the JWT-exp branch stays dead")

    def test_no_token_means_no_stamp(self, monkeypatch):
        """A static header carries no token to reason about; do not invent one."""
        monkeypatch.setenv("T", "abc")
        merged = dispatch.merge_auth({"auth": {"type": "static", "mode": "api_key",
                                               "name": "X-Key", "value_ref": "env:T"}})
        assert "_auth_token" not in merged

    @pytest.mark.parametrize("site", ["mark_refreshed(token=self.config.get(\"_auth_token\"))"])
    def test_both_refresh_points_pass_the_token(self, site):
        assert CT.count(site) == 2, (
            "call_target must hand the token to the lifecycle at BOTH the initial materialize and "
            "the mid-run re-auth; one without the other leaves the exp check dead half the time")

    def test_no_bare_mark_refreshed_remains(self):
        assert not re.search(r"mark_refreshed\(\)", CT), "a bare mark_refreshed() drops the token"

    def test_the_jwt_exp_branch_now_fires_with_a_real_token(self):
        """End to end through the lifecycle: a JWT whose exp is in the past must trigger refresh."""
        import base64, json, time
        exp = int(time.time()) - 10
        b64 = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
        jwt = f"{b64({'alg':'none'})}.{b64({'exp': exp})}."
        lc = A.AuthLifecycle({"type": "refresh_on_ttl", "ttl_s": 99999})
        lc.mark_refreshed(token=jwt)
        assert lc.needs_refresh(), "an expired JWT must refresh even though ttl_s says 'not yet'"
        lc2 = A.AuthLifecycle({"type": "refresh_on_ttl", "ttl_s": 99999})
        lc2.mark_refreshed()                        # the old call shape: no token
        assert not lc2.needs_refresh(), "without the token the check silently falls back to ttl_s"


class TestExtraHonoursSecretRefs:
    def test_an_env_ref_in_extra_is_resolved(self, monkeypatch):
        monkeypatch.setenv("AUD_SECRET", "resolved-value")
        prov, seen = _oauth(monkeypatch, _Resp(payload={"access_token": "t"}),
                            extra={"audience": "env:AUD_SECRET"})
        prov.materialize()
        assert seen["data"]["audience"] == "resolved-value", (
            "extra values went to the wire raw; an env: ref was posted as the literal string "
            "'env:AUD_SECRET' — the one place in this file a secret could be inlined")

    def test_a_literal_ref_is_resolved(self, monkeypatch):
        prov, seen = _oauth(monkeypatch, _Resp(payload={"access_token": "t"}),
                            extra={"resource": "literal:https://api"})
        prov.materialize()
        assert seen["data"]["resource"] == "https://api"

    def test_a_bare_value_still_passes_through(self, monkeypatch):
        """Back-compat: working configs carry non-secret literals here."""
        prov, seen = _oauth(monkeypatch, _Resp(payload={"access_token": "t"}),
                            extra={"audience": "https://api.example"})
        prov.materialize()
        assert seen["data"]["audience"] == "https://api.example"

    def test_a_missing_env_ref_in_extra_fails_like_every_other_ref(self, monkeypatch):
        monkeypatch.delenv("NOPE", raising=False)
        prov, _ = _oauth(monkeypatch, _Resp(payload={"access_token": "t"}),
                         extra={"x": "env:NOPE"})
        with pytest.raises(A.AuthError):
            prov.materialize()


class TestTheTokenEndpointReplyIsGuarded:
    def test_non_json_2xx_is_an_auth_error_not_a_traceback(self, monkeypatch):
        prov, _ = _oauth(monkeypatch, _Resp(status=200, text="<html>login page</html>"))
        with pytest.raises(A.AuthError) as e:
            prov.materialize()
        assert "not JSON" in str(e.value)

    def test_a_json_array_is_refused_readably(self, monkeypatch):
        prov, _ = _oauth(monkeypatch, _Resp(payload=["not", "an", "object"]))
        with pytest.raises(A.AuthError) as e:
            prov.materialize()
        assert "not an object" in str(e.value)

    def test_a_good_reply_still_yields_a_bearer(self, monkeypatch):
        prov, seen = _oauth(monkeypatch, _Resp(payload={"access_token": "tok"}))
        mat = prov.materialize()
        assert mat.headers["Authorization"] == "Bearer tok"
        assert seen["data"]["grant_type"] == "client_credentials"
        assert seen["data"]["client_secret"] == "s3cret", "the secret must resolve from env:"


class TestTheOtherTwoMaterializersHaveErrorCoverage:
    """`_materialize_csrf` and `_materialize_multihop` had zero tests of any kind."""

    def test_csrf_missing_token_is_an_auth_error(self, monkeypatch):
        import requests
        class S:
            cookies = []
            def get(self, *a, **k): return _Resp(200, "<html>no token here</html>")
        monkeypatch.setattr(requests, "Session", lambda: S())
        prov = A.AuthProvider({"type": "csrf", "bootstrap_url": "https://x/",
                               "extract": {"regex": 'csrf="([^"]+)'}, "into_header": "X-CSRF"})
        with pytest.raises(A.AuthError) as e:
            prov.materialize()
        assert "not found" in str(e.value)

    def test_csrf_extracts_from_html_and_echoes_into_the_header(self, monkeypatch):
        import requests
        class S:
            cookies = []
            def get(self, *a, **k): return _Resp(200, '<meta name="csrf-token" content="abc123">')
        monkeypatch.setattr(requests, "Session", lambda: S())
        prov = A.AuthProvider({"type": "csrf", "bootstrap_url": "https://x/",
                               "extract": {"regex": r'csrf-token" content="([^"]+)'},
                               "into_header": "X-CSRF-Token"})
        mat = prov.materialize()
        assert mat.headers["X-CSRF-Token"] == "abc123"

    def test_multihop_failed_step_names_the_step(self, monkeypatch):
        import requests
        class S:
            cookies = []
            def request(self, *a, **k): return _Resp(500, "boom")
        monkeypatch.setattr(requests, "Session", lambda: S())
        prov = A.AuthProvider({"type": "derived_multihop",
                               "steps": [{"method": "POST", "url": "https://x/login", "json": {}}]})
        with pytest.raises(A.AuthError) as e:
            prov.materialize()
        assert "step 0" in str(e.value)

    def test_multihop_threads_a_variable_into_the_next_step_and_the_attach(self, monkeypatch):
        import requests
        calls = []
        class S:
            cookies = []
            def request(self, method, url, headers=None, json=None, data=None, **k):
                calls.append((method, url, dict(headers or {})))
                if url.endswith("/login"):
                    return _Resp(200, "", {"token": "T1"})
                return _Resp(200, "", {"session": "S2"})
        monkeypatch.setattr(requests, "Session", lambda: S())
        prov = A.AuthProvider({"type": "derived_multihop", "steps": [
            {"method": "POST", "url": "https://x/login", "json": {},
             "extract": [{"var": "TOK", "path": "token"}]},
            {"method": "GET", "url": "https://x/session", "headers": {"Authorization": "Bearer {{TOK}}"},
             "extract": [{"var": "SID", "path": "session"}]},
        ], "attach": {"headers": {"X-Session": "{{SID}}", "Authorization": "Bearer {{TOK}}"}}})
        mat = prov.materialize()
        assert calls[1][2]["Authorization"] == "Bearer T1", "step 2 must see step 1's variable"
        assert mat.headers == {"X-Session": "S2", "Authorization": "Bearer T1"}
        assert prov.token == "T1", "the bearer must be cached for the lifecycle"
