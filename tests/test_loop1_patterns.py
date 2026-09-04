"""
test_loop1_patterns.py — patterns the first forge-and-test loop found the CLI could not handle,
each reproduced against agent-forge and fixed at one seam.

  * a WebSocket target with the API key in the query string: the key was folded into an HTTP URL
    and silently dropped for a `ws://` one (validation passed against a gate that was not there)
  * a target that answers every unauthenticated request with a 302 to an HTML sign-in page:
    diagnosed as "rejected every body shape" instead of "behind auth"
  * a form-posting target: no form-encoded candidate at all, and the politeness abort fired first
  * a GraphQL endpoint and a create-then-message contract: the hint did not name what it saw
  * a target that answers every Nth request with 429: the probe scored as unanswered
"""
import json
import sys
import types
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
for p in ("shells/cli", "runtime", "control", "tests"):
    if str(REPO / p) not in sys.path:
        sys.path.insert(0, str(REPO / p))
from conftest import FakeResponse, install_fake_requests  # noqa: E402

probe = pytest.importorskip("discovery.probe")
import ascend  # noqa: E402

JSON_CT = {"Content-Type": "application/json"}
HTML_CT = {"Content-Type": "text/html; charset=utf-8"}
SIGNIN = "<!doctype html><html><body><h1>Sign in</h1><form><input type=\"password\"></form></body></html>"


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    monkeypatch.setattr(probe.time, "sleep", lambda s: None)


def run(monkeypatch, handler, url, **kw):
    rec = install_fake_requests(monkeypatch, handler)
    kw.setdefault("rate_limit_s", 0.0)
    return probe.probe_api(url, **kw), rec


class TestSignInRedirect:
    def test_a_302_to_a_sign_in_page_is_an_auth_wall_not_a_shape_problem(self, monkeypatch):
        def handler(method, url, kw):
            r = FakeResponse(200, text=SIGNIN, headers=HTML_CT)
            r.history = [FakeResponse(302, headers={"Location": "/signin"})]
            r.url = "https://bot.example.com/signin"
            return r
        res, _ = run(monkeypatch, handler, "https://bot.example.com/chat")
        assert res.ok is False and res.diagnosis == "auth_required", (res.diagnosis, res.message)
        assert "sign-in page" in res.message and "--login-url" in res.hint

    def test_an_ordinary_html_200_is_not_mistaken_for_a_wall(self):
        assert probe._looks_like_signin("<html><body>Hello, how can I help?</body></html>") is False
        assert probe._looks_like_signin(SIGNIN) is True


class TestFormEncodedTarget:
    def test_a_form_only_target_derives_with_its_content_type(self, monkeypatch):
        def handler(method, url, kw):
            data = kw.get("data")
            if isinstance(data, dict) and data.get("message") and data.get("channel") == "web":
                return FakeResponse(200, {"reply": "Yes, we are open until 6pm on weekdays."}, headers=JSON_CT)
            return FakeResponse(403, {"error": "invalid access code"}, headers=JSON_CT)
        res, rec = run(monkeypatch, handler, "https://bot.example.com/chat",
                       extra_body={"channel": "web", "access_code": "x"})
        assert res.ok is True, (res.diagnosis, res.message)
        cfg = probe.build_config(res)
        assert cfg["headers"]["Content-Type"] == "application/x-www-form-urlencoded"
        assert cfg["body"]["channel"] == "web" and "{{PROMPT}}" in json.dumps(cfg["body"])

    def test_the_form_candidate_comes_second_so_the_auth_abort_cannot_hide_it(self):
        shapes = probe.default_shapes("POST", None)
        labels = [s.label for s in shapes]
        assert labels.index("form_message") == 1, labels[:4]


class TestHintsNameTheContract:
    def test_graphql_is_named(self, monkeypatch):
        def handler(method, url, kw):
            return FakeResponse(200, {"errors": [{"message": 'Variable "$input" of required type "MessageInput!" was not provided.'}]}, headers=JSON_CT)
        res, _ = run(monkeypatch, handler, "https://bot.example.com/graphql")
        assert res.diagnosis == "bad_shape" and "GraphQL" in res.hint

    def test_a_2xx_without_an_answer_is_a_create_then_message_contract(self, monkeypatch):
        def handler(method, url, kw):
            if url.endswith("/conversations"):
                return FakeResponse(201, {"id": "c-1", "conversation_id": "c-1"}, headers=JSON_CT)
            return FakeResponse(404, {"detail": "Not Found"}, headers=JSON_CT)
        res, _ = run(monkeypatch, handler, "https://bot.example.com/")
        # The probe already knows this shape as an async POST-then-GET contract; either diagnosis
        # must name what it saw and send the operator to a HAR, never to "give the full path".
        assert res.diagnosis in ("async_poll", "not_found"), res.diagnosis
        assert "--har" in res.hint and ("returned an id" in res.message or "create-then-message" in res.message)


class TestRateLimitRetry:
    def test_retry_after_is_parsed_and_bounded(self):
        import call_target as ct
        assert ct._retry_after_seconds({"Retry-After": "2"}) == 2.0
        assert ct._retry_after_seconds([("retry-after", "7.5")]) == 7.5
        assert ct._retry_after_seconds({"X-Other": "1"}) is None
        assert ct._retry_after_seconds(None) is None

    def test_a_429_is_retried_once_after_the_wait(self, monkeypatch):
        import call_target as ct
        calls, slept = [], []
        monkeypatch.setattr(ct.time, "sleep", lambda s: slept.append(s))

        class Router:
            def send(self, *a, **k):
                calls.append(1)
                if len(calls) == 1:
                    return {"metadata": {"status_code": 429, "headers": {"Retry-After": "3"}}, "response": ""}
                return {"metadata": {"status_code": 200, "headers": {}}, "response": "hello"}

        caller = ct.TargetCaller.__new__(ct.TargetCaller)
        caller.config = {"adapter": "direct_api"}
        caller.config_name = "t"; caller.adapter_type = "direct_api"; caller.timeout_s = 5
        caller.router = Router()
        caller._lifecycle = types.SimpleNamespace(should_reauth=lambda s: False, note_response=lambda *a, **k: None)
        caller._maybe_refresh_auth = lambda: None
        monkeypatch.setattr(ct, "extract_prompt", lambda body, cfg: "hi")
        monkeypatch.setattr(ct, "conversation_key", lambda m, c: None)
        monkeypatch.setattr(ct, "shape_result", lambda r, c: (int(r["metadata"]["status_code"]), {"response": r.get("response", "")}))
        status, out = caller.handler({"payload": {"body": {"message": "hi"}}})
        assert status == 200 and out["response"] == "hello"
        assert calls == [1, 1] and slept == [3.0]

    def test_a_second_429_stands(self, monkeypatch):
        import call_target as ct
        slept = []
        monkeypatch.setattr(ct.time, "sleep", lambda s: slept.append(s))
        n = []

        class Router:
            def send(self, *a, **k):
                n.append(1)
                return {"metadata": {"status_code": 429, "headers": {"Retry-After": "600"}}, "response": ""}

        caller = ct.TargetCaller.__new__(ct.TargetCaller)
        caller.config = {}; caller.config_name = "t"; caller.adapter_type = "direct_api"; caller.timeout_s = 5
        caller.router = Router()
        caller._lifecycle = types.SimpleNamespace(should_reauth=lambda s: False, note_response=lambda *a, **k: None)
        caller._maybe_refresh_auth = lambda: None
        monkeypatch.setattr(ct, "extract_prompt", lambda body, cfg: "hi")
        monkeypatch.setattr(ct, "conversation_key", lambda m, c: None)
        monkeypatch.setattr(ct, "shape_result", lambda r, c: (429, {"response": ""}))
        status, _ = caller.handler({"payload": {"body": {}}})
        assert status == 429 and len(n) == 2, "exactly one retry"
        assert slept == [ct.RETRY_AFTER_MAX_S], "a Retry-After of 600 must not park a probe for ten minutes"


class TestWebSocketQueryKey:
    def test_material_params_fold_into_ws_url(self):
        from layers.auth import AuthMaterial
        m = AuthMaterial(params={"key": "k"})
        assert m.merge_into_config({"ws_url": "ws://h/ws"})["ws_url"] == "ws://h/ws?key=k"

    def test_finalize_strips_the_key_from_ws_url(self, monkeypatch):
        monkeypatch.setenv("T_K", "k-1")
        a = types.SimpleNamespace(header=None, bearer=None, token_file=None, api_key="key:env:T_K:in=query",
                                  basic=None, cookie=None, _login_auth=None)
        ascend._target_auth(a)
        out = ascend._finalize_target_auth({"ws_url": "ws://h/ws?key=k-1"}, a)
        assert out["ws_url"] == "ws://h/ws" and out["auth"]["in"] == "query"

    def test_onboard_folds_the_query_into_the_ws_url(self):
        import inspect
        src = inspect.getsource(ascend.cmd_onboard)
        i = src.index("res = probe_ws(")
        assert "auth_query" in src[i - 600:i] and "probe_ws(ws_url" in src
