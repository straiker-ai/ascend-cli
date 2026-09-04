"""
test_probe.py — non-browser API discovery (`discovery.probe`).

The gap `probe_api` closes: a customer hands over an HTTP endpoint (or just a
base URL) and nothing else — no browser, no HAR. The probe derives the contract
EMPIRICALLY, by sending one benign prompt at a time until a real answer comes
back. These tests pin that behaviour down offline:

* the headline case — a PARENT url where the real endpoint lives deeper;
* every failure mode is a *diagnosis with a next action*, not an exception;
* a 200 is never mistaken for success (echo / empty / error envelope);
* manners — bounded attempt count, sequential, backs off, stops knocking on auth.

Everything is network-free: `requests` is routed through `install_fake_requests`
and `time.sleep` is neutered, so the whole file runs in milliseconds.
"""
import json

import pytest

import requests

from conftest import FakeResponse, install_fake_requests

probe = pytest.importorskip("discovery.probe",
                            reason="runtime/discovery/probe.py not present")
classify = pytest.importorskip("discovery.classify")

probe_api = probe.probe_api
build_config = probe.build_config
DEFAULT_PROMPT = probe.DEFAULT_PROMPT

JSON_CT = {"Content-Type": "application/json"}


# --------------------------------------------------------------------------- #
# scaffolding
# --------------------------------------------------------------------------- #
@pytest.fixture(autouse=True)
def slept(monkeypatch):
    """Neuter the politeness sleep and record what it *would* have waited.

    Keeps the suite instant while still letting the manners test assert that the
    probe actually paced itself.
    """
    waits = []
    monkeypatch.setattr(probe.time, "sleep", lambda s: waits.append(s))
    return waits


def run_probe(monkeypatch, handler, url, **kw):
    """Probe `url` with every HTTP call served by `handler`. Returns (result, recorder)."""
    rec = install_fake_requests(monkeypatch, handler)
    kw.setdefault("rate_limit_s", 0.0)
    return probe_api(url, **kw), rec


def serve(mapping, default=None):
    """Build a handler from ``{url: callable(method, url, kwargs) -> FakeResponse}``.

    Anything not in the map gets `default` (a 404 by default), which is what a
    real host does for the 20 paths the probe sweeps.
    """
    def _default(method, url, kw):
        return FakeResponse(404, {"detail": "Not Found"}, headers=JSON_CT)

    fallback = default or _default

    def handler(method, url, kw):
        fn = mapping.get(url)
        if fn is None:
            return fallback(method, url, kw)
        return fn(method, url, kw) if callable(fn) else fn
    return handler


def always(response_factory):
    """Handler that returns the same response for every request."""
    def handler(method, url, kw):
        return response_factory(method, url, kw)
    return handler


def raising(exc_factory):
    """Handler that raises a transport exception for every request."""
    def handler(method, url, kw):
        raise exc_factory()
    return handler


OPENAI_BODY = {"id": "chatcmpl-1", "object": "chat.completion", "model": "demo-1",
               "choices": [{"index": 0, "finish_reason": "stop",
                            "message": {"role": "assistant",
                                        "content": "I can help with orders, billing and returns."}}]}


def openai_endpoint(method, url, kw):
    """An OpenAI-compatible handler: 200 for `messages`, 400 for anything else."""
    body = kw.get("json") or {}
    if isinstance(body, dict) and "messages" in body:
        return FakeResponse(200, OPENAI_BODY, headers=JSON_CT)
    return FakeResponse(400, {"error": {"message": "'messages' is required"}}, headers=JSON_CT)


# =========================================================================== #
# 1. Full endpoint given, first try works
# =========================================================================== #
class TestFullEndpointFirstTry:
    URL = "https://bot.example.com/api/chat"

    def _handler(self):
        def ok(method, url, kw):
            return FakeResponse(200, {"reply": "Sure — I can help with account questions."},
                                headers=JSON_CT)
        return serve({self.URL: ok})

    def test_ok_on_first_request(self, monkeypatch):
        r, rec = run_probe(monkeypatch, self._handler(), self.URL)
        assert r.ok is True
        assert r.diagnosis == "ok"
        assert r.endpoint == self.URL
        assert r.method == "POST"
        assert rec.calls[0]["url"] == self.URL, "the caller's own URL must be tried first"
        assert len(rec.calls) == 1, "a working endpoint must not be swept past"

    def test_response_path_points_at_the_answer(self, monkeypatch):
        r, _ = run_probe(monkeypatch, self._handler(), self.URL)
        assert r.response_path == "reply"
        assert r.transport == "rest_json"
        assert r.response_text == "Sure — I can help with account questions."
        assert probe.dot_get({"reply": "x"}, r.response_path) == "x"

    def test_request_body_template_keeps_the_placeholder(self, monkeypatch):
        r, rec = run_probe(monkeypatch, self._handler(), self.URL)
        assert r.request_body == {"message": probe.PROMPT_TOKEN}
        # ...but the wire carried the real prompt, not the token.
        assert rec.calls[0]["json"] == {"message": DEFAULT_PROMPT}

    def test_build_config_is_runnable_direct_api(self, monkeypatch):
        r, _ = run_probe(monkeypatch, self._handler(), self.URL)
        cfg = build_config(r)
        assert cfg["adapter"] == "direct_api"
        assert cfg["endpoint"] == self.URL
        assert cfg["method"] == "POST"
        assert cfg["body"] == {"message": probe.PROMPT_TOKEN}
        assert cfg["response_path"] == "reply"
        # No timeout is pinned. The probe's own timeout is how long we waited while working out the
        # contract; it says nothing about how long the target takes under assessment. Pinning the
        # discovery value made slow targets fail every probe, and pinning the runtime default
        # instead would permanently override the derived per-probe timeout for this config. Absent means
        # the runtime default, and its env override, apply.
        assert "timeout_ms" not in cfg
        assert cfg["_probe"]["verified_answer"].startswith("Sure")

    def test_build_config_pins_a_timeout_only_when_asked(self, monkeypatch):
        r, _ = run_probe(monkeypatch, self._handler(), self.URL)
        assert build_config(r, timeout_ms=45_000)["timeout_ms"] == 45_000

    def test_evidence_feeds_classify_evidence_and_yields_a_config(self, monkeypatch):
        r, _ = run_probe(monkeypatch, self._handler(), self.URL)
        assert r.evidence["prompt_sent"] == DEFAULT_PROMPT
        assert r.evidence["reply_text"] == r.response_text
        assert len(r.evidence["pairs"]) == 1, "only the WINNING exchange is evidence"

        classified = classify.classify_evidence(r.evidence)
        cfg = classified["config"]
        assert cfg["endpoint"] == self.URL
        assert cfg["response_path"] == "reply"
        assert cfg["body"] == {"message": probe.PROMPT_TOKEN}
        assert set(classified["layers"]) == set(classify.LAYER_NAMES)
        composed = classify.compose(classified)
        assert composed["endpoint"] == self.URL

    def test_result_is_json_serialisable(self, monkeypatch):
        r, _ = run_probe(monkeypatch, self._handler(), self.URL)
        blob = json.loads(json.dumps(r.to_dict()))
        assert blob["ok"] is True and blob["diagnosis"] == "ok"
        assert blob["attempts"][0]["outcome"] == "answer"

    def test_caller_headers_are_sent_on_every_request(self, monkeypatch):
        r, rec = run_probe(monkeypatch, self._handler(), self.URL,
                           headers={"Authorization": "Bearer tok", "X-Tenant": "acme"})
        assert r.ok is True
        for call in rec.calls:
            assert call["headers"]["Authorization"] == "Bearer tok"
            assert call["headers"]["X-Tenant"] == "acme"
        cfg = build_config(r)
        assert cfg["headers"]["Authorization"] == "Bearer tok"
        # secrets echoed back must be flagged, loudly, before this lands in a repo
        assert "Authorization" in cfg["_probe"]["inline_secret_headers"]

    def test_caller_supplied_body_shape_is_tried_first(self, monkeypatch):
        url = "https://bot.example.com/agent/talk"

        def ok(method, url_, kw):
            if (kw.get("json") or {}).get("utterance"):
                return FakeResponse(200, {"result": {"speech": "Of course, happy to help."}},
                                    headers=JSON_CT)
            return FakeResponse(400, {"error": "unknown field"}, headers=JSON_CT)

        r, rec = run_probe(monkeypatch, serve({url: ok}), url,
                           bodies=[{"utterance": probe.PROMPT_TOKEN}])
        assert r.ok is True
        assert len(rec.calls) == 1
        assert r.shape_label == "caller[0]"
        assert r.response_path == "result.speech"

    def test_caller_supplied_path_is_tried_first(self, monkeypatch):
        url = "https://bot.example.com/weird/entry"

        def ok(method, url_, kw):
            return FakeResponse(200, {"answer": "Sure, here is what I can do for you."},
                                headers=JSON_CT)

        r, rec = run_probe(monkeypatch, serve({url: ok}), "https://bot.example.com/",
                           paths=["weird/entry"])
        assert r.ok is True
        assert rec.calls[0]["url"] == url
        assert r.endpoint == url


# =========================================================================== #
# 2. THE HEADLINE CASE — parent URL given, real endpoint is deeper
# =========================================================================== #
class TestParentUrlPathDiscovery:
    PARENT = "https://bot.example.com/"
    REAL = "https://bot.example.com/v1/chat/completions"

    def test_finds_the_deeper_endpoint(self, monkeypatch):
        r, rec = run_probe(monkeypatch, serve({self.REAL: openai_endpoint}), self.PARENT)
        assert r.ok is True, r.message
        assert r.diagnosis == "ok"
        assert r.endpoint == self.REAL
        assert r.response_path == "choices.0.message.content"
        assert r.response_text.startswith("I can help with")
        assert r.transport == "rest_json"
        assert r.shape_label == "openai_messages"

    def test_it_actually_had_to_search(self, monkeypatch):
        r, rec = run_probe(monkeypatch, serve({self.REAL: openai_endpoint}), self.PARENT)
        tried = [c["url"] for c in rec.calls]
        assert len(tried) > 1, "the parent URL alone cannot be the answer"
        assert self.REAL in tried
        assert tried == list(dict.fromkeys(tried)), "no URL is probed twice in the sweep"
        # the parent had no path of its own, so it is not replayed verbatim
        assert self.PARENT not in tried[:1]

    def test_path_name_only_reorders_the_queue(self, monkeypatch):
        """The `/…/completions` name puts the OpenAI shape first — one request, not fifteen."""
        r, rec = run_probe(monkeypatch, serve({self.REAL: openai_endpoint}), self.PARENT)
        at_real = [c for c in rec.calls if c["url"] == self.REAL]
        assert len(at_real) == 1
        assert "messages" in at_real[0]["json"]

    def test_config_and_evidence_survive_the_search(self, monkeypatch):
        r, _ = run_probe(monkeypatch, serve({self.REAL: openai_endpoint}), self.PARENT)
        cfg = build_config(r)
        assert cfg["endpoint"] == self.REAL
        assert cfg["response_path"] == "choices.0.message.content"
        assert cfg["body"] == {"messages": [{"role": "user", "content": probe.PROMPT_TOKEN}]}
        classified = classify.classify_evidence(r.evidence)
        assert classified["config"]["endpoint"] == self.REAL
        assert classified["config"]["response_path"] == "choices.0.message.content"

    def test_intermediate_base_path_is_searched_too(self, monkeypatch):
        """`https://h/api/v2/bot` also probes `/api/v2/bot/chat`, `/api/v2/chat` and `/chat`."""
        real = "https://bot.example.com/api/v2/chat"

        def ok(method, url, kw):
            return FakeResponse(200, {"reply": "Yes, I can look that up for you."},
                                headers=JSON_CT)

        r, rec = run_probe(monkeypatch, serve({real: ok}), "https://bot.example.com/api/v2/bot")
        assert r.ok is True
        assert r.endpoint == real
        assert rec.calls[0]["url"] == "https://bot.example.com/api/v2/bot"

    def test_two_answering_endpoints_are_reported_as_ambiguous(self, monkeypatch):
        """Silently picking one of two live bots would assess the wrong system."""
        def ok(method, url, kw):
            return FakeResponse(200, {"reply": "Sure, I can help you with lots of things."},
                                headers=JSON_CT)

        r, _ = run_probe(monkeypatch, serve({"https://bot.example.com/chat": ok,
                                             "https://bot.example.com/api/chat": ok}),
                         self.PARENT)
        assert r.ok is False
        assert r.diagnosis == "ambiguous"
        assert r.endpoint is not None, "the best candidate is still reported"
        assert r.alternatives, "the other answering endpoint must be named"
        assert "endpoint" in r.hint.lower() or "paths=" in r.hint


# =========================================================================== #
# 3. Transport-level failures
# =========================================================================== #
class TestTransportDiagnoses:
    def test_dns_failure(self, monkeypatch):
        def boom():
            return requests.exceptions.ConnectionError(
                "HTTPSConnectionPool(host='nope.invalid', port=443): Max retries exceeded "
                "(Failed to resolve 'nope.invalid' [Errno 8] nodename nor servname provided)")

        r, _ = run_probe(monkeypatch, raising(boom), "https://nope.invalid/api/chat")
        assert r.ok is False
        assert r.diagnosis == "dns"
        assert "nope.invalid" in r.message
        assert "resolve" in r.message.lower()
        assert "nslookup" in r.hint and "VPN" in r.hint
        assert r.endpoint is None

    def test_connection_refused(self, monkeypatch):
        def boom():
            return requests.exceptions.ConnectionError(
                "HTTPConnectionPool(host='10.0.0.9', port=8080): Max retries exceeded "
                "([Errno 61] Connection refused)")

        r, _ = run_probe(monkeypatch, raising(boom), "http://10.0.0.9:8080/chat")
        assert r.diagnosis == "unreachable"
        assert "refused or timed out" in r.message
        assert "firewall" in r.hint.lower() or "egress" in r.hint.lower()
        assert "curl -v" in r.hint

    def test_timeout_is_unreachable_not_dns(self, monkeypatch):
        r, _ = run_probe(monkeypatch,
                         raising(lambda: requests.exceptions.ReadTimeout("timed out")),
                         "https://slow.example.com/chat")
        assert r.diagnosis == "unreachable"

    def test_tls_failure_is_its_own_diagnosis(self, monkeypatch):
        def boom():
            return requests.exceptions.SSLError(
                "certificate verify failed: self signed certificate in chain")

        r, _ = run_probe(monkeypatch, raising(boom), "https://internal.example.com/chat")
        assert r.diagnosis == "tls"
        assert "verify_tls=False" in r.hint or "--insecure" in r.hint
        assert "REQUESTS_CA_BUNDLE" in r.hint

    def test_verify_tls_flag_is_passed_through(self, monkeypatch):
        r, rec = run_probe(monkeypatch, always(lambda *a: FakeResponse(404, {})),
                           "https://h.example.com/chat", verify_tls=False, max_attempts=6)
        assert all(c["kwargs"]["verify"] is False for c in rec.calls)

    def test_unusable_url_is_a_diagnosis_not_an_exception(self, monkeypatch):
        r, rec = run_probe(monkeypatch, always(lambda *a: FakeResponse(200, {})), "")
        assert r.ok is False
        assert r.diagnosis == "dns"
        assert "absolute URL" in r.message
        assert rec.calls == [], "an unusable URL must not touch the network"


# =========================================================================== #
# 4. HTTP-level failures
# =========================================================================== #
class TestHttpDiagnoses:
    def test_every_path_404_says_what_it_tried(self, monkeypatch):
        r, rec = run_probe(monkeypatch,
                           always(lambda *a: FakeResponse(404, {"detail": "Not Found"},
                                                          headers=JSON_CT)),
                           "https://bot.example.com/")
        assert r.ok is False
        assert r.diagnosis == "not_found"
        assert "is UP" in r.message
        assert "Tried:" in r.message
        assert "https://bot.example.com/chat" in r.message
        assert "FULL endpoint path" in r.hint
        assert "curl" in r.hint
        assert "HAR" in r.hint or "--url" in r.hint
        assert len(r.tried_urls) > 5

    def test_wall_of_401_stops_knocking(self, monkeypatch):
        r, rec = run_probe(monkeypatch,
                           always(lambda *a: FakeResponse(401, {"error": "unauthorized"},
                                                          headers=JSON_CT)),
                           "https://bot.example.com/")
        assert r.diagnosis == "auth_required"
        assert len(rec.calls) <= 3, "repeated 401 probing is credential guessing"
        # First-class auth flags are the guided re-run; --header still shown as a fallback.
        assert "--bearer" in r.hint
        assert "--api-key" in r.hint and "x-api-key" in r.hint.lower()
        assert "--cookie" in r.hint
        assert "--login-url" in r.hint          # login/access-code path is surfaced
        assert "--header" in r.hint

    def test_403_is_also_auth_required(self, monkeypatch):
        r, rec = run_probe(monkeypatch,
                           always(lambda *a: FakeResponse(403, {"error": "forbidden"},
                                                          headers=JSON_CT)),
                           "https://bot.example.com/api/chat")
        assert r.diagnosis == "auth_required"
        assert all(a.outcome == "auth" for a in r.attempts)

    def test_429_backs_off_instead_of_hammering(self, monkeypatch):
        r, rec = run_probe(monkeypatch,
                           always(lambda *a: FakeResponse(429, {"error": "slow down"},
                                                          headers={"Retry-After": "30",
                                                                   **JSON_CT})),
                           "https://bot.example.com/", max_attempts=40)
        assert r.diagnosis == "rate_limited"
        assert len(rec.calls) <= 2, "a rate-limited target must not be swept"
        assert "429" in r.message
        assert "rate_limit_s" in r.hint
        assert "max_attempts" in r.hint or "allow-list" in r.hint

    def test_consistent_5xx_blames_the_target(self, monkeypatch):
        r, _ = run_probe(monkeypatch,
                         always(lambda *a: FakeResponse(503, text="upstream unavailable",
                                                        headers={"Content-Type": "text/plain"})),
                         "https://bot.example.com/")
        assert r.diagnosis == "server_error"
        assert "5xx" in r.message
        assert "target is failing" in r.message
        assert "owner" in r.hint and "re-run" in r.hint
        assert all(a.outcome == "server_error" for a in r.attempts)

    def test_one_endpoint_is_not_retried_past_its_5xx_budget(self, monkeypatch):
        url = "https://bot.example.com/api/chat"
        r, rec = run_probe(monkeypatch,
                           always(lambda *a: FakeResponse(500, {"error": "boom"}, headers=JSON_CT)),
                           url)
        at_url = [c for c in rec.calls if c["url"] == url]
        assert len(at_url) <= 2, "a failing endpoint gets at most 2 tries"

    def test_endpoint_exists_but_every_shape_400s(self, monkeypatch):
        url = "https://bot.example.com/api/chat"

        def four_hundred(method, url_, kw):
            return FakeResponse(400, {"error": "bad request"}, headers=JSON_CT)

        r, rec = run_probe(monkeypatch, serve({url: four_hundred}), url)
        assert r.ok is False
        assert r.diagnosis == "bad_shape"
        assert url in r.message
        assert "real endpoint" in r.message
        assert "not a 404" in r.message
        assert "curl" in r.hint
        assert "field name" in r.hint
        # It went deep on the ONE real endpoint rather than wide on 20 fake ones.
        at_url = [c for c in rec.calls if c["url"] == url]
        assert len(at_url) >= 5
        assert len(at_url) == len(rec.calls), "a settled path question stops the sweep"

    def test_405_also_proves_the_path_is_real(self, monkeypatch):
        url = "https://bot.example.com/api/chat"

        def only_get(method, url_, kw):
            if method == "GET":
                return FakeResponse(200, {"answer": "Sure, I can help with that today."},
                                    headers=JSON_CT)
            return FakeResponse(405, {"detail": "Method Not Allowed"}, headers=JSON_CT)

        r, _ = run_probe(monkeypatch, serve({url: only_get}), url)
        assert r.ok is True
        assert r.method == "GET"
        assert r.endpoint.startswith(url)

    def test_target_error_message_teaches_the_body_shape(self, monkeypatch):
        """A FastAPI `detail[].loc` naming its field beats any guess we could make."""
        url = "https://bot.example.com/api/chat"

        def fastapi(method, url_, kw):
            body = kw.get("json") or {}
            if "question" in body:
                return FakeResponse(200, {"answer": "Sure, I can help you with account questions."},
                                    headers=JSON_CT)
            return FakeResponse(422, {"detail": [{"loc": ["body", "question"],
                                                  "msg": "field required",
                                                  "type": "value_error.missing"}]},
                                headers=JSON_CT)

        r, rec = run_probe(monkeypatch, serve({url: fastapi}), url)
        assert r.ok is True
        assert r.shape_label == "error_hint:question"
        assert r.request_body == {"question": probe.PROMPT_TOKEN}
        assert len(rec.calls) == 2, "the target's own error should cost exactly one extra request"


# =========================================================================== #
# 5. Response shapes -> transport + response_path
# =========================================================================== #
class TestResponseShapes:
    URL = "https://bot.example.com/api/chat"

    def _probe_body(self, monkeypatch, text=None, json_data=None, headers=None):
        def resp(method, url, kw):
            return FakeResponse(200, json_data, text=text, headers=headers or JSON_CT)
        return run_probe(monkeypatch, serve({self.URL: resp}), self.URL)

    def test_openai_choices_shape(self, monkeypatch):
        r, _ = self._probe_body(monkeypatch, json_data=OPENAI_BODY)
        assert r.ok is True
        assert r.transport == "rest_json"
        assert r.response_path == "choices.0.message.content"
        assert build_config(r)["adapter"] == "direct_api"

    def test_nested_data_reply_shape(self, monkeypatch):
        body = {"status": "ok", "id": "b6f0e3b0-0000-4000-8000-000000000000",
                "data": {"reply": "Sure, I can help you with orders and returns.",
                         "conversation_id": "c-99"}}
        r, _ = self._probe_body(monkeypatch, json_data=body)
        assert r.response_path == "data.reply"
        assert r.transport == "rest_json"
        assert probe.dot_get(body, r.response_path) == r.response_text

    def test_plain_text_body_has_no_response_path(self, monkeypatch):
        r, _ = self._probe_body(monkeypatch, text="I can help you with billing questions today.",
                                headers={"Content-Type": "text/plain"})
        assert r.ok is True
        assert r.transport == "text"
        assert r.response_path is None
        assert r.response_text == "I can help you with billing questions today."
        cfg = build_config(r)
        assert cfg["adapter"] == "direct_api"
        assert "response_path" not in cfg, "no path means 'the body IS the answer'"

    def test_sse_stream_yields_sse_transport_and_stream_hints(self, monkeypatch):
        sse = ('data: {"delta":"Hello"}\n\n'
               'data: {"delta":" there, how can I help you?"}\n\n'
               'data: [DONE]\n\n')
        r, _ = self._probe_body(monkeypatch, text=sse,
                                headers={"Content-Type": "text/event-stream"})
        assert r.ok is True
        assert r.transport == "sse"
        assert r.response_path == "delta"
        assert r.response_text == "Hello there, how can I help you?"
        assert r.stream_hints["format"] == "sse"
        assert r.stream_hints["done_when"] == {"contains": "[DONE]"}

    def test_sse_builds_an_sse_stream_adapter_config(self, monkeypatch):
        sse = 'data: {"content":"Hi"}\n\ndata: {"content":" there, what can I do?"}\n\ndata: [DONE]\n\n'
        r, _ = self._probe_body(monkeypatch, text=sse,
                                headers={"Content-Type": "text/event-stream"})
        cfg = build_config(r)
        assert cfg["adapter"] == "sse_stream"
        assert cfg["base_url"] == "https://bot.example.com"
        assert cfg["chat_path"] == "/api/chat"
        assert cfg["request_template"] == {"message": probe.PROMPT_TOKEN}
        assert cfg["stream"]["format"] == "sse"
        assert cfg["stream"]["text_path"] == "content"
        assert cfg["stream"]["idle_ms"] > 0

    def test_ndjson_stream(self, monkeypatch):
        nd = ('{"text":"Hello"}\n'
              '{"text":" there, how can I help you?"}\n'
              '{"type":"done"}\n')
        r, _ = self._probe_body(monkeypatch, text=nd,
                                headers={"Content-Type": "application/x-ndjson"})
        assert r.transport == "ndjson"
        assert r.response_path == "text"
        assert r.response_text == "Hello there, how can I help you?"
        assert r.stream_hints["done_when"] == {"path": "type", "equals": "done"}
        cfg = build_config(r)
        assert cfg["adapter"] == "sse_stream"
        assert cfg["stream"]["format"] == "ndjson"

    def test_ndjson_detected_without_a_content_type(self, monkeypatch):
        nd = '{"delta":"Sure, I "}\n{"delta":"can help with that."}\n'
        r, _ = self._probe_body(monkeypatch, text=nd, headers={})
        assert r.transport == "ndjson"
        assert r.response_text == "Sure, I can help with that."

    @pytest.mark.parametrize("body,expected_path", [
        ({"answer": "Absolutely, I can look that up for you."}, "answer"),
        ({"output": "Absolutely, I can look that up for you."}, "output"),
        ({"completion": "Absolutely, I can look that up for you."}, "completion"),
        ({"result": {"speech": "Absolutely, I can look that up for you."}}, "result.speech"),
        ({"messages": [{"role": "assistant",
                        "content": "Absolutely, I can look that up for you."}]},
         "messages.0.content"),
    ])
    def test_common_answer_paths(self, monkeypatch, body, expected_path):
        r, _ = self._probe_body(monkeypatch, json_data=body)
        assert r.ok is True
        assert r.response_path == expected_path


# =========================================================================== #
# 6. Plausibility — a 200 proves nothing
# =========================================================================== #
class TestPlausibility:
    URL = "https://bot.example.com/api/chat"

    def _probe(self, monkeypatch, responder):
        return run_probe(monkeypatch, serve({self.URL: responder}), self.URL)

    def _detail_at_url(self, result):
        return next(a.detail for a in result.attempts if a.url == self.URL)

    def test_pure_echo_is_rejected(self, monkeypatch):
        def echo(method, url, kw):
            return FakeResponse(200, {"reply": (kw.get("json") or {}).get("message", "")},
                                headers=JSON_CT)

        r, _ = self._probe(monkeypatch, echo)
        assert r.ok is False
        assert r.endpoint is None
        assert r.diagnosis == "bad_shape"
        assert all(a.outcome != "answer" for a in r.attempts)
        assert "no answer-like string" in self._detail_at_url(r)

    def test_empty_200_is_rejected(self, monkeypatch):
        r, _ = self._probe(monkeypatch,
                           lambda m, u, k: FakeResponse(200, text="", headers=JSON_CT))
        assert r.ok is False
        assert "empty body" in self._detail_at_url(r)

    def test_error_envelope_with_200_is_rejected(self, monkeypatch):
        r, _ = self._probe(monkeypatch,
                           lambda m, u, k: FakeResponse(
                               200, {"error": {"message": "model overloaded"}}, headers=JSON_CT))
        assert r.ok is False
        assert "error envelope" in self._detail_at_url(r)
        assert "model overloaded" in self._detail_at_url(r)

    def test_error_envelope_wins_even_when_prose_is_present(self, monkeypatch):
        """An envelope that flags an error AND carries prose is still an error."""
        r, _ = self._probe(monkeypatch,
                           lambda m, u, k: FakeResponse(
                               200, {"error": "quota exceeded",
                                     "reply": "Sorry, I could not process that just now."},
                               headers=JSON_CT))
        assert r.ok is False
        assert "error envelope" in self._detail_at_url(r)

    def test_success_false_envelope_is_rejected(self, monkeypatch):
        r, _ = self._probe(monkeypatch,
                           lambda m, u, k: FakeResponse(
                               200, {"success": False,
                                     "message": "The assistant is temporarily unavailable."},
                               headers=JSON_CT))
        assert r.ok is False
        assert "success=false" in self._detail_at_url(r)

    def test_status_only_body_is_rejected(self, monkeypatch):
        r, _ = self._probe(monkeypatch,
                           lambda m, u, k: FakeResponse(
                               200, {"status": "ok", "id": "550e8400-e29b-41d4-a716-446655440000",
                                     "created": "2026-01-01T00:00:00Z"},
                               headers=JSON_CT))
        assert r.ok is False
        assert "no answer-like string" in self._detail_at_url(r)

    def test_html_page_is_rejected(self, monkeypatch):
        r, _ = self._probe(monkeypatch,
                           lambda m, u, k: FakeResponse(
                               200, text="<!doctype html><html><body>Login</body></html>",
                               headers={"Content-Type": "text/html"}))
        assert r.ok is False
        assert "HTML page" in self._detail_at_url(r)

    def test_stream_with_no_text_frames_is_rejected(self, monkeypatch):
        sse = 'data: {"type":"ping"}\n\ndata: [DONE]\n\n'
        r, _ = self._probe(monkeypatch,
                           lambda m, u, k: FakeResponse(
                               200, text=sse, headers={"Content-Type": "text/event-stream"}))
        assert r.ok is False
        assert "no text frames" in self._detail_at_url(r)

    def test_build_config_refuses_an_unproven_result(self, monkeypatch):
        r, _ = self._probe(monkeypatch,
                           lambda m, u, k: FakeResponse(200, text="", headers=JSON_CT))
        with pytest.raises(ValueError) as exc:
            build_config(r)
        assert "did not find a working contract" in str(exc.value)
        assert "next:" in str(exc.value), "even the exception says what to do next"


class TestScoreAnswer:
    """`score_answer` is the plausibility gate; MIN_ANSWER_SCORE is the bar."""

    @pytest.mark.parametrize("value", [
        DEFAULT_PROMPT,                                  # exact echo
        "Hello, what can you help",                      # fragment of our prompt
        "ok", "true", "error", "processing",             # protocol chatter
        "550e8400-e29b-41d4-a716-446655440000",          # uuid
        "deadbeefdeadbeefdeadbeef",                      # hex id
        "2026-01-01T12:00:00Z",                          # timestamp
        "42", "-1.5",                                    # numbers
        "https://example.com/x",                         # url
        "application/json",                              # mime
        "<!doctype html><p>hi</p>",                      # markup
        "",                                              # empty
    ])
    def test_disqualified_values(self, value):
        assert probe.score_answer("reply", value, DEFAULT_PROMPT) < probe.MIN_ANSWER_SCORE

    @pytest.mark.parametrize("path,value", [
        ("reply", "I can help with orders, billing and returns."),
        ("data.answer", "Sure! Ask me about your account and I will look it up."),
        ("", "Happy to help — what would you like to know?"),
    ])
    def test_accepted_values(self, path, value):
        assert probe.score_answer(path, value, DEFAULT_PROMPT) >= probe.MIN_ANSWER_SCORE

    def test_identity_leaf_keys_are_disqualified(self):
        assert probe.score_answer("conversation_id", "abc def ghi", DEFAULT_PROMPT) < 0
        assert probe.score_answer("model", "gpt something big", DEFAULT_PROMPT) < 0

    def test_answer_leaf_key_outranks_a_neutral_one(self):
        text = "That is a great question about your recent order."
        assert (probe.score_answer("answer", text, DEFAULT_PROMPT)
                > probe.score_answer("blob", text, DEFAULT_PROMPT))


# =========================================================================== #
# 7. Manners
# =========================================================================== #
class TestManners:
    def test_total_requests_never_exceed_max_attempts(self, monkeypatch):
        for cap in (1, 3, 6, 12, 25):
            r, rec = run_probe(monkeypatch,
                               always(lambda *a: FakeResponse(404, {"detail": "no"},
                                                              headers=JSON_CT)),
                               "https://bot.example.com/", max_attempts=cap)
            assert len(rec.calls) <= cap, f"cap={cap} was exceeded"
            assert len(r.attempts) == len(rec.calls)

    def test_max_attempts_bounds_the_deep_shape_search_too(self, monkeypatch):
        url = "https://bot.example.com/api/chat"
        r, rec = run_probe(monkeypatch,
                           serve({url: lambda m, u, k: FakeResponse(400, {"error": "nope"},
                                                                    headers=JSON_CT)}),
                           url, max_attempts=7)
        assert len(rec.calls) <= 7

    def test_the_callers_url_is_probed_first(self, monkeypatch):
        url = "https://bot.example.com/some/deep/path"
        r, rec = run_probe(monkeypatch,
                           always(lambda *a: FakeResponse(404, {"detail": "no"}, headers=JSON_CT)),
                           url)
        assert rec.calls[0]["url"] == url
        assert r.tried_urls[0] == url

    def test_requests_are_sequential_and_paced(self, monkeypatch, slept):
        r, rec = run_probe(monkeypatch,
                           always(lambda *a: FakeResponse(404, {"detail": "no"}, headers=JSON_CT)),
                           "https://bot.example.com/", rate_limit_s=1.5, max_attempts=5)
        assert len(rec.calls) == 5
        assert len(slept) == 4, "one pause between each pair of requests"
        assert all(0 < w <= 1.5 for w in slept)

    def test_rate_limit_zero_means_no_sleeping(self, monkeypatch, slept):
        run_probe(monkeypatch,
                  always(lambda *a: FakeResponse(404, {"detail": "no"}, headers=JSON_CT)),
                  "https://bot.example.com/", rate_limit_s=0.0, max_attempts=5)
        assert slept == []

    def test_only_the_one_benign_prompt_is_ever_sent(self, monkeypatch):
        """Discovery is reconnaissance; adversarial payloads are the assessment's job."""
        r, rec = run_probe(monkeypatch,
                           always(lambda *a: FakeResponse(400, {"error": "no"}, headers=JSON_CT)),
                           "https://bot.example.com/api/chat")
        assert len(rec.calls) > 5
        for call in rec.calls:
            data = call["data"]
            if isinstance(data, dict):                    # a form-encoded candidate (data= mapping)
                data = json.dumps(data)
            wire = json.dumps(call["json"]) if call["json"] is not None else (data or "")
            params = call["kwargs"].get("params") or {}
            blob = wire + json.dumps(params)
            assert DEFAULT_PROMPT in blob or blob in ("", "{}")
            for banned in ("ignore previous", "system prompt", "DAN", "'", "--", "<script"):
                assert banned not in blob

    def test_a_custom_prompt_is_the_only_prompt_used(self, monkeypatch):
        url = "https://bot.example.com/api/chat"
        r, rec = run_probe(monkeypatch,
                           serve({url: lambda m, u, k: FakeResponse(
                               200, {"reply": "Yes, we are open until 6pm on weekdays."},
                               headers=JSON_CT)}),
                           url, prompt="What are your opening hours?")
        assert r.ok is True
        assert r.prompt == "What are your opening hours?"
        assert rec.calls[0]["json"] == {"message": "What are your opening hours?"}
        assert r.evidence["prompt_sent"] == "What are your opening hours?"

    def test_pinned_method_is_respected(self, monkeypatch):
        url = "https://bot.example.com/api/ask"

        def get_only(method, url_, kw):
            if method == "GET" and (kw.get("params") or {}).get("q"):
                return FakeResponse(200, {"answer": "Sure, happy to help with that."},
                                    headers=JSON_CT)
            return FakeResponse(404, {"detail": "no"}, headers=JSON_CT)

        r, rec = run_probe(monkeypatch, serve({url: get_only}), url, method="GET")
        assert r.ok is True
        assert r.method == "GET"
        assert {c["method"] for c in rec.calls} == {"GET"}, "a pinned verb must not be violated"

    def test_timeout_is_passed_to_every_request(self, monkeypatch):
        r, rec = run_probe(monkeypatch,
                           always(lambda *a: FakeResponse(404, {"detail": "no"}, headers=JSON_CT)),
                           "https://bot.example.com/", timeout_s=4.5, max_attempts=4)
        assert all(c["kwargs"]["timeout"] == 4.5 for c in rec.calls)


# =========================================================================== #
# 8. Pure helpers (no HTTP at all)
# =========================================================================== #
class TestPureHelpers:
    def test_no_network_at_import_time(self):
        """`requests` is imported lazily; importing the module must be inert."""
        import importlib
        mod = importlib.reload(probe)
        assert mod.DEFAULT_PROMPT == DEFAULT_PROMPT

    def test_candidate_endpoints_puts_the_given_url_first(self):
        cands = probe.candidate_endpoints("https://h/api/v2/bot", limit=8)
        assert cands[0] == "https://h/api/v2/bot"
        assert "https://h/api/v2/bot/chat" in cands
        assert "https://h/api/v2/chat" in cands
        assert "https://h/chat" in cands

    def test_candidate_endpoints_are_unique_and_capped(self):
        cands = probe.candidate_endpoints("https://h/", limit=5)
        assert len(cands) == 5
        assert len(set(cands)) == 5

    def test_candidate_endpoints_assume_https(self):
        assert probe.candidate_endpoints("h.example.com/api", limit=1) == \
            ["https://h.example.com/api"]

    def test_candidate_endpoints_preserve_the_query_string(self):
        assert probe.candidate_endpoints("https://h/api?tenant=acme", limit=1) == \
            ["https://h/api?tenant=acme"]

    def test_candidate_endpoints_extra_paths_come_first(self):
        cands = probe.candidate_endpoints("https://h/", extra_paths=["zzz"], limit=3)
        assert cands[0] == "https://h/zzz"

    def test_candidate_endpoints_rejects_a_relative_url(self):
        with pytest.raises(ValueError):
            probe.candidate_endpoints("/api/chat")

    def test_default_shapes_are_verb_filtered(self):
        assert {s.method for s in probe.default_shapes("GET")} == {"GET"}
        assert {s.method for s in probe.default_shapes("PUT")} == {"PUT"}
        assert {s.method for s in probe.default_shapes(None)} == {"POST", "GET"}

    def test_default_shapes_all_carry_the_placeholder(self):
        for shape in probe.default_shapes(None):
            rendered = json.dumps(shape.body) if shape.body is not None else (shape.raw or "")
            assert probe.PROMPT_TOKEN in rendered or shape.query_param

    def test_shape_render_escapes_the_prompt(self):
        shape = probe.Shape("t", "POST", body={"message": probe.PROMPT_TOKEN})
        out = shape.render('he said "hi" \\ and left')
        assert out == {"message": 'he said "hi" \\ and left'}

    def test_string_paths_walks_lists_and_dicts(self):
        assert probe.string_paths({"a": {"b": "x"}, "c": ["y", {"d": "z"}]}) == \
            [("a.b", "x"), ("c.0", "y"), ("c.1.d", "z")]

    def test_dot_get_indexes_lists_and_tolerates_misses(self):
        obj = {"a": {"b": [{"c": "found"}]}}
        assert probe.dot_get(obj, "a.b.0.c") == "found"
        assert probe.dot_get(obj, "a.b.9.c") is None
        assert probe.dot_get(obj, "nope") is None
        assert probe.dot_get(obj, "") is None


# =========================================================================== #
# 9. Known defect — reproduced offline so the fix is detectable
# =========================================================================== #
class StreamConsumedResponse:
    """A `requests.Response` look-alike with REAL streaming semantics.

    `conftest.FakeResponse.text` is a plain attribute, so it stays readable after
    `iter_lines()` is exhausted. A live `requests` response does not: once a
    streamed body has been consumed, touching `.text` raises
    ``RuntimeError: The content for this response was already consumed``.
    """

    def __init__(self, status_code=200, body="", headers=None):
        self.status_code = status_code
        self.headers = headers or {}
        self._body = body
        self._consumed = False

    def iter_lines(self, *_a, **_kw):
        self._consumed = True
        for line in self._body.splitlines():
            yield line.encode("utf-8")

    @property
    def text(self):
        if self._consumed:
            raise RuntimeError("The content for this response was already consumed")
        return self._body

    def close(self):
        pass


def test_empty_200_over_a_real_stream_is_a_diagnosis_not_a_crash(monkeypatch):
    url = "https://bot.example.com/api/chat"

    def handler(method, u, kw):
        if u == url:
            return StreamConsumedResponse(200, "", headers=JSON_CT)
        return StreamConsumedResponse(404, '{"detail":"no"}', headers=JSON_CT)

    r, _ = run_probe(monkeypatch, handler, url, max_attempts=4)
    assert r.ok is False
    assert r.diagnosis in ("bad_shape", "not_found")
