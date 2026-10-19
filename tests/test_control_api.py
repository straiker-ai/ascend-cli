"""
test_control_api.py — the Ascend v3 platform API client, fully offline.

Covers the fiddly, easy-to-regress behaviours:
  * PAT → JWT RFC-8693 token exchange (correct grant + subject token type);
  * a 401 forces exactly ONE re-exchange, then gives up (no infinite loop);
  * a direct (non-PAT) bearer is used as-is with no exchange;
  * run() drives the create → PAUSE → resume lifecycle in that exact order
    (a new assessment is `created`, and resume-on-created is a 409);
  * _safe_transition swallows a 409 (already in target state);
  * validate_controls flags deprecated / unknown / zero-scorable-control runs;
  * the spec builders emit v3's JSON-string templates + headers-array shape;
  * _clean_templates strips the `{{ PROMPT }}` spaces gotcha.

All HTTP is mocked at requests.{post,request}; no sockets.
"""
import importlib
import json

import pytest

from conftest import FakeResponse, install_fake_requests

api = importlib.import_module("api")
AscendAPI = api.AscendAPI
AscendAPIError = api.AscendAPIError


# --------------------------------------------------------------------------- #
# token exchange
# --------------------------------------------------------------------------- #
def test_pat_exchange_shape(monkeypatch):
    seen = {}

    def handler(method, url, kwargs):
        if url.endswith("/auth/token"):
            seen["exchange"] = kwargs
            return FakeResponse(200, {"access_token": "JWT-123"})
        seen["main_headers"] = kwargs["headers"]
        return FakeResponse(200, {"applications": []})

    install_fake_requests(monkeypatch, handler)
    client = AscendAPI(token="s6r_pat_abc")
    client.list_apps()

    form = seen["exchange"]["data"]
    assert form["grant_type"] == "urn:ietf:params:oauth:grant-type:token-exchange"
    assert form["subject_token"] == "s6r_pat_abc"
    assert form["subject_token_type"] == "urn:straiker:params:oauth:token-type:pat"
    assert seen["main_headers"]["Authorization"] == "Bearer JWT-123"


def test_jwt_cached_across_calls(monkeypatch):
    counts = {"exchange": 0}

    def handler(method, url, kwargs):
        if url.endswith("/auth/token"):
            counts["exchange"] += 1
            return FakeResponse(200, {"access_token": "JWT-1"})
        return FakeResponse(200, {"ok": True})

    install_fake_requests(monkeypatch, handler)
    client = AscendAPI(token="s6r_pat_x")
    client.list_apps()
    client.list_controls()
    client.list_apps()
    assert counts["exchange"] == 1  # exchanged once, then cached


def test_direct_bearer_no_exchange(monkeypatch):
    counts = {"exchange": 0}

    def handler(method, url, kwargs):
        if url.endswith("/auth/token"):
            counts["exchange"] += 1
            return FakeResponse(200, {"access_token": "SHOULD-NOT-HAPPEN"})
        assert kwargs["headers"]["Authorization"] == "Bearer already-a-jwt"
        return FakeResponse(200, {"ok": True})

    install_fake_requests(monkeypatch, handler)
    client = AscendAPI(token="already-a-jwt")  # not s6r_pat_
    client.list_apps()
    assert counts["exchange"] == 0


def test_exchange_failure_raises(monkeypatch):
    def handler(method, url, kwargs):
        if url.endswith("/auth/token"):
            return FakeResponse(400, text="bad pat")
        return FakeResponse(200, {})

    install_fake_requests(monkeypatch, handler)
    client = AscendAPI(token="s6r_pat_bad")
    with pytest.raises(AscendAPIError):
        client.list_apps()


def test_exchange_missing_access_token_raises(monkeypatch):
    def handler(method, url, kwargs):
        if url.endswith("/auth/token"):
            return FakeResponse(200, {"not_a_token": "x"})
        return FakeResponse(200, {})

    install_fake_requests(monkeypatch, handler)
    client = AscendAPI(token="s6r_pat_x")
    with pytest.raises(AscendAPIError):
        client.list_apps()


def test_no_token_raises(monkeypatch):
    monkeypatch.delenv("STRAIKER_PAT", raising=False)
    monkeypatch.delenv("STRAIKER_TOKEN", raising=False)
    with pytest.raises(AscendAPIError):
        AscendAPI(token=None)


# --------------------------------------------------------------------------- #
# 401 → exactly one re-exchange, then stop
# --------------------------------------------------------------------------- #
def test_401_triggers_exactly_one_reexchange(monkeypatch):
    counts = {"exchange": 0, "main": 0}

    def handler(method, url, kwargs):
        if url.endswith("/auth/token"):
            counts["exchange"] += 1
            return FakeResponse(200, {"access_token": f"JWT-{counts['exchange']}"})
        counts["main"] += 1
        return FakeResponse(401, text="expired")

    install_fake_requests(monkeypatch, handler)
    client = AscendAPI(token="s6r_pat_x")
    with pytest.raises(AscendAPIError) as ei:
        client.list_apps()
    assert "401" in str(ei.value)
    # initial exchange + exactly one re-exchange
    assert counts["exchange"] == 2
    # initial request + exactly one retry
    assert counts["main"] == 2


def test_401_then_success_after_reexchange(monkeypatch):
    counts = {"exchange": 0, "main": 0}

    def handler(method, url, kwargs):
        if url.endswith("/auth/token"):
            counts["exchange"] += 1
            return FakeResponse(200, {"access_token": f"JWT-{counts['exchange']}"})
        counts["main"] += 1
        if counts["main"] == 1:
            return FakeResponse(401, text="expired")
        return FakeResponse(200, {"applications": ["recovered"]})

    install_fake_requests(monkeypatch, handler)
    client = AscendAPI(token="s6r_pat_x")
    out = client.list_apps()
    assert out == {"applications": ["recovered"]}
    assert counts["exchange"] == 2
    assert counts["main"] == 2


def test_direct_bearer_401_not_retried(monkeypatch):
    counts = {"main": 0}

    def handler(method, url, kwargs):
        counts["main"] += 1
        return FakeResponse(401, text="nope")

    install_fake_requests(monkeypatch, handler)
    client = AscendAPI(token="raw-jwt")  # non-PAT → no re-exchange path
    with pytest.raises(AscendAPIError):
        client.list_apps()
    assert counts["main"] == 1  # no retry for a direct bearer


# --------------------------------------------------------------------------- #
# error status propagation
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("code", [400, 404, 409, 422, 500, 503])
def test_error_status_raises_with_code(monkeypatch, code):
    def handler(method, url, kwargs):
        if url.endswith("/auth/token"):
            return FakeResponse(200, {"access_token": "JWT"})
        return FakeResponse(code, text="boom")

    install_fake_requests(monkeypatch, handler)
    client = AscendAPI(token="s6r_pat_x")
    with pytest.raises(AscendAPIError) as ei:
        client.get_app("aapp_1")
    assert str(code) in str(ei.value)


# --------------------------------------------------------------------------- #
# run() lifecycle: create → PAUSE → resume → poll (exact order)
# --------------------------------------------------------------------------- #
def test_run_calls_create_pause_resume_poll_in_order(monkeypatch):
    order = []
    client = AscendAPI(token="s6r_pat_x")

    monkeypatch.setattr(client, "create_assessment",
                        lambda app, name: order.append("create") or {"id": "asmt_1"})
    monkeypatch.setattr(client, "pause",
                        lambda app, aid: order.append(("pause", aid)))
    monkeypatch.setattr(client, "resume",
                        lambda app, aid: order.append(("resume", aid)))
    monkeypatch.setattr(client, "poll_assessment",
                        lambda app, aid, **kw: order.append("poll") or {"status": "completed"})
    monkeypatch.setattr(client, "live_assessment", lambda app: None)
    monkeypatch.setattr(client, "get_assessment", lambda app, aid: {"status": "running"})

    result = client.run("aapp_1", "run-1", settle=0)
    assert result["status"] == "completed"
    assert result["assessment_id"] == "asmt_1" and result["started"] is True
    assert order == ["create", ("pause", "asmt_1"), ("resume", "asmt_1"), "poll"]


def test_run_no_wait_skips_poll(monkeypatch):
    order = []
    client = AscendAPI(token="s6r_pat_x")
    monkeypatch.setattr(client, "create_assessment", lambda a, n: {"id": "asmt_9"})
    monkeypatch.setattr(client, "pause", lambda a, aid: order.append("pause"))
    monkeypatch.setattr(client, "resume", lambda a, aid: order.append("resume"))
    monkeypatch.setattr(client, "poll_assessment",
                        lambda *a, **k: order.append("poll"))
    monkeypatch.setattr(client, "live_assessment", lambda app: None)
    monkeypatch.setattr(client, "get_assessment", lambda app, aid: {"status": "running"})
    out = client.run("aapp_1", "r", wait=False, settle=0)
    assert out["assessment_id"] == "asmt_9"
    assert out["status"] == "running"
    assert "poll" not in order
    assert order == ["pause", "resume"]


def test_run_no_assessment_id_raises(monkeypatch):
    client = AscendAPI(token="s6r_pat_x")
    monkeypatch.setattr(client, "live_assessment", lambda app: None)
    monkeypatch.setattr(client, "create_assessment", lambda a, n: {"no": "id"})
    monkeypatch.setattr(client._s, "request", lambda *a, **k: pytest.fail("unexpected HTTP request"))
    with pytest.raises(AscendAPIError, match="assessment create returned no id"):
        client.run("aapp_1", "r", wait=False)


# --------------------------------------------------------------------------- #
# _safe_transition swallows 409, re-raises other errors
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("msg", ["POST ... -> 409: conflict",
                                 "invalid_assessment_state"])
def test_safe_transition_swallows_409(monkeypatch, msg):
    client = AscendAPI(token="s6r_pat_x")

    def raiser(app, aid):
        raise AscendAPIError(msg)

    # should NOT raise
    client._safe_transition(raiser, "aapp", "asmt", want="paused")


def test_safe_transition_reraises_other_errors():
    client = AscendAPI(token="s6r_pat_x")

    def raiser(app, aid):
        raise AscendAPIError("POST ... -> 500: server error")

    with pytest.raises(AscendAPIError):
        client._safe_transition(raiser, "aapp", "asmt", want="paused")


def test_run_tolerates_409_on_pause(monkeypatch):
    order = []
    client = AscendAPI(token="s6r_pat_x")
    monkeypatch.setattr(client, "create_assessment", lambda a, n: {"id": "asmt_1"})

    def pause(app, aid):
        raise AscendAPIError("POST /pause -> 409: invalid_assessment_state")

    monkeypatch.setattr(client, "pause", pause)
    monkeypatch.setattr(client, "resume", lambda a, aid: order.append("resume"))
    monkeypatch.setattr(client, "poll_assessment", lambda *a, **k: {"status": "completed"})
    monkeypatch.setattr(client, "live_assessment", lambda app: None)
    monkeypatch.setattr(client, "get_assessment", lambda app, aid: {"status": "running"})
    out = client.run("aapp_1", "r")
    assert out["status"] == "completed" and out["started"] is True
    assert order == ["resume"]  # proceeded past the tolerated 409


# --------------------------------------------------------------------------- #
# validate_controls
# --------------------------------------------------------------------------- #
CATALOG = {"controls": [
    {"id": "sys_prompt_leak"},
    {"id": "instruction_manipulation"},
    {"id": "agentic_data_exfil", "agentic": True},
    {"id": "agentic_tmu", "agentic": True},
    {"id": "old_control", "deprecated": True},
]}


def _client_with_catalog(monkeypatch, catalog=CATALOG):
    client = AscendAPI(token="s6r_pat_x")
    monkeypatch.setattr(client, "list_controls", lambda: catalog)
    return client


def test_validate_controls_all_valid(monkeypatch):
    c = _client_with_catalog(monkeypatch)
    r = c.validate_controls(["sys_prompt_leak", "instruction_manipulation"])
    assert r["valid"] == ["sys_prompt_leak", "instruction_manipulation"]
    assert r["deprecated"] == []
    assert r["unknown"] == []
    assert r["warnings"] == []


def test_validate_controls_flags_deprecated(monkeypatch):
    c = _client_with_catalog(monkeypatch)
    r = c.validate_controls(["sys_prompt_leak", "old_control"])
    assert r["deprecated"] == ["old_control"]
    assert "old_control" not in r["valid"]
    assert any("deprecated" in w for w in r["warnings"])


def test_validate_controls_flags_unknown(monkeypatch):
    c = _client_with_catalog(monkeypatch)
    r = c.validate_controls(["sys_prompt_leak", "does_not_exist"])
    assert r["unknown"] == ["does_not_exist"]
    assert any("unknown" in w for w in r["warnings"])


def test_validate_controls_flags_agentic(monkeypatch):
    c = _client_with_catalog(monkeypatch)
    r = c.validate_controls(["agentic_data_exfil", "agentic_tmu"])
    assert set(r["agentic"]) == {"agentic_data_exfil", "agentic_tmu"}
    assert set(r["valid"]) == {"agentic_data_exfil", "agentic_tmu"}


def test_validate_controls_zero_scorable_warns(monkeypatch):
    c = _client_with_catalog(monkeypatch)
    r = c.validate_controls(["old_control", "nope"])
    assert r["valid"] == []
    assert any("zero probes" in w for w in r["warnings"])


def test_validate_controls_empty_input(monkeypatch):
    c = _client_with_catalog(monkeypatch)
    r = c.validate_controls([])
    assert r["valid"] == []
    assert any("zero probes" in w for w in r["warnings"])


def test_validate_controls_catalog_wrapped_dict(monkeypatch):
    # the authoritative shape is {"controls": [...]}, optionally with extra keys
    c = AscendAPI(token="s6r_pat_x")
    monkeypatch.setattr(c, "list_controls",
                        lambda: {"controls": [{"id": "a"}, {"id": "b", "deprecated": True}],
                                 "total": 2})
    r = c.validate_controls(["a", "b", "c"])
    assert r["valid"] == ["a"]
    assert r["deprecated"] == ["b"]
    assert r["unknown"] == ["c"]


def test_validate_controls_handles_bare_list_catalog(monkeypatch):
    # A bare-list catalog (no {"controls": ...} envelope) is now handled, not raised:
    # isinstance is checked before cat.get. A known id resolves as valid.
    c = AscendAPI(token="s6r_pat_x")
    monkeypatch.setattr(c, "list_controls", lambda: [{"id": "a"}])
    res = c.validate_controls(["a"])
    assert res["valid"] == ["a"]
    assert res["unknown"] == []


# --------------------------------------------------------------------------- #
# spec builders + _clean_templates
# --------------------------------------------------------------------------- #
def test_build_api_spec_shape():
    spec = api.build_api_spec(
        name="t", url="https://x/api", system_prompt="sp",
        control_ids=["sys_prompt_leak"], qpm=6)
    assert spec["api_type"] == "api"
    assert spec["control_type"] == "custom"
    assert spec["control_ids"] == ["sys_prompt_leak"]
    assert spec["max_queries_per_minute"] == 6
    # templates serialized to JSON strings
    assert isinstance(spec["request_template"], str)
    assert json.loads(spec["request_template"]) == {"prompt": "{{PROMPT}}"}
    assert isinstance(spec["response_template"], str)
    # headers as an array of {name,value}
    assert isinstance(spec["headers"], list)
    assert all("name" in h and "value" in h for h in spec["headers"])


def test_build_api_spec_control_type_all_when_no_ids():
    spec = api.build_api_spec(name="t", url="https://x", system_prompt="sp")
    assert spec["control_type"] == "all"
    assert "control_ids" not in spec


def test_build_thin_spec_shape():
    spec = api.build_thin_spec(name="t", system_prompt="sp",
                               control_ids=["a", "b"])
    assert spec["api_type"] == "thin"
    assert "url" not in spec  # thin apps have no direct url
    assert spec["control_type"] == "custom"
    assert spec["control_ids"] == ["a", "b"]


def test_build_spec_headers_passthrough_when_already_array():
    hdrs = [{"name": "Authorization", "value": "Bearer x"}]
    spec = api.build_api_spec(name="t", url="u", system_prompt="s", headers=hdrs)
    assert spec["headers"] == hdrs


@pytest.mark.parametrize("template", [
    {"prompt": "{{ PROMPT }}"},
    {"response": "{{ RESPONSE }}"},
    {"a": "{{ PROMPT }}", "b": "{{ RESPONSE }}"},
    {"nested": {"deep": "{{ PROMPT }}"}},
])
def test_clean_templates_strips_spaces(template):
    cleaned = api._clean_templates(template)
    s = json.dumps(cleaned)
    assert "{{ PROMPT }}" not in s
    assert "{{ RESPONSE }}" not in s
    # the no-space forms survive
    if "PROMPT" in json.dumps(template):
        assert "{{PROMPT}}" in s


def test_clean_templates_non_dict_passthrough():
    assert api._clean_templates("a string") == "a string"


# --------------------------------------------------------------------------- #
# summarize_result
# --------------------------------------------------------------------------- #
# The real /assessments payload shape, copied from a live completed run.
_REAL_ASSESSMENT = {
    "id": "asmt_x", "status": "complete", "score": 76, "severity": "high",
    "failed": 15, "total": 19,
    "category_summary": [
        {"id": "agent_vulnerabilities", "name": "Agentic Risks", "failed": 15, "total": 15,
         "controls": [{"id": "agentic_data_exfil", "status": "fail", "severity": "high",
                       "failed": 15, "total": 15,
                       "keyfindings": ["Exfiltrated member data via tool chain"]}]},
        {"id": "sys_prompt_leak", "name": "System Prompt Leak", "failed": 0, "total": 4,
         "controls": [{"id": "sys_prompt_leak", "status": "pass", "severity": "medium",
                       "failed": 0, "total": 4}]},
    ],
    "recommendations": [{"title": "Improve system prompt",
                         "description": "Hardening your system prompt may help."}],
}


def test_summarize_result_uses_category_name_not_id():
    """REGRESSION: read c['name']; the old code read c['category'] and printed '?'."""
    out = api.summarize_result(_REAL_ASSESSMENT)
    assert "Agentic Risks" in out
    assert "System Prompt Leak" in out
    assert "?" not in out.split("recommendations")[0]


def test_summarize_result_lists_per_control_findings():
    out = api.summarize_result(_REAL_ASSESSMENT)
    assert "agentic_data_exfil" in out
    assert "FAIL" in out and "pass" in out
    assert "15/15" in out


def test_summarize_result_renders_recommendation_dicts_not_repr():
    """REGRESSION: recommendations printed as raw Python dicts."""
    out = api.summarize_result(_REAL_ASSESSMENT)
    assert "Improve system prompt" in out
    assert "{'title'" not in out and '{"title"' not in out


def test_summarize_result_severity_counts():
    out = api.summarize_result(_REAL_ASSESSMENT)
    assert "1 high" in out          # one failing high-severity control


def test_summarize_result_detail_shows_keyfindings():
    plain = api.summarize_result(_REAL_ASSESSMENT)
    detail = api.summarize_result(_REAL_ASSESSMENT, detail=True)
    assert "Exfiltrated member data" not in plain
    assert "Exfiltrated member data" in detail


def test_iter_findings_sorts_failures_first_by_severity():
    f = api.iter_findings(_REAL_ASSESSMENT)
    assert f[0]["id"] == "agentic_data_exfil" and f[0]["status"] == "fail"
    assert f[-1]["status"] == "pass"


def test_summarize_result_non_dict():
    assert api.summarize_result("raw string") == "raw string"


# --------------------------------------------------------------------------- #
# poll_assessment terminal detection (mock get_assessment, no sleep)
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("terminal", ["completed", "complete", "failed",
                                      "cancelled", "canceled", "error", "done"])
def test_poll_returns_on_terminal_status(monkeypatch, terminal):
    client = AscendAPI(token="s6r_pat_x")
    monkeypatch.setattr(client, "get_assessment",
                        lambda app, aid: {"status": terminal, "progress": 1.0})
    out = client.poll_assessment("aapp", "asmt", interval=1, timeout=5)
    assert str(out["status"]).lower() == terminal


def test_poll_timeout_raises(monkeypatch):
    import itertools
    client = AscendAPI(token="s6r_pat_x")
    monkeypatch.setattr(client, "get_assessment",
                        lambda app, aid: {"status": "running", "progress": 0.5})
    monkeypatch.setattr(api.time, "sleep", lambda *_a, **_k: None)
    # monotonically advancing clock so the deadline is immediately exceeded
    clock = itertools.count(0, 1000)
    monkeypatch.setattr(api.time, "time", lambda: next(clock))
    with pytest.raises(AscendAPIError):
        client.poll_assessment("aapp", "asmt", interval=1, timeout=1)
