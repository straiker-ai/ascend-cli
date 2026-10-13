"""
Registering a target once, reaching it directly, and proving a run started.

Every test here pins a defect that reached a live tenant: one afternoon of `target add` produced
28 identically named applications, all bridge-type, with no assessment that ever ran. The causes
were in this CLI, not in the operator:

  * `target add` always created, and always created a BRIDGE app — there was no direct path.
  * the one function that could build a direct app read `url` while the deriver wrote `endpoint`,
    added a second `{{PROMPT}}` field, and flattened a nested answer path into a key that matches
    nothing.
  * `run --no-wait` returned a hard-coded "running" it had never checked, while the platform had
    already put the run back to paused.
"""
from __future__ import annotations

import json
import os
import re
import sys
import types
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "shells" / "cli"))
sys.path.insert(0, str(REPO / "runtime"))
sys.path.insert(0, str(REPO / "control"))
sys.path.insert(0, str(REPO))
import api  # noqa: E402
import ascend  # noqa: E402
from runtime.discovery import profiles  # noqa: E402

SRC = (REPO / "shells" / "cli" / "ascend.py").read_text()

# The config `target add` really writes — captured from a live derivation, not imagined.
DERIVED = {
    "adapter": "direct_api",
    "endpoint": "https://bot.example.com/api/chat",
    "method": "POST",
    "body": {"message": "{{PROMPT}}", "workspace": "retail-support"},
    "response_path": "message",
    "headers": {"x-demo-key": "pass", "Authorization": "Bearer sk_live_abcdef123456"},
}


# ------------------------------------------------------------------ the direct contract
class TestApiContract:
    def test_the_address_is_read_from_endpoint(self):
        assert ascend._api_contract(DERIVED)["url"] == "https://bot.example.com/api/chat"

    def test_an_older_config_that_says_url_still_works(self):
        cfg = {**DERIVED, "url": "https://old.example.com/x"}
        cfg.pop("endpoint")
        assert ascend._api_contract(cfg)["url"] == "https://old.example.com/x"

    def test_a_templated_body_is_not_given_a_second_placeholder(self):
        body = ascend._api_contract(DERIVED)["request_template"]
        assert body == {"message": "{{PROMPT}}", "workspace": "retail-support"}
        assert json.dumps(body).count("{{PROMPT}}") == 1

    def test_a_nested_placeholder_counts_as_templated(self):
        cfg = {**DERIVED, "body": {"messages": [{"role": "user", "content": "{{PROMPT}}"}]}}
        assert "prompt" not in ascend._api_contract(cfg)["request_template"]

    def test_a_literal_body_gets_the_placeholder_on_its_prompt_field(self):
        cfg = {**DERIVED, "body": {"q": "hello", "lang": "en"}, "prompt_field": "q"}
        assert ascend._api_contract(cfg)["request_template"] == {"lang": "en", "q": "{{PROMPT}}"}

    @pytest.mark.parametrize("path,expected", [
        ("message", {"message": "{{RESPONSE}}"}),
        ("data.reply", {"data": {"reply": "{{RESPONSE}}"}}),
        # byte-for-byte the template on an application that demonstrably completes runs
        ("choices.0.message.content", {"choices": [{"message": {"content": "{{RESPONSE}}"}}]}),
        ("output[0].text", {"output": [{"text": "{{RESPONSE}}"}]}),
    ])
    def test_the_answer_path_becomes_a_nested_mirror(self, path, expected):
        assert ascend._response_template_from_path(path) == expected

    def test_the_required_api_key_is_lifted_from_the_bearer(self):
        assert ascend._api_contract(DERIVED)["api_key"] == "sk_live_abcdef123456"

    def test_the_credential_stays_in_the_request_as_well(self):
        """Measured: the platform does not inject `api_key` into the call. Lifting it OUT of the
        headers left the target unauthenticated and the run paused itself within 20 seconds."""
        assert ascend._api_contract(DERIVED)["headers"]["Authorization"].startswith("Bearer ")

    def test_a_key_carried_in_the_body_is_found(self):
        cfg = {**DERIVED, "headers": {}, "body": {"message": "{{PROMPT}}", "apiKey": "sk_body_1234567"}}
        assert ascend._lift_api_key(cfg) == "sk_body_1234567"

    def test_an_open_target_still_gets_a_value_the_platform_will_accept(self):
        assert ascend._lift_api_key({"headers": {}, "body": {"message": "{{PROMPT}}"}}) == "none"

    def test_app_create_and_target_add_share_one_contract_builder(self):
        """Two builders drifted once already; that drift is why the direct path never worked."""
        body = SRC[SRC.index("def _spec_from_config("):SRC.index("_PRIVATE_SUFFIXES")]
        assert "_api_contract(cfg)" in body
        assert 'cfg.get("response_path")' not in body


# ------------------------------------------------------------------ the default: a hosted adaptor
class TestDefaultIsAHostedAdaptor:
    """`target add` (via=auto) registers a direct app driven by generated JavaScript the engine
    runs; the bridge is the explicit, deprecated path. The owner's decision: locally run adapters
    are retired, so a public JSON endpoint, a stream, a socket and a session API all go the same
    way, and only what nothing generated can replace still falls to a bridge."""

    def _args(self, **kw):
        return types.SimpleNamespace(**{"via": "auto", **kw})

    @pytest.mark.parametrize("adapter,cfg", [
        ("direct_api", {"endpoint": "https://8.8.8.8/c"}),
        ("direct_api", {"endpoint": "https://8.8.8.8/c", "auth": {"type": "static"}}),
        ("sse_stream", {"base_url": "https://8.8.8.8", "chat_path": "/stream"}),
        ("websocket_direct", {"ws_url": "wss://8.8.8.8/ws"}),
        ("session_api", {"session_endpoint": "https://8.8.8.8/s", "message_endpoint": "https://8.8.8.8/m"}),
        ("session_poll", {"create": {"url": "https://8.8.8.8/c"}, "send": {"url": "https://8.8.8.8/c/{{CONV}}/m"},
                          "poll": {"url": "https://8.8.8.8/c/{{CONV}}"}}),
        ("copilot_studio", {"endpoint": "https://8.8.8.8/x"}),      # no generator: the scaffold, still hosted
    ])
    def test_every_shape_the_platform_can_reach_is_an_adaptor(self, adapter, cfg):
        via, why = ascend._choose_transport(self._args(), adapter, cfg)
        assert via == "adaptor" and "nothing runs on this machine" in why

    def test_two_env_referenced_credentials_are_a_list_and_do_not_crash(self):
        """`(cfg.get("auth") or {}).get("type")` raised AttributeError on the list form."""
        cfg = {"endpoint": "https://8.8.8.8/c",
               "auth": [{"type": "static", "mode": "custom", "name": "x-code", "value_ref": "env:A"},
                        {"type": "static", "mode": "bearer", "value_ref": "env:B"}]}
        assert ascend._auth_type(cfg) == "static"
        assert ascend._choose_transport(self._args(), "direct_api", cfg)[0] == "adaptor"
        assert ascend._auth_type({**cfg, "auth": [cfg["auth"][0], {"type": "oauth2"}]}) == "oauth2"
        assert ascend._auth_type({}) is None and ascend._auth_type({"auth": {"type": "csrf"}}) == "csrf"

    @pytest.mark.parametrize("adapter", ["custom", "browser"])
    def test_what_only_this_machine_can_run_still_takes_the_bridge_and_says_it_is_deprecated(self, adapter):
        via, why = ascend._choose_transport(self._args(), adapter, {"endpoint": "https://8.8.8.8/c"})
        assert via == "bridge" and adapter in why and "deprecated" in why

    @pytest.mark.parametrize("kind", ["oauth2", "csrf", "derived_multihop"])
    def test_a_login_handshake_is_adaptor_driven_with_the_scaffold_not_a_bridge(self, kind):
        """A handshake target defaulted to the DEPRECATED bridge, silently. It is now registered
        adaptor-driven: the generated file is the scaffold with the login named in its header,
        and the repair loop (`adaptor test` → finish → `adaptor store`) completes it."""
        via, why = ascend._choose_transport(self._args(), "direct_api",
                                            {"endpoint": "https://8.8.8.8/c", "auth": {"type": kind}})
        assert via == "adaptor"
        assert kind in why and "scaffold" in why and "adaptor test" in why and "adaptor store" in why
        assert "--via bridge" in why, "the way back to the old path is named"

    @pytest.mark.parametrize("kind", ["oauth2", "csrf", "derived_multihop"])
    def test_a_handshake_target_still_takes_the_bridge_on_request(self, kind):
        via, why = ascend._choose_transport(self._args(via="bridge"), "direct_api",
                                            {"endpoint": "https://8.8.8.8/c", "auth": {"type": kind}})
        assert via == "bridge" and "deprecated" in why

    def test_a_handshake_target_on_a_private_address_is_still_refused(self, monkeypatch):
        """The reachability gate comes first: the scaffold would run in the engine, which cannot
        dial a private address either."""
        monkeypatch.setattr(sys, "argv", ["ascend", "--json"])
        with pytest.raises(SystemExit):
            ascend._choose_transport(self._args(json=True), "direct_api",
                                     {"endpoint": "http://127.0.0.1:1/c", "auth": {"type": "oauth2"}})

    def test_the_handshake_kinds_are_one_list(self):
        """The CLI and the generator decide "handshake" from the same tuple."""
        from runtime.discovery import codegen_js as G
        assert tuple(ascend.DYNAMIC_AUTH_KINDS) == tuple(G.DYNAMIC_AUTH_KINDS)
        for kind in ascend.DYNAMIC_AUTH_KINDS:
            assert G.handshake_kind({"auth": {"type": kind}}) == kind
            assert G.handshake_kind({"auth": [{"type": "static"}, {"type": kind}]}) == kind
        assert G.handshake_kind({"auth": {"type": "static"}}) is None and G.handshake_kind({}) is None

    def test_a_private_address_is_refused_before_any_app_exists(self, monkeypatch):
        """The engine cannot reach it, so a hosted adaptor would only ever fail its test; say so
        now, with the two ways out, instead of creating an app that cannot work."""
        monkeypatch.setattr(sys, "argv", ["ascend", "--json"])
        with pytest.raises(SystemExit):
            ascend._choose_transport(self._args(json=True), "direct_api", {"endpoint": "http://127.0.0.1:1/c"})

    def test_an_explicit_bridge_is_honoured_and_labelled_deprecated(self):
        via, why = ascend._choose_transport(self._args(via="bridge"), "direct_api", {"endpoint": "https://8.8.8.8/c"})
        assert via == "bridge" and "deprecated" in why

    def test_an_explicit_plain_template_app_keeps_its_meaning(self):
        via, why = ascend._choose_transport(self._args(via="api"), "direct_api", {"endpoint": "https://8.8.8.8/c"})
        assert via == "api" and "speak its contract itself" in why
        with pytest.raises(SystemExit):
            ascend._choose_transport(self._args(via="api", json=True), "sse_stream",
                                     {"base_url": "https://8.8.8.8", "chat_path": "/s"})

    def test_the_contract_address_follows_the_shape(self):
        """`_api_contract` read only endpoint/url, so every other shape registered with no URL."""
        assert ascend._api_contract({"adapter": "sse_stream", "base_url": "https://h", "chat_path": "/sse/chat",
                                     "request_template": {"message": "{{PROMPT}}"}})["url"] == "https://h/sse/chat"
        assert ascend._api_contract({"adapter": "websocket_direct", "ws_url": "wss://h/ws"})["url"] == "wss://h/ws"
        assert ascend._api_contract({"adapter": "session_api", "session_endpoint": "https://h/s",
                                     "message_endpoint": "https://h/m"})["url"] == "https://h/m"
        assert ascend._api_contract({"adapter": "session_poll", "create": {"url": "https://h/c"},
                                     "send": {"url": "https://h/c/{{CONV}}/m"}, "poll": {"url": "https://h/c/{{CONV}}"}
                                     })["url"] == "https://h/c"
        sse = ascend._api_contract({"adapter": "sse_stream", "base_url": "https://h", "chat_path": "/x",
                                    "request_template": {"q": "{{PROMPT}}"}})
        assert sse["request_template"] == {"q": "{{PROMPT}}"}


# ------------------------------------------------------------------ the legacy form: direct first, bridge last
class TestTransport:
    """`onboard` has no --via; it keeps the pre-adaptor rule (via=None here)."""
    @pytest.mark.parametrize("url", [
        "http://127.0.0.1:8899/chat", "http://localhost:3000", "http://10.1.2.3/api",
        "https://192.168.1.20/chat", "http://172.16.0.9/x", "https://bot.internal/chat",
        "https://agent.corp/chat", "http://buildbox/chat", "http://169.254.169.254/latest",
        "http://[::1]:8080/chat",
    ])
    def test_private_addresses_are_not_public(self, url):
        assert ascend._is_public_host(url) is False

    def test_a_routable_address_is_public(self):
        assert ascend._is_public_host("https://8.8.8.8/chat") is True

    def test_a_name_that_does_not_resolve_is_treated_as_private(self):
        assert ascend._is_public_host("https://does-not-exist.invalid/chat") is False

    def _args(self, **kw):
        return types.SimpleNamespace(**{"via": None, **kw})

    def test_a_public_json_endpoint_goes_direct(self):
        via, _ = ascend._choose_transport(self._args(), "direct_api", {"endpoint": "https://8.8.8.8/c"})
        assert via == "api"

    def test_a_private_endpoint_needs_a_bridge_and_says_why(self):
        via, why = ascend._choose_transport(self._args(), "direct_api", {"endpoint": "http://127.0.0.1:1/c"})
        assert via == "bridge" and "not reachable" in why

    def test_a_protocol_the_platform_cannot_speak_needs_a_bridge(self):
        via, why = ascend._choose_transport(self._args(), "sse_stream", {"endpoint": "https://8.8.8.8/c"})
        assert via == "bridge" and "sse_stream" in why

    @pytest.mark.parametrize("kind", ["oauth2", "csrf", "derived_multihop"])
    def test_a_login_handshake_needs_a_bridge(self, kind):
        """A direct app carries static headers and nothing else; the handshake runs locally."""
        via, why = ascend._choose_transport(
            self._args(), "direct_api", {"endpoint": "https://8.8.8.8/c", "auth": {"type": kind}})
        assert via == "bridge" and kind in why

    def test_static_auth_does_not_force_a_bridge(self):
        via, _ = ascend._choose_transport(
            self._args(), "direct_api", {"endpoint": "https://8.8.8.8/c", "auth": {"type": "static"}})
        assert via == "api"

    def test_an_explicit_request_for_a_bridge_is_honoured(self):
        via, _ = ascend._choose_transport(self._args(via="bridge"), "direct_api", {"endpoint": "https://8.8.8.8/c"})
        assert via == "bridge"

    def test_insisting_on_direct_for_a_private_target_fails_loudly(self):
        with pytest.raises(SystemExit):
            ascend._choose_transport(self._args(via="api", json=True), "direct_api",
                                     {"endpoint": "http://127.0.0.1:1/c"})

    def test_registration_consults_both_the_lookup_and_the_transport_choice(self):
        reg = SRC[SRC.index("# 3. register"):SRC.index("# `target add` stops here.")]
        assert "c.find_app_by_name(app_name)" in reg
        assert "_choose_transport(args, adapter, cfg)" in reg
        # a bridge app is built in exactly one place, behind the transport decision
        # one name guard, ahead of BOTH builders
        assert reg.count("_refuse_duplicate_app_name(") == 1
        assert reg.index("_refuse_duplicate_app_name(") < reg.index("api.build_api_spec(")
        assert reg.count("api.build_thin_spec(") == 1
        assert reg.index("_choose_transport(") < reg.index("api.build_thin_spec(")


# ------------------------------------------------------------------ one target, one application
def _client(rows=None, history=None):
    c = api.AscendAPI(token="s6r_pat_x")
    history = history or {}

    def fake_req(method, path, **kw):
        if method == "GET" and path.startswith("/ascend/applications?"):
            return {"data": rows or []}
        m = re.match(r"/ascend/applications/([^/]+)/assessments$", path)
        if method == "GET" and m:
            return {"data": history.get(m.group(1), [])}
        raise AssertionError(f"unexpected {method} {path}")
    c._req = fake_req
    return c


class TestOneTargetOneApplication:
    def test_an_existing_application_is_found_by_name(self):
        c = _client([{"id": "aapp_1", "name": "Retail Bot"}])
        assert c.find_app_by_name("Retail Bot")["id"] == "aapp_1"

    def test_the_match_ignores_case_and_stray_whitespace(self):
        c = _client([{"id": "aapp_1", "name": "Retail  Bot "}])
        assert c.find_app_by_name("  retail bot")["id"] == "aapp_1"

    def test_a_partial_name_is_not_a_match(self):
        c = _client([{"id": "aapp_1", "name": "Retail Bot (staging)"}])
        assert c.find_app_by_name("Retail Bot") is None

    def test_among_older_duplicates_the_one_with_history_wins(self):
        rows = [{"id": "aapp_empty", "name": "x", "created_at": "2026-09-19"},
                {"id": "aapp_used", "name": "x", "created_at": "2026-09-01"}]
        c = _client(rows, history={"aapp_used": [{"id": "asmt_1", "status": "complete"}]})
        assert c.find_app_by_name("x")["id"] == "aapp_used"

    def test_the_listing_asks_for_a_full_page(self):
        seen = []
        c = api.AscendAPI(token="s6r_pat_x")
        c._req = lambda m, p, **kw: seen.append(p) or {"data": []}
        c.list_apps()
        assert "limit=" in seen[0]


# ------------------------------------------------------------------ a start that is proven
class TestVerifiedStart:
    def test_a_finished_run_the_platform_calls_running_is_still_finished(self):
        """Measured: resume on a completed run is accepted and leaves it `running` forever."""
        assert api.is_finished({"status": "running", "progress": 1,
                                "completed_at": "2026-09-20T03:57:52Z"}) is True

    def test_a_run_in_flight_is_not_finished(self):
        assert api.is_finished({"status": "running", "progress": 0.4, "completed_at": None}) is False

    def test_an_unfinished_run_is_picked_up_instead_of_creating_another(self):
        c = _client(history={"aapp_1": [{"id": "asmt_old", "status": "paused",
                                         "created_at": "2026-09-20"}]})
        created = []
        c.create_assessment = lambda a, n: created.append(n) or {"id": "asmt_new"}
        c.pause = c.resume = lambda a, aid: None
        c.get_assessment = lambda a, aid: {"status": "running"}
        out = c.run("aapp_1", "second attempt", wait=False, settle=0)
        assert created == []
        assert out["assessment_id"] == "asmt_old" and out["reused_assessment"] is True

    def test_new_forces_a_fresh_run(self):
        c = _client(history={"aapp_1": [{"id": "asmt_old", "status": "paused"}]})
        c.create_assessment = lambda a, n: {"id": "asmt_new"}
        c.pause = c.resume = lambda a, aid: None
        c.get_assessment = lambda a, aid: {"status": "running"}
        assert c.run("aapp_1", "r", wait=False, new=True, settle=0)["assessment_id"] == "asmt_new"

    def test_a_run_that_falls_back_to_paused_is_reported_as_not_started(self, monkeypatch):
        monkeypatch.setattr(api.time, "sleep", lambda s: None)
        c = api.AscendAPI(token="s6r_pat_x")
        states = iter(["running", "running", "paused", "paused"])
        ticks = iter([0, 1, 2, 3, 99, 99, 99])
        monkeypatch.setattr(api.time, "time", lambda: next(ticks))
        c.get_assessment = lambda a, aid: {"status": next(states)}
        out = c.confirm_started("aapp_1", "asmt_1", settle=10, every=1)
        assert out == {"status": "paused", "started": False, "auto_paused": True}

    def test_a_run_that_holds_is_started(self):
        c = api.AscendAPI(token="s6r_pat_x")
        c.get_assessment = lambda a, aid: {"status": "running"}
        assert c.confirm_started("aapp_1", "asmt_1", settle=0)["started"] is True

    def test_the_reported_status_is_the_platforms_not_an_assumption(self):
        c = _client()
        c.create_assessment = lambda a, n: {"id": "asmt_1"}
        c.pause = c.resume = lambda a, aid: None
        c.get_assessment = lambda a, aid: {"status": "paused"}
        out = c.run("aapp_1", "r", wait=False, settle=0)
        assert out["status"] == "paused" and out["started"] is False

    def test_waiting_on_a_paused_run_gives_up_instead_of_hanging(self, monkeypatch):
        monkeypatch.setattr(api.time, "sleep", lambda s: None)
        c = api.AscendAPI(token="s6r_pat_x")
        polls = []

        def paused(a, aid):
            polls.append(1)
            # Fail, do not spin: without the give-up rule this loop runs for the whole timeout, and
            # a regression here should turn CI red rather than hang it.
            assert len(polls) < 20, "still polling a paused run"
            return {"status": "paused"}
        c.get_assessment = paused
        out = c.poll_assessment("aapp_1", "asmt_1", interval=1, timeout=7200)
        assert out["stalled"] is True
        assert len(polls) == 3


# ------------------------------------------------------------------ the wire shape
def test_every_create_and_patch_is_sent_in_the_shape_the_platform_accepts():
    out = api._clean_templates({"request_template": {"m": "{{ PROMPT }}"},
                                "response_template": {"a": [{"b": "{{RESPONSE}}"}]},
                                "headers": {"x-k": "v"}})
    assert out["request_template"] == '{"m": "{{PROMPT}}"}'
    assert json.loads(out["response_template"]) == {"a": [{"b": "{{RESPONSE}}"}]}
    assert out["headers"] == [{"name": "x-k", "value": "v"}]


# ------------------------------------------------------------------ credentials off argv
class TestAuthFile:
    def test_credentials_are_taken_from_a_private_file(self, tmp_path, monkeypatch):
        f = tmp_path / "auth.json"
        f.write_text(json.dumps({"headers": {"x-demo-key": "pass"}, "body_fields": {"apiKey": "k"}}))
        f.chmod(0o600)
        monkeypatch.setenv("ASCEND_TARGET_AUTH_FILE", str(f))
        headers, _ = ascend._target_auth(types.SimpleNamespace())
        assert headers["x-demo-key"] == "pass"
        assert ascend._body_fields(types.SimpleNamespace())["apiKey"] == "k"

    def test_a_file_other_users_can_read_is_refused(self, tmp_path, monkeypatch):
        f = tmp_path / "auth.json"
        f.write_text("{}")
        f.chmod(0o644)
        monkeypatch.setenv("ASCEND_TARGET_AUTH_FILE", str(f))
        with pytest.raises(SystemExit):
            ascend._auth_file()

    def test_an_explicit_flag_wins_over_the_file(self, tmp_path, monkeypatch):
        f = tmp_path / "auth.json"
        f.write_text(json.dumps({"headers": {"x-demo-key": "from-file"}}))
        f.chmod(0o600)
        monkeypatch.setenv("ASCEND_TARGET_AUTH_FILE", str(f))
        headers, _ = ascend._target_auth(types.SimpleNamespace(header=["x-demo-key: from-flag"]))
        assert headers["x-demo-key"] == "from-flag"


# ------------------------------------------------------------------ a target that publishes its contract
class TestPublishedContract:
    WS = {"slug": "retail-support", "share_id": "nwRetail4Kp7Zx2Q", "name": "Retail: Customer Support",
          "description": "Retail support agent", "system_prompt": "You are the support assistant.",
          "tool_specs": [{"name": "lookup_customer"}, {"name": "issue_refund"}]}

    @pytest.fixture(autouse=True)
    def _fake_host(self, monkeypatch):
        def fake_get(url, headers=None, verify=True):
            if url.endswith("/api/config"):
                return 200, {"app_name": "Doppelganger", "gated": True}
            if url.endswith("/api/workspaces"):
                return 200, {"workspaces": [self.WS]}
            if url.endswith("/api/workspaces/retail-support"):
                return 200, self.WS
            return 404, None
        monkeypatch.setattr(profiles, "_get", fake_get)

    def test_the_host_is_recognised_without_credentials(self):
        assert profiles.detect("https://dg.example.com/anything") is profiles.Doppelganger

    def test_missing_credentials_are_named_exactly(self):
        with pytest.raises(ValueError) as e:
            profiles.Doppelganger.build("https://dg.example.com", workspace="retail-support",
                                        headers={}, body_fields={})
        assert "x-demo-key" in str(e.value) and "apiKey" in str(e.value)

    def test_a_host_with_several_agents_asks_which(self):
        with pytest.raises(ValueError) as e:
            profiles.Doppelganger.build("https://dg.example.com", workspace="",
                                        headers={"x-demo-key": "p"}, body_fields={"apiKey": "k"})
        assert "retail-support" in str(e.value)

    def test_the_contract_mirrors_what_the_host_publishes(self):
        cfg, facts = profiles.Doppelganger.build(
            "https://dg.example.com", workspace="retail-support",
            headers={"x-demo-key": "p"}, body_fields={"apiKey": "sk_x"})
        assert cfg["endpoint"] == "https://dg.example.com/api/chat"
        assert cfg["body"]["workspace"] == "nwRetail4Kp7Zx2Q"      # the share token, not the slug
        assert cfg["body"]["apiKey"] == "sk_x" and cfg["body"]["message"] == "{{PROMPT}}"
        assert cfg["headers"]["x-demo-key"] == "p"
        assert facts["agentic"] is True and facts["tools"] == ["lookup_customer", "issue_refund"]
        assert facts["system_prompt"] == "You are the support assistant."

    def test_a_bearer_is_accepted_as_the_key_and_not_sent_twice(self):
        cfg, _ = profiles.Doppelganger.build(
            "https://dg.example.com", workspace="retail-support",
            headers={"x-demo-key": "p", "Authorization": "Bearer sk_b"}, body_fields={})
        assert cfg["body"]["apiKey"] == "sk_b"
        assert "Authorization" not in cfg["headers"]


# ------------------------------------------------------------------ surviving a platform fault
class TestSupervisedRun:
    """Measured on prod 2026-09-20: a run against a target answering 55 of 55 calls in ~1.5s was
    paused by the platform after 92s, 91s, 81s and 71s, advancing a few probes each time. The
    operator cannot configure that away, so `assess run` can put the run back — bounded, and
    never silently.

    `resumes` counts only SUPERVISION resumes. `run()` also resumes once at the start to get the
    assessment going, which is not the same thing and must not be reported as a platform pause.
    """

    def _client(self, script):
        c = api.AscendAPI(token="s6r_pat_x")
        seq = iter(script)
        c.get_assessment = lambda a, aid: next(seq)
        c.create_assessment = lambda a, n: {"id": "asmt_1"}
        c.live_assessment = lambda a: None
        c.pause = lambda a, aid: None
        c.resumed = []
        c.resume = lambda a, aid: c.resumed.append(aid)
        return c

    def test_a_platform_pause_is_resumed_and_the_run_finishes(self, monkeypatch):
        monkeypatch.setattr(api.time, "sleep", lambda s: None)
        script = ([{"status": "running"}] * 3 + [{"status": "paused"}] * 3
                  + [{"status": "running"}] * 2 + [{"status": "complete", "total": 9}] * 3)
        c = self._client(script)
        out = c.run("aapp_1", "r", wait=True, settle=0, interval=1, resume_on_pause=3)
        assert out["status"] == "complete"
        assert out["resumes"] == 1
        assert len(c.resumed) == 2, "one to start it, one to revive it"

    def test_a_clean_run_still_carries_the_count(self, monkeypatch):
        monkeypatch.setattr(api.time, "sleep", lambda s: None)
        c = self._client([{"status": "running"}] * 3 + [{"status": "complete", "total": 4}] * 3)
        out = c.run("aapp_1", "r", wait=True, settle=0, interval=1, resume_on_pause=3)
        assert out["resumes"] == 0

    def test_supervision_is_bounded(self, monkeypatch):
        monkeypatch.setattr(api.time, "sleep", lambda s: None)
        c = self._client([{"status": "running"}] * 2 + [{"status": "paused"}] * 400)
        out = c.run("aapp_1", "r", wait=True, settle=0, interval=1, resume_on_pause=2)
        assert out["stalled"] is True
        assert out["resumes"] == 2, "it must give up, not resume forever"

    def test_off_by_default(self, monkeypatch):
        monkeypatch.setattr(api.time, "sleep", lambda s: None)
        c = self._client([{"status": "running"}] * 2 + [{"status": "paused"}] * 40)
        out = c.run("aapp_1", "r", wait=True, settle=0, interval=1)
        assert out["stalled"] is True
        assert len(c.resumed) == 1, "only the resume that started it"

    def test_a_finished_run_is_never_resumed(self, monkeypatch):
        monkeypatch.setattr(api.time, "sleep", lambda s: None)
        # The platform accepts a resume on a completed run and then reports it running forever.
        done = {"status": "paused", "progress": 1, "completed_at": "2026-09-20T06:00:00Z"}
        c = self._client([{"status": "running"}] * 2 + [done] * 10)
        out = c.run("aapp_1", "r", wait=True, settle=0, interval=1, resume_on_pause=3)
        assert out["resumes"] == 0 and len(c.resumed) == 1

    def test_the_command_reports_the_count_and_diagnoses_a_stall(self):
        body = SRC[SRC.index("def cmd_assess_run("):SRC.index("def _diagnose_not_started(")]
        assert 'res.get("resumes")' in body and "paused this run" in body
        assert body.count("_diagnose_not_started(c, appid, res)") == 2, (
            "a run that stalled mid-flight deserves the same tested diagnosis as one that never started")
