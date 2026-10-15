"""
runtime/discovery/codegen_js.py — a derived contract as a hosted JavaScript adaptor.

The fixtures are the configs `target add` really writes for each transport, captured from live
derivations against Straiker's own target lab (hosts replaced), not imagined. Every generated
source is held to the same rule the publish gate enforces: synchronous host calls only, nothing
the isolate does not have, exactly one `sendTurn`. The reply is returned under the key the app's
response_template names, because a wrong shape does not fail — it scores.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
for _p in (REPO / "runtime", REPO):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))
import adaptor as AD  # noqa: E402
from runtime.discovery import codegen_js as G  # noqa: E402

# --- the configs the CLI derives, one per shape ---------------------------------------------
REST = {
    "adapter": "direct_api",
    "endpoint": "https://bot.example.com/rest/api/chat",
    "method": "POST",
    "body": {"message": "{{PROMPT}}"},
    "response_path": "reply",
    "headers": {},
    "_probe": {"verified_answer": "Hello! I can help with order status."},
}
REST_NESTED = {
    "adapter": "direct_api",
    "endpoint": "https://llm.example.com/v1/chat/completions",
    "method": "POST",
    "body": {"model": "x", "messages": [{"role": "user", "content": "{{PROMPT}}"}]},
    "response_path": "choices.0.message.content",
    "headers": {"Authorization": "Bearer sk_test_123456"},
    "timeout_ms": 45000,
}
SSE = {
    "adapter": "sse_stream",
    "base_url": "https://bot.example.com",
    "chat_path": "/sse/api/chat",
    "method": "POST",
    "request_template": {"message": "{{PROMPT}}"},
    "stream": {"format": "sse", "text_path": "content", "token_types": ["token"],
               "done_when": {"path": "type", "equals": "done"}, "idle_ms": 20000},
    "headers": {},
}
SSE_CREATE = {
    "adapter": "sse_stream",
    "base_url": "https://bot.example.com",
    "chat_path": "/api/threads/{{CONV}}/stream",
    "request_template": {"message": "{{PROMPT}}"},
    "stream": {"format": "sse", "text_path": "delta"},
    "create": {"url": "https://ids.example.com/api/threads", "method": "POST", "body": {},
               "id_path": "id", "id_mode": "server", "per_prompt": True},
}
WS = {
    "adapter": "websocket_direct",
    "ws_url": "wss://sock.example.com/demo?code=abc123",
    "send_template": {"message": "{{PROMPT}}"},
    "idle_ms": 1500,
    "aggregate": "concat",
    "response_path": "text",
    "done_when": {"path": "type", "equals": "done"},
}
SESSION = {
    "adapter": "session_api",
    "session_endpoint": "https://bot.example.com/session/api/conversations",
    "session_body": {},
    "session_extract": "conversation_id",
    "session_variable": "SESSION_ID",
    "message_endpoint": "https://bot.example.com/session/api/messages",
    "message_body": {"message": "{{PROMPT}}", "conversation_id": "{{SESSION_ID}}"},
    "response_path": "reply",
    "headers": {"Content-Type": "application/json"},
}
SESSION_IN_PATH = {
    **SESSION,
    "session_endpoint": "https://auth.example.com/v1/sessions",
    "message_endpoint": "https://bot.example.com/v1/sessions/{{SESSION_ID}}/messages",
    "message_body": {"text": "{{PROMPT}}"},
}
POLL = {
    "adapter": "session_poll",
    "create": {"url": "https://bot.example.com/api/conversations", "method": "POST", "body": {},
               "extract": "conversation_id"},
    "send": {"url": "https://bot.example.com/api/conversations/{{CONV}}/messages", "method": "POST",
             "body": {"message": "{{PROMPT}}"}},
    "poll": {"url": "https://transcripts.example.com/api/conversations/{{CONV}}/messages",
             "method": "GET", "list_path": "messages", "role_field": "role",
             "bot_roles": ["assistant", "bot"], "text_path": "text", "interval_ms": 1000,
             "timeout_ms": 30000},
}
ODD = {"adapter": "sentinel_stream", "url": "https://bot.example.com/chat", "method": "POST",
       "begin_marker": "B{", "end_marker": "}E", "message": {"body": {"message": "{{PROMPT}}"}},
       "headers": {"x-api-key": "secret-value-9999"}}

SHAPED = {"direct_api": REST, "sse_stream": SSE, "websocket_direct": WS,
          "session_api": SESSION, "session_poll": POLL}
EVERY = [REST, REST_NESTED, SSE, SSE_CREATE, WS, SESSION, SESSION_IN_PATH, POLL, ODD]


def _code(src: str) -> str:
    return AD.strip_comments(src)


# --- the address the application is registered with -----------------------------------------
class TestAppUrl:
    @pytest.mark.parametrize("cfg,url", [
        (REST, "https://bot.example.com/rest/api/chat"),
        (SSE, "https://bot.example.com/sse/api/chat"),
        (WS, "wss://sock.example.com/demo?code=abc123"),
        (SESSION, "https://bot.example.com/session/api/messages"),
        (POLL, "https://bot.example.com/api/conversations"),
        (ODD, "https://bot.example.com/chat"),
    ])
    def test_each_shape_registers_its_real_address(self, cfg, url):
        assert G.app_url(cfg) == url

    def test_a_placeholder_never_reaches_the_platform(self):
        assert G.app_url(SSE_CREATE) == "https://bot.example.com/api/threads"
        assert G.app_url(SESSION_IN_PATH) == "https://bot.example.com/v1/sessions"
        assert G.path_template(SSE_CREATE) == "/api/threads/{{CONV}}/stream"
        assert G.path_template(SESSION_IN_PATH) == "/v1/sessions/{{SESSION_ID}}/messages"
        assert G.path_template(SSE) is None

    def test_a_query_placeholder_is_cut_too(self):
        cfg = {**SSE, "chat_path": "/api/chat?conv={{CONV}}"}
        assert G.app_url(cfg) == "https://bot.example.com/api/chat"
        assert G.path_template(cfg) == "/api/chat?conv={{CONV}}"


# --- the templates on the application -------------------------------------------------------
class TestTemplates:
    def test_a_direct_target_keeps_its_whole_body(self):
        assert G.request_template(REST_NESTED) == REST_NESTED["body"]

    def test_a_literal_body_gets_the_prompt_on_its_field(self):
        cfg = {**REST, "body": {"q": "hello", "lang": "en"}, "prompt_field": "q"}
        assert G.request_template(cfg) == {"lang": "en", "q": "{{PROMPT}}"}

    @pytest.mark.parametrize("cfg,key", [(SSE, "message"), (WS, "message"), (SESSION, "message"),
                                         (SESSION_IN_PATH, "text"), (POLL, "message")])
    def test_a_reassembled_shape_carries_only_the_prompt_key(self, cfg, key):
        assert G.request_template(cfg) == {key: "{{PROMPT}}"}

    def test_the_prompt_path_follows_a_nested_body(self):
        assert G.prompt_path(REST_NESTED["body"]) == ["messages", "0", "content"]
        assert G.prompt_path({"q": "x"}) == []

    def test_a_direct_answer_path_is_mirrored(self):
        assert G.response_template(REST) == {"reply": "{{RESPONSE}}"}
        assert G.response_template(REST_NESTED) == {
            "choices": [{"message": {"content": "{{RESPONSE}}"}}]}

    @pytest.mark.parametrize("cfg", [SSE, WS, SESSION, POLL, ODD])
    def test_every_reassembled_shape_answers_under_response(self, cfg):
        assert G.response_template(cfg) == {"response": "{{RESPONSE}}"}

    def test_the_reply_body_mirrors_the_template_including_arrays(self):
        assert G.reply_body_js({"reply": "{{RESPONSE}}"}) == '{ "reply": text }'
        assert G.reply_body_js({"choices": [{"message": {"content": "{{RESPONSE}}"}}]}) == \
            '{ "choices": [{ "message": { "content": text } }] }'
        assert G.reply_body_js({"ok": True, "data": {"text": "{{RESPONSE}}"}}) == \
            '{ "ok": true, "data": { "text": text } }'

    def test_the_header_statement_is_the_one_adaptor_shape_prints(self):
        """One source of truth for "what must I return": runtime/adaptor.py."""
        assert G.plan(REST)["reply_statement"] == AD.reply_shape({"reply": "{{RESPONSE}}"})["statement"]
        assert AD.reply_shape({"choices": [{"message": {"content": "{{RESPONSE}}"}}]})["statement"] == \
            "return { status_code: 200, body: { choices: [ { message: { content: text } } ] } };"


# --- egress beyond the application's host ---------------------------------------------------
class TestDomains:
    @pytest.mark.parametrize("cfg", [REST, SSE, WS, SESSION])
    def test_one_host_means_no_extra_domains(self, cfg):
        assert G.extra_domains(cfg) == []

    def test_every_second_host_is_listed(self):
        assert G.extra_domains(SSE_CREATE) == ["ids.example.com"]
        assert G.extra_domains(SESSION_IN_PATH) == ["auth.example.com"]
        assert G.extra_domains(POLL) == ["transcripts.example.com"]

    def test_the_plan_carries_them_for_the_template(self):
        assert G.plan(POLL)["domains"] == ["transcripts.example.com"]
        assert G.plan(REST_NESTED)["params"] == {"_adaptor_timeout_ms": 45000}
        assert G.plan(REST)["params"] == {}


# --- what every generated source obeys ------------------------------------------------------
class TestEveryGeneratedSource:
    @pytest.mark.parametrize("cfg", EVERY, ids=[c["adapter"] + ("-2" if c is REST_NESTED or c is SESSION_IN_PATH or c is SSE_CREATE else "") for c in EVERY])
    def test_it_passes_the_local_gate(self, cfg):
        src = G.generate_adaptor(cfg)
        assert AD.lint_source(src) == [], AD.lint_source(src)

    @pytest.mark.parametrize("cfg", EVERY)
    def test_one_send_turn_and_the_prompt_from_the_payload(self, cfg):
        code = _code(G.generate_adaptor(cfg))
        assert len(re.findall(r"\bfunction sendTurn\(turn, host\)", code)) == 1
        if G.shape_of(cfg) != G.SCAFFOLD:
            assert "promptOf(turn)" in code and "turn.payload" in code
            assert "turn.headers" in code
            assert "host.config.endpoint()" in code

    @pytest.mark.parametrize("cfg", EVERY)
    def test_no_credential_and_no_address_is_a_literal(self, cfg):
        """The target's address comes from host.config.endpoint(); a credential only ever from
        turn.headers or host.config. A header VALUE from the config must never be in the file."""
        src = G.generate_adaptor(cfg)
        for value in (cfg.get("headers") or {}).values():
            if value != "application/json":
                assert value not in src
        assert "sk_test_123456" not in src and "secret-value-9999" not in src
        code = _code(src)
        if G.shape_of(cfg) != G.SCAFFOLD:
            assert G.app_url(cfg) not in code, "the app's own address is read from the host, not pasted"

    @pytest.mark.parametrize("cfg", EVERY)
    def test_the_lint_strips_only_comments(self, cfg):
        """The JSDoc typedef says import("./host"); the code must not."""
        src = G.generate_adaptor(cfg)
        assert 'import("./host")' in src
        assert "import" not in _code(src)

    def test_the_banned_words_are_the_gates(self):
        for word in ("async", "await", "Promise", "fetch", "XMLHttpRequest", "require", "import",
                     "eval", "setTimeout", "setInterval", "console"):
            assert word in AD.GATE_BANNED

    def test_the_lint_itself_can_fail(self):
        bad = "function sendTurn(turn, host) { const r = fetch(x); return r; }"
        assert any("fetch" in p for p in AD.lint_source(bad))
        # Measured on the live gate: `Object.prototype.toString.call(x)` was refused as a
        # denied member, after every local check had passed. The lint knows the member now.
        proto = "function sendTurn(t, h) { return Object.prototype.toString.call(t); }"
        assert any(".prototype" in p for p in AD.lint_source(proto))
        assert any("__proto__" in p for p in AD.lint_source("function sendTurn(t, h) { return t.__proto__; }"))
        assert any("sendTurn" in p for p in AD.lint_source("function other() {}"))
        assert any("sendTurn" in p for p in AD.lint_source(
            "function sendTurn(a, b) {}\nfunction sendTurn(c, d) {}"))
        assert any("export" in p for p in AD.lint_source("export function sendTurn(t, h) {}"))
        assert AD.lint_source("// fetch in a comment\nfunction sendTurn(t, h) { return 1; }") == []


# --- per shape: the contract is in the file -------------------------------------------------
class TestDirectApi:
    def test_the_reply_is_returned_under_the_apps_key(self):
        code = _code(G.generate_adaptor(REST))
        assert 'body: { "reply": text }' in code
        assert 'var RESPONSE_PATH = "reply";' in code
        assert 'var METHOD = "POST";' in code

    def test_a_nested_answer_path_and_timeout_parameter(self):
        src = G.generate_adaptor(REST_NESTED)
        assert 'var RESPONSE_PATH = "choices.0.message.content";' in src
        assert 'body: { "choices": [{ "message": { "content": text } }] }' in src
        assert 'var PROMPT_PATH = ["messages", "0", "content"];' in src
        assert "Number(params.timeout_ms)" in src

    def test_the_credential_statuses_are_passed_through_and_the_rest_is_502(self):
        code = _code(G.generate_adaptor(REST))
        assert "status === 400 || status === 401 || status === 403 ? status : 502" in code

    def test_a_carried_conversation_id_lives_in_host_state(self):
        src = G.generate_adaptor({**REST, "carry": {"reply_path": "conversation_id",
                                                     "request_field": "conversation_id"}})
        assert 'host.state.get("carry")' in src and 'host.state.set("carry"' in src


class TestSseStream:
    def test_the_stream_framing_is_carried_verbatim(self):
        src = G.generate_adaptor(SSE)
        stream = json.loads(re.search(r"var STREAM = (\{.*?\});", src).group(1))
        assert stream["text_path"] == "content" and stream["token_types"] == ["token"]
        assert stream["done_when"] == {"path": "type", "equals": "done"}
        assert stream["format"] == "sse"
        assert "partialOnTimeout: true" in src
        assert '"Accept": "text/event-stream"' in src
        assert "var CHAT_PATH = null;" in src and "var CREATE = null;" in src

    def test_a_create_step_mints_per_prompt_and_renders_conv_on_the_origin(self):
        src = G.generate_adaptor(SSE_CREATE)
        assert 'var CHAT_PATH = "/api/threads/{{CONV}}/stream";' in src
        create = json.loads(re.search(r"var CREATE = (\{.*?\});", src).group(1))
        assert create["url"] == "https://ids.example.com/api/threads" and create["per_prompt"] is True
        assert "targetUrl(host, CHAT_PATH, vars)" in src
        assert "host.state.getOrMint(CONV_SLOT" in src
        assert "ids.example.com" in src.split("\n", 12)[-1] or "domains  ids.example.com" in src

    def test_ndjson_is_a_format_not_a_shape(self):
        src = G.generate_adaptor({**SSE, "stream": {"format": "ndjson", "text_path": "delta"}})
        assert '"format": "ndjson"' in src and '"Accept": "application/x-ndjson"' in src


class TestWebSocket:
    def test_the_socket_is_the_apps_url_or_the_parameter(self):
        src = G.generate_adaptor(WS)
        assert 'url.indexOf("ws") !== 0 && params.ws_url' in src
        assert 'var SEND = {"message": "{{PROMPT}}"};' in src
        assert 'var DONE_WHEN = {"path": "type", "equals": "done"};' in src
        assert "var IDLE_MS = 1500;" in src
        assert "function checkReachability(turn, host)" in src
        assert "sock.close()" in src and "frames < MAX_FRAMES" in src

    def test_the_handshake_is_not_replayed_on_a_reused_socket(self):
        assert "if (!sock.reused)" in G.generate_adaptor(WS)


class TestSessionApi:
    def test_the_id_is_minted_once_per_conversation_and_remade_on_401(self):
        src = G.generate_adaptor(SESSION)
        assert "host.state.getOrMint(SESSION_SLOT" in src
        assert "if (res.status === 401)" in src and "host.state.set(SESSION_SLOT, null)" in src
        assert 'var SESSION_EXTRACT = "conversation_id";' in src
        assert 'var SESSION_ENDPOINT = "https://bot.example.com/session/api/conversations";' in src
        assert "function checkReachability(turn, host)" in src
        assert 'var MESSAGE_PATH = null;' in src

    def test_an_id_in_the_path_is_rendered_on_the_origin(self):
        src = G.generate_adaptor(SESSION_IN_PATH)
        assert 'var MESSAGE_PATH = "/v1/sessions/{{SESSION_ID}}/messages";' in src
        assert 'var MESSAGE_BODY = {"text": "{{PROMPT}}"};' in src

    def test_a_warmup_turn_is_sent_once_after_the_mint(self):
        src = G.generate_adaptor({**SESSION, "warmup_message": "hello"})
        assert 'var WARMUP = "hello";' in src and "if (WARMUP)" in src
        assert "var WARMUP = null;" in G.generate_adaptor(SESSION)


class TestSessionPoll:
    def test_create_send_poll_with_a_watermark_and_a_bound(self):
        src = G.generate_adaptor(POLL)
        poll = json.loads(re.search(r"var POLL = (\{.*?\});", src).group(1))
        assert poll["list_path"] == "messages" and poll["bot_roles"] == ["assistant", "bot"]
        assert poll["url"].endswith("/{{CONV}}/messages")
        assert 'var SEND_PATH = "/api/conversations/{{CONV}}/messages";' in src
        assert "var baseline = botTurns(" in src
        assert "polls < MAX_POLLS" in src and "host.sleep(interval)" in src
        assert "host.now()" in src


class TestScaffold:
    def test_an_unknown_shape_gets_the_shipped_scaffold_and_says_what_was_captured(self):
        src = G.generate_adaptor(ODD)
        assert src.startswith("// @ts-check\n// UNFINISHED")
        assert "'sentinel_stream'" in src and "x-api-key" in src
        assert "secret-value-9999" not in src
        assert AD.template_js("scaffold").split("\n", 1)[1] in src
        assert G.plan(ODD)["finished"] is False and G.plan(REST)["finished"] is True

    @pytest.mark.parametrize("kind", ["browser", "custom", "copilot_studio", "scrt2_direct", ""])
    def test_the_shape_of_everything_else(self, kind):
        assert G.shape_of({"adapter": kind}) == (G.SCAFFOLD if kind else "direct_api")
        assert G.shape_of({"adapter": "api"}) == "direct_api"


# --- a target that logs in: the login-capable scaffold, never a thin passthrough ---------------
OAUTH = {"adapter": "direct_api", "endpoint": "https://bot.example.com/api/chat", "method": "POST",
         "body": {"message": "{{PROMPT}}"}, "response_path": "reply",
         "auth": {"type": "oauth2", "grant": "client_credentials",
                  "token_url": "https://idp.example.com/oauth/token",
                  "client_secret_ref": "env:CLIENT_SECRET"}}
CSRF = {"adapter": "direct_api", "endpoint": "https://bot.example.com/api/chat",
        "body": {"message": "{{PROMPT}}"}, "response_path": "reply",
        "auth": {"type": "csrf", "bootstrap_url": "https://bot.example.com/login", "into_header": "X-CSRF"}}
MULTIHOP = {"adapter": "direct_api", "endpoint": "https://bot.example.com/api/chat",
            "body": {"message": "{{PROMPT}}"}, "response_path": "reply",
            "auth": {"type": "derived_multihop", "steps": [{"url": "https://bot.example.com/a"},
                                                           {"url": "https://bot.example.com/b"}]}}
LOGINS = [OAUTH, CSRF, MULTIHOP]


class TestLoginScaffold:
    """A handshake the engine performs itself (oauth2 / csrf / derived_multihop) gets a login
    scaffold: the mint/echo structure plus a pure-JS PKCE helper, not the per-adapter passthrough
    that would 401 on every probe."""

    @pytest.mark.parametrize("cfg", LOGINS)
    def test_a_dynamic_auth_contract_is_the_login_shape(self, cfg):
        assert G.is_login_shape(cfg) is True
        plan = G.plan(cfg)
        assert plan["shape"] == G.LOGIN and plan["shape"] == "login"
        assert plan["finished"] is False          # the operator still writes the login body

    @pytest.mark.parametrize("cfg", LOGINS)
    def test_the_login_scaffold_carries_the_pkce_helper_and_the_mint(self, cfg):
        src = G.generate_adaptor(cfg)
        assert "function pkceChallenge(" in src and "function mintCredential(" in src
        assert "host.state.getOrMint(" in src and "host.http.request(" in src

    @pytest.mark.parametrize("cfg", LOGINS)
    def test_the_login_scaffold_passes_the_local_gate(self, cfg):
        """The gate-accepts proof on the operator's side: lint_source mirrors the publish gate
        (banned identifiers, one sendTurn, no export). The engine gate is proven live."""
        assert AD.lint_source(G.generate_adaptor(cfg)) == []

    def test_the_captured_handshake_is_described_without_a_secret(self):
        src = G.generate_adaptor(OAUTH)
        assert src.startswith("// @ts-check\n// UNFINISHED")
        assert "'oauth2'" in src and "client_credentials" in src
        assert "idp.example.com" in src          # the host, as a hint
        assert "env:CLIENT_SECRET" not in src and "CLIENT_SECRET" not in src   # never the ref

    def test_a_static_credential_is_not_a_login(self):
        static = {"adapter": "direct_api", "endpoint": "https://bot.example.com/api/chat",
                  "body": {"message": "{{PROMPT}}"}, "response_path": "reply",
                  "auth": {"type": "static", "mode": "bearer", "value_ref": "env:T"}}
        assert G.is_login_shape(static) is False
        assert G.plan(static)["shape"] == "direct_api" and G.plan(static)["finished"] is True
        assert "mintCredential" not in G.generate_adaptor(static)

    def test_two_static_credentials_as_a_list_are_still_a_passthrough(self):
        twolist = {"adapter": "direct_api", "endpoint": "https://bot.example.com/api/chat",
                   "body": {"message": "{{PROMPT}}"}, "response_path": "reply",
                   "auth": [{"type": "static", "mode": "custom", "name": "x", "value_ref": "env:A"},
                            {"type": "static", "mode": "bearer", "value_ref": "env:B"}]}
        assert G.is_login_shape(twolist) is False
        assert G.plan(twolist)["shape"] == "direct_api"
