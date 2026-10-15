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


# --- a login handshake: the scaffold, named ---------------------------------------------------
class TestHandshake:
    @pytest.mark.parametrize("kind", G.DYNAMIC_AUTH_KINDS)
    def test_a_handshake_gets_the_scaffold_whatever_the_transport(self, kind):
        """No generator mints a token or completes a CSRF dance. A direct_api adaptor sending
        static headers 401'd on every probe; the scaffold says what is missing instead."""
        for base in (REST, SSE, SESSION):
            cfg = {**base, "auth": {"type": kind}}
            assert G.transport_shape(cfg) == base["adapter"]
            assert G.shape_of(cfg) == G.SCAFFOLD
            pl = G.plan(cfg)
            assert pl["finished"] is False and kind in pl["unfinished_why"]
            assert pl["url"] == G.app_url(base), "the address still follows the transport"
            assert f"UNFINISHED: this target authenticates with a '{kind}' handshake" in pl["source"]
            assert f"//   auth     {kind}:" in pl["source"]
            assert AD.lint_source(pl["source"]) == []

    def test_a_handshake_in_a_list_of_blocks_counts(self):
        cfg = {**REST, "auth": [{"type": "static", "mode": "bearer", "value_ref": "env:T"}, {"type": "csrf"}]}
        assert G.handshake_kind(cfg) == "csrf" and G.shape_of(cfg) == G.SCAFFOLD

    def test_static_auth_keeps_its_generator(self):
        cfg = {**REST, "auth": {"type": "static", "mode": "bearer", "value_ref": "env:T"}}
        assert G.shape_of(cfg) == "direct_api" and G.plan(cfg)["finished"] is True
        assert G.plan(cfg)["unfinished_why"] is None

    def test_a_direct_request_keeps_its_whole_body_as_the_template(self):
        """The scaffold forwards turn.payload whole, so a direct target's template stays the
        whole body — what the transport needs, not what the generator chose."""
        cfg = {**REST_NESTED, "auth": {"type": "oauth2"}}
        assert G.plan(cfg)["request_template"] == REST_NESTED["body"]

    def test_the_unfinished_reason_for_a_contract_no_generator_covers(self):
        assert G.plan(ODD)["unfinished_why"] == "no generator covers the 'sentinel_stream' adapter"
        assert "UNFINISHED: the derived adapter is 'sentinel_stream'" in G.plan(ODD)["source"]


# --- a second host behind the customer's tunnel ---------------------------------------------
TUNNELLED_SESSION = {
    **SESSION,
    "session_endpoint": "https://auth.corp.internal:8443/v1/sessions",
    "message_endpoint": "https://chat.corp.internal.tun.straiker.ai/v1/messages",
}
TUNNELLED_POLL = {
    "adapter": "session_poll",
    "create": {"url": "http://ids.corp.internal:80/api/conversations", "method": "POST", "body": {},
               "extract": "conversation_id"},
    "send": {"url": "https://chat.corp.internal.tun.straiker.ai/api/conversations/{{CONV}}/messages",
             "method": "POST", "body": {"message": "{{PROMPT}}"}},
    "poll": {"url": "wss://transcripts.corp.internal/api/stream/{{CONV}}", "method": "GET",
             "list_path": "messages", "role_field": "role", "bot_roles": ["bot"], "text_path": "text"},
    "bootstrap": [{"url": "https://chat.corp.internal.tun.straiker.ai/warm", "method": "GET"},
                  {"url": "https://already.tun.straiker.ai/x", "method": "GET"}],
}


class TestRoutedSecondHosts:
    @pytest.mark.parametrize("url,routed,allow", [
        ("https://auth.corp.internal:8443/v1/sessions", "https://auth.corp.internal.tun.straiker.ai/v1/sessions", "auth.corp.internal:8443"),
        ("https://auth.corp.internal/v1", "https://auth.corp.internal.tun.straiker.ai/v1", "auth.corp.internal:443"),
        ("http://ids.corp.internal/api?x=1", "http://ids.corp.internal.tun.straiker.ai/api?x=1", "ids.corp.internal:80"),
        ("http://ids.corp.internal:8080/api", "http://ids.corp.internal.tun.straiker.ai/api", "ids.corp.internal:8080"),
        ("https://tls.corp.internal:80/x", "https://tls.corp.internal.tun.straiker.ai/x", "tls.corp.internal:80"),
        ("wss://sock.corp.internal/ws", "wss://sock.corp.internal.tun.straiker.ai/ws", "sock.corp.internal:443"),
        ("ws://sock.corp.internal/ws", "ws://sock.corp.internal.tun.straiker.ai/ws", "sock.corp.internal:80"),
        ("ws://sock.corp.internal:9000/ws", "ws://sock.corp.internal.tun.straiker.ai/ws", "sock.corp.internal:9000"),
        ("HTTPS://Auth.Corp.Internal:8443/V1", "https://auth.corp.internal.tun.straiker.ai/V1", "auth.corp.internal:8443"),
        # not a scheme the tunnel carries: routed as https, as it always was
        ("ftp://files.corp.internal/x", "https://files.corp.internal.tun.straiker.ai/x", "files.corp.internal:443"),
    ])
    def test_the_tunnel_url_rule(self, url, routed, allow):
        """The host rides inside the name, the port lives in the agent's allow list, and the
        scheme is the URL's own on any port: a plain-HTTP second host on 8080 stays http://
        (runtime/tunnel.py's rule, restated for the generator)."""
        assert G.tunnel_url(url) == (routed, allow)

    @pytest.mark.parametrize("url", [
        "http://ids.corp.internal:8089/api", "http://ids.corp.internal/api?x=1",
        "https://auth.corp.internal:8443/v1", "https://auth.corp.internal/v1",
        "https://tls.corp.internal:80/x", "ws://sock.corp.internal:9000/ws",
        "wss://sock.corp.internal/ws", "wss://sock.corp.internal:9443/ws",
        "HTTP://Ids.Corp.Internal:8089/Api"])
    def test_the_generator_and_tunnel_url_give_the_same_answer(self, url):
        """Two copies of one rule: the generator routes a second host, `ascend tunnel url` routes
        the app. Both once said https for plain HTTP off port 80; this holds them together."""
        import tunnel as T
        r = T.url_rule(url)
        assert G.tunnel_url(url) == (r["url"], r["allow"])

    def test_a_public_app_is_untouched(self):
        for cfg in (SSE_CREATE, SESSION_IN_PATH, POLL):
            out, notes = G.route_second_hosts(cfg)
            assert out == cfg and notes == []

    def test_a_tunnel_app_routes_its_second_hosts_everywhere_they_are_read(self):
        out, notes = G.route_second_hosts(TUNNELLED_SESSION)
        assert out["session_endpoint"] == "https://auth.corp.internal.tun.straiker.ai/v1/sessions"
        assert TUNNELLED_SESSION["session_endpoint"].startswith("https://auth.corp.internal:8443"), "the input is not mutated"
        [note] = notes
        assert "auth.corp.internal.tun.straiker.ai" in note and "--allow auth.corp.internal:8443" in note
        assert G.extra_domains(TUNNELLED_SESSION) == ["auth.corp.internal.tun.straiker.ai"]
        pl = G.plan(TUNNELLED_SESSION)
        assert pl["domains"] == ["auth.corp.internal.tun.straiker.ai"] and pl["domain_notes"] == notes
        assert "auth.corp.internal.tun.straiker.ai" in pl["source"]
        assert "auth.corp.internal:8443" not in AD.strip_comments(pl["source"])
        assert pl["request_template"] == {"message": "{{PROMPT}}"}

    def test_every_slot_of_a_poll_shape_is_routed_and_names_already_routed_are_left(self):
        out, notes = G.route_second_hosts(TUNNELLED_POLL)
        assert out["create"]["url"] == "http://ids.corp.internal.tun.straiker.ai/api/conversations"
        assert out["poll"]["url"] == "wss://transcripts.corp.internal.tun.straiker.ai/api/stream/{{CONV}}"
        assert out["bootstrap"][0]["url"] == TUNNELLED_POLL["bootstrap"][0]["url"]     # the app's own host
        assert out["bootstrap"][1]["url"] == TUNNELLED_POLL["bootstrap"][1]["url"]     # already a tunnel name
        assert sorted(G.extra_domains(TUNNELLED_POLL)) == ["already.tun.straiker.ai",
                                                           "ids.corp.internal.tun.straiker.ai",
                                                           "transcripts.corp.internal.tun.straiker.ai"]
        assert [n.split(" is reached")[0] for n in notes] == ["ids.corp.internal", "transcripts.corp.internal"]
        assert "--allow ids.corp.internal:80" in notes[0] and "--allow transcripts.corp.internal:443" in notes[1]
        src = G.generate_adaptor(TUNNELLED_POLL)
        assert "transcripts.corp.internal.tun.straiker.ai" in src and "wss://transcripts.corp.internal/" not in src
        assert AD.lint_source(src) == []

    def test_a_private_link_app_leaves_the_host_and_says_it_must_be_routed(self):
        cfg = {**SESSION_IN_PATH, "message_endpoint": "https://k7f3q9x2m4ta.pl.straiker.ai/v1/sessions/{{SESSION_ID}}/messages"}
        out, notes = G.route_second_hosts(cfg)
        assert out == cfg
        [note] = notes
        assert note.startswith("auth.example.com is a second host behind a private link")
        assert G.extra_domains(cfg) == ["auth.example.com"]

    def test_routed_app(self):
        assert G.routed_app(TUNNELLED_SESSION) == ("tunnel", "chat.corp.internal.tun.straiker.ai")
        assert G.routed_app({**REST, "endpoint": "https://x.pl.straiker.ai/v1"}) == ("private-link", "x.pl.straiker.ai")
        assert G.routed_app(REST) == ("", "")


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
                     "eval", "setTimeout", "setInterval"):
            assert word in AD.GATE_BANNED

    def test_console_is_allowed_as_the_gate_allows_it(self):
        """The engine's gate lists `console` among its allowed globals (it routes to host.log);
        the lint once refused it, so a file the engine would pass was refused here first."""
        assert "console" not in AD.GATE_BANNED
        assert AD.lint_source("function sendTurn(t, h) { console.log('hi'); return 1; }") == []

    def test_the_lint_itself_can_fail(self):
        bad = "function sendTurn(turn, host) { const r = fetch(x); return r; }"
        assert any("fetch" in p for p in AD.lint_source(bad))
        # Measured on the live gate: `Object.prototype.toString.call(x)` was refused as a
        # denied member, after every local check had passed. The lint knows the member now.
        proto = "function sendTurn(t, h) { return Object.prototype.toString.call(t); }"
        assert any(".prototype" in p for p in AD.lint_source(proto))
        assert any("__proto__" in p for p in AD.lint_source("function sendTurn(t, h) { return t.__proto__; }"))
        assert any("sendTurn" in p for p in AD.lint_source("function other() {}"))
        assert any("export" in p for p in AD.lint_source("export function sendTurn(t, h) {}"))
        assert AD.lint_source("// fetch in a comment\nfunction sendTurn(t, h) { return 1; }") == []

    def test_send_turn_must_be_defined_and_a_redeclaration_is_a_parse_error(self):
        """The gate's contract rule is `must define sendTurn` (not "exactly one"). A second
        declaration is still refused — MEASURED on the live gate 2026-10-13 as `parse: Identifier
        'sendTurn' has already been declared`, module code being strict — so the lint says that,
        and not a contract rule it never had."""
        [problem] = AD.lint_source("function other() {}")
        assert "must be defined" in problem
        [problem] = AD.lint_source("function sendTurn(a, b) {}\nfunction sendTurn(c, d) {}")
        assert "declared 2 times" in problem and "parse error" in problem and "exactly one" not in problem

    @pytest.mark.parametrize("src,kind", [
        ("function sendTurn(t, h) { return atob(t); }", "atob"),
        ("function sendTurn(t, h) { return new URL(t); }", "URL"),
        ("function sendTurn(t, h) { return Symbol(); }", "Symbol"),
        ("function sendTurn(t, h) { return Buffer.from(t); }", "Buffer"),
        ("function sendTurn(t, h) { return new TextEncoder(); }", "TextEncoder"),
        ("function sendTurn(t, h) { with (t) { return x; } }", "with"),
        ("function sendTurn(turn, host) { return host['http']; }", "host[expr]"),
        ("function __tick() {}\nfunction sendTurn(t, h) {}", "__tick"),
        ("function sendTurn(t, h) { return this; }", "this"),
        ("function sendTurn(turn: Turn, host: Host): Reply { return 1; }", "TypeScript"),
        ("interface X {}\nfunction sendTurn(t, h) {}", "TypeScript"),
    ])
    def test_the_other_rules_the_gate_enforces(self, src, kind):
        """Unknown globals, `with`, `host[expr]`, `__`-prefixed names, `this` outside a class
        body and TypeScript — each refused by gate.core.js, each now named here first."""
        problems = AD.lint_source(src)
        assert any(kind in p for p in problems), problems

    def test_the_structural_rules_read_past_strings_as_the_parser_does(self):
        """`this adaptor` in a message is text, and `this` inside a class body is the instance:
        the shipped scaffold carries the former and a typed error the latter, and both pass."""
        assert AD.lint_source(AD.template_js("scaffold")) == []
        assert AD.lint_source('function sendTurn(t, h) { return { note: "finish this adaptor" }; }') == []
        assert AD.lint_source("class E extends Error { constructor(m) { super(m); this.m = m; } }\n"
                              "function sendTurn(t, h) { return new E('x'); }") == []
        assert AD.lint_source("function sendTurn(turn, host) { var o = { headers: turn.headers, "
                              "method: 'POST' }; return o; }") == []


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
