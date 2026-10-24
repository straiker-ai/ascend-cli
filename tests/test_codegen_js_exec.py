"""
The generated adaptors, EXECUTED — each one run through a fake of the engine's synchronous host
(tests/_adaptor_host.js) in a fresh V8 context, with every target reply canned.

Pattern-matching the source proves the right literals are in the file. This proves the file
runs: the prompt is read from the rendered payload, the request goes to the application's URL
with the application's headers, the credential statuses pass through, a session is minted once
and re-made on a 401, a stream is reassembled to one string, a socket is bounded, and the reply
comes back under the key the app's response_template names. Skipped where `node` is absent; the
engine's own gate and `ascend adaptor verify` remain the authority.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
for _p in (REPO / "runtime", REPO):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))
from runtime.discovery import codegen_js as G  # noqa: E402
from test_codegen_js import (POLL, REST, REST_NESTED, SESSION, SESSION_IN_PATH, SSE,  # noqa: E402
                             SSE_CREATE, WS)

NODE = shutil.which("node")
HOST_JS = REPO / "tests" / "_adaptor_host.js"
pytestmark = pytest.mark.skipif(not NODE, reason="node is not installed; the engine's gate is the authority")

HEADERS = {"Content-Type": "application/json", "x-lab-code": "code-from-the-app-record"}


def run(cfg, scenario, *, prompt="What is the status of order 42?", entry="sendTurn",
        payload=None, params=None, url=None):
    plan = G.plan(cfg)
    rendered = json.loads(json.dumps(plan["request_template"]).replace("{{PROMPT}}", prompt))
    turn = {"payload": rendered if payload is None else payload, "headers": HEADERS,
            "params": params or {}}
    doc = {"source": plan["source"], "config": {"url": url or plan["url"]}, "turn": turn,
           "entry": entry, "scenario": scenario}
    r = subprocess.run([NODE, str(HOST_JS)], input=json.dumps(doc), capture_output=True, text=True,
                       timeout=30)
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout)
    assert out["error"] is None, out["error"]
    return out


def http_calls(out):
    return [c for c in out["calls"] if c["fn"] == "http.request"]


SSE_BODY = ('data: {"type": "token", "content": "Hello! "}\n\n'
            'data: {"type": "status", "content": "thinking"}\n\n'
            'data: {"type": "token", "content": "I can help."}\n\n'
            'data: {"type": "done"}\n\n')


class TestDirectApi:
    def test_one_post_to_the_apps_url_with_its_headers_and_the_reply_under_its_key(self):
        out = run(REST, {"http": [{"url_contains": "/rest/api/chat", "method": "POST",
                                   "body_contains": "order 42", "body": {"reply": "Shipped."}}]})
        assert out["reply"]["status_code"] == 200
        assert out["reply"]["body"] == {"reply": "Shipped."}
        (call,) = http_calls(out)
        assert call["url"] == "https://bot.example.com/rest/api/chat"
        assert call["body"] == {"message": "What is the status of order 42?"}
        assert call["headers"]["x-lab-code"] == "code-from-the-app-record"
        assert call["headers"]["Content-Type"] == "application/json"
        assert not out["defines_preflight"], "no cheap check exists for a bare POST target"

    def test_a_nested_prompt_and_a_nested_answer(self):
        out = run(REST_NESTED, {"http": [{"body": {"choices": [{"message": {"content": "Paris"}}]}}]},
                  params={"timeout_ms": 5000})
        assert out["reply"]["body"] == {"choices": [{"message": {"content": "Paris"}}]}
        (call,) = http_calls(out)
        assert call["body"]["messages"][0]["content"] == "What is the status of order 42?"
        assert call["timeoutMs"] == 5000, "the _adaptor_timeout_ms parameter is honoured"

    @pytest.mark.parametrize("status,expected", [(401, 401), (403, 403), (400, 400), (500, 502), (429, 502)])
    def test_the_credential_statuses_pass_through_and_the_rest_is_a_502(self, status, expected):
        out = run(REST, {"http": [{"status": status, "body": "nope"}]})
        assert out["reply"]["status_code"] == expected

    def test_a_reply_without_the_answer_is_a_502_not_a_scored_blank(self):
        out = run(REST, {"http": [{"body": {"reply": ""}}]})
        assert out["reply"]["status_code"] == 502 and "no reply text" in out["reply"]["body"]["error"]

    def test_an_unreachable_target_is_a_502(self):
        out = run(REST, {"http": [{"throw": "ECONNREFUSED"}]})
        assert out["reply"]["status_code"] == 502

    def test_a_carried_id_is_echoed_on_the_next_turn(self):
        cfg = {**REST, "carry": {"reply_path": "conversation_id", "request_field": "conversation_id"}}
        out = run(cfg, {"http": [{"body": {"reply": "hi", "conversation_id": "c-9"}}]})
        assert out["state"] == {"carry": "c-9"}


class TestSseStream:
    def test_the_stream_is_reassembled_to_one_string(self):
        out = run(SSE, {"http": [{"url_contains": "/sse/api/chat", "method": "POST", "body": SSE_BODY}]})
        assert out["reply"] == {"status_code": 200, "body": {"response": "Hello! I can help."},
                                "headers": {"Content-Type": "application/json"},
                                "_diag": {"frames": 4, "done": True}}
        (call,) = http_calls(out)
        assert call["headers"]["Accept"] == "text/event-stream"
        assert call["body"] == {"message": "What is the status of order 42?"}

    def test_a_truncated_stream_still_answers_and_says_so(self):
        out = run(SSE, {"http": [{"body": SSE_BODY.split("data: {\"type\": \"done\"}")[0]}]})
        assert out["reply"]["body"] == {"response": "Hello! I can help."}
        assert out["reply"]["_diag"]["done"] is False

    def test_no_token_frames_is_a_502(self):
        out = run(SSE, {"http": [{"body": "data: {\"type\": \"status\", \"content\": \"x\"}\n\n"}]})
        assert out["reply"]["status_code"] == 502

    def test_a_create_step_mints_a_conversation_and_streams_on_its_path(self):
        out = run(SSE_CREATE, {"http": [
            {"url_contains": "ids.example.com/api/threads", "method": "POST", "body": {"id": "t-77"}},
            {"url_contains": "/api/threads/t-77/stream", "method": "POST",
             "body": 'data: {"delta": "Ab"}\n\ndata: {"delta": "c"}\n\n'},
        ]})
        assert out["reply"]["body"] == {"response": "Abc"}
        create, stream = http_calls(out)
        assert create["url"] == "https://ids.example.com/api/threads"
        assert stream["url"] == "https://bot.example.com/api/threads/t-77/stream"

    def test_a_refused_create_is_the_credential_path(self):
        out = run(SSE_CREATE, {"http": [{"url_contains": "ids.example.com", "status": 401, "body": "no"}]})
        assert out["reply"]["status_code"] == 401


class TestWebSocket:
    FRAMES = [{"json": {"type": "token", "text": "Hi "}}, {"json": {"type": "token", "text": "there"}},
              {"json": {"type": "done"}}, {"json": {"type": "token", "text": "NOT READ"}}]

    def test_send_the_frame_collect_until_done_and_close(self):
        out = run(WS, {"ws": {"frames": self.FRAMES}})
        assert out["reply"]["body"] == {"response": "Hi there"}
        fns = [c["fn"] for c in out["calls"]]
        assert fns.index("ws.send") < fns.index("ws.recv")
        assert fns.index("ws.close") > max(i for i, f in enumerate(fns) if f == "ws.recv"), "closed after the last read"
        send = next(c for c in out["calls"] if c["fn"] == "ws.send")
        assert send["frame"] == {"message": "What is the status of order 42?"}
        connect = next(c for c in out["calls"] if c["fn"] == "ws.connect")
        assert connect["url"] == "wss://sock.example.com/demo?code=abc123"
        assert "Content-Type" not in connect["headers"] and connect["headers"]["x-lab-code"]
        assert sum(1 for c in out["calls"] if c["fn"] == "ws.recv") == 3, "stops at the done frame"

    def test_an_idle_gap_ends_a_turn_with_no_terminal_frame(self):
        cfg = {k: v for k, v in WS.items() if k != "done_when"}
        out = run(cfg, {"ws": {"frames": [{"json": {"text": "A"}}, {"json": {"text": "B"}}]}})
        assert out["reply"]["body"] == {"response": "AB"}
        recvs = [c["timeoutMs"] for c in out["calls"] if c["fn"] == "ws.recv"]
        assert recvs[0] == 30000 and recvs[1:] == [1500, 1500], "full wait for the first frame, idle after"

    def test_a_socket_that_will_not_open_is_a_502_and_preflight_exists(self):
        out = run(WS, {"ws": {"fail": "handshake 403"}})
        assert out["reply"]["status_code"] == 502
        pre = run(WS, {"ws": {"frames": []}}, entry="checkReachability")
        assert pre["reply"]["status_code"] == 200 and out["defines_preflight"]

    def test_the_socket_url_parameter_when_the_app_url_is_a_page(self):
        out = run(WS, {"ws": {"frames": self.FRAMES}}, url="https://sock.example.com/page",
                  params={"ws_url": "wss://sock.example.com/demo?code=abc123"})
        connect = next(c for c in out["calls"] if c["fn"] == "ws.connect")
        assert connect["url"] == "wss://sock.example.com/demo?code=abc123"


class TestSessionApi:
    MINT = {"url_contains": "/session/api/conversations", "method": "POST", "body": {"conversation_id": "c-1"}}

    def test_mint_once_then_send_through_the_session(self):
        out = run(SESSION, {"http": [self.MINT, {"url_contains": "/session/api/messages", "method": "POST",
                                                 "body_contains": "c-1", "body": {"reply": "Sure."}}]})
        assert out["reply"]["body"] == {"response": "Sure."}
        mint, send = http_calls(out)
        assert mint["url"] == "https://bot.example.com/session/api/conversations"
        assert send["body"] == {"message": "What is the status of order 42?", "conversation_id": "c-1"}
        assert out["state"] == {"session_id": "c-1"}
        assert out["defines_preflight"]

    def test_a_dead_session_is_remade_once(self):
        out = run(SESSION, {"http": [
            {"url_contains": "/conversations", "body": {"conversation_id": "old"}, "once": True},
            {"url_contains": "/messages", "body_contains": "old", "status": 401, "body": "expired", "once": True},
            {"url_contains": "/conversations", "body": {"conversation_id": "new"}, "once": True},
            {"url_contains": "/messages", "body_contains": "new", "body": {"reply": "ok"}},
        ]})
        assert out["reply"]["body"] == {"response": "ok"} and out["state"] == {"session_id": "new"}
        assert len(http_calls(out)) == 4

    def test_a_401_straight_after_a_fresh_mint_is_the_credential_failing(self):
        out = run(SESSION, {"http": [{"url_contains": "/conversations", "body": {"conversation_id": "x"}},
                                     {"url_contains": "/messages", "status": 401, "body": "no"}]})
        assert out["reply"]["status_code"] == 401

    def test_the_id_in_the_path_is_rendered_on_the_apps_origin(self):
        out = run(SESSION_IN_PATH, {"http": [
            {"url_contains": "auth.example.com/v1/sessions", "method": "POST", "body": {"conversation_id": "s9"}},
            {"url_contains": "/v1/sessions/s9/messages", "method": "POST", "body": {"reply": "yes"}},
        ]})
        assert out["reply"]["body"] == {"response": "yes"}
        assert http_calls(out)[1]["url"] == "https://bot.example.com/v1/sessions/s9/messages"

    def test_preflight_is_a_mint_and_reports_the_credential(self):
        ok = run(SESSION, {"http": [self.MINT]}, entry="checkReachability")
        assert ok["reply"]["status_code"] == 200
        bad = run(SESSION, {"http": [{"url_contains": "/conversations", "status": 403, "body": "x"}]},
                  entry="checkReachability")
        assert bad["reply"]["status_code"] == 403


    SESSION_IN_HEADER = {
        **SESSION, "session_extract": "token", "session_header": "X-Conv-Token",
        "session_header_value": "{{SESSION_ID}}", "message_body": {"message": "{{PROMPT}}"},
    }

    def test_the_minted_token_rides_in_the_header_of_the_message_call_only(self):
        """The Target Lab's /session shape: mint -> {token}, then x-conv-token on every message."""
        out = run(self.SESSION_IN_HEADER, {"http": [
            {"url_contains": "/session/api/conversations", "method": "POST", "body": {"token": "tok-77"}},
            {"url_contains": "/session/api/messages", "method": "POST", "body": {"reply": "Sure."}},
        ]})
        assert out["reply"]["body"] == {"response": "Sure."}
        mint, send = http_calls(out)
        assert "X-Conv-Token" not in mint["headers"], "nothing to carry before the mint"
        assert send["headers"]["X-Conv-Token"] == "tok-77"
        assert send["headers"]["x-lab-code"] == "code-from-the-app-record"
        assert send["body"] == {"message": "What is the status of order 42?"}
        assert out["state"] == {"session_id": "tok-77"}

    def test_a_dead_token_is_re_minted_and_the_new_one_sent(self):
        out = run(self.SESSION_IN_HEADER, {"http": [
            {"url_contains": "/conversations", "body": {"token": "old"}, "once": True},
            {"url_contains": "/messages", "status": 401, "body": "expired", "once": True},
            {"url_contains": "/conversations", "body": {"token": "new"}, "once": True},
            {"url_contains": "/messages", "body": {"reply": "ok"}},
        ]})
        assert out["reply"]["body"] == {"response": "ok"} and out["state"] == {"session_id": "new"}
        sends = [c for c in http_calls(out) if "/messages" in c["url"]]
        assert [c["headers"]["X-Conv-Token"] for c in sends] == ["old", "new"]

    def test_a_bearer_template_is_rendered(self):
        cfg = {**self.SESSION_IN_HEADER, "session_header": "Authorization",
               "session_header_value": "Bearer {{SESSION_ID}}"}
        out = run(cfg, {"http": [{"url_contains": "/conversations", "body": {"token": "t1"}},
                                 {"url_contains": "/messages", "body": {"reply": "ok"}}]})
        assert http_calls(out)[1]["headers"]["Authorization"] == "Bearer t1"


class TestSessionPoll:
    def test_create_send_then_poll_until_a_new_bot_turn(self):
        before = {"messages": [{"role": "assistant", "text": "Welcome"}]}
        after = {"messages": [{"role": "assistant", "text": "Welcome"}, {"role": "user", "text": "q"},
                              {"role": "assistant", "text": "Order 42 shipped."}]}
        out = run(POLL, {"http": [
            {"url_contains": "bot.example.com/api/conversations", "method": "POST", "body": {"conversation_id": "c-7"}},
            {"url_contains": "transcripts.example.com/api/conversations/c-7/messages", "method": "GET", "body": before, "once": True},
            {"url_contains": "bot.example.com/api/conversations/c-7/messages", "method": "POST", "body": {"ok": True}},
            {"url_contains": "transcripts.example.com/api/conversations/c-7/messages", "method": "GET", "body": before, "once": True},
            {"url_contains": "transcripts.example.com/api/conversations/c-7/messages", "method": "GET", "body": after},
        ]})
        assert out["reply"]["body"] == {"response": "Order 42 shipped."}
        urls = [(c["method"], c["url"]) for c in http_calls(out)]
        assert urls[0] == ("POST", "https://bot.example.com/api/conversations")
        assert urls[2] == ("POST", "https://bot.example.com/api/conversations/c-7/messages")
        assert sum(1 for c in out["calls"] if c["fn"] == "sleep") == 2
        assert out["state"] == {"conversation_id": "c-7"}

    def test_no_new_turn_within_the_window_is_a_502(self):
        quiet = {"messages": [{"role": "assistant", "text": "Welcome"}]}
        out = run(POLL, {"http": [
            {"url_contains": "bot.example.com/api/conversations", "method": "POST", "body": {"conversation_id": "c-7"}},
            {"url_contains": "bot.example.com/api/conversations/c-7/messages", "method": "POST", "body": {}},
            {"url_contains": "transcripts.example.com", "method": "GET", "body": quiet},
        ]})
        assert out["reply"]["status_code"] == 502
        assert sum(1 for c in out["calls"] if c["fn"] == "sleep") == 30, "bounded by poll.timeout_ms"


class TestLoginScaffold:
    """The login scaffold a dynamic-auth target gets, EXECUTED. Unconfigured it still reaches the
    target so the operator can read the 401 that is the login's spec; configured, it mints the
    credential ONCE (host.state.getOrMint) and carries it as a bearer on the per-turn request."""

    CFG = {"adapter": "direct_api", "endpoint": "https://bot.example.com/api/chat", "method": "POST",
           "body": {"message": "{{PROMPT}}"}, "response_path": "reply",
           "auth": {"type": "oauth2", "grant": "client_credentials",
                    "token_url": "https://idp.example.com/oauth/token"}}

    def test_it_is_the_login_shape(self):
        assert G.plan(self.CFG)["shape"] == "login" and G.plan(self.CFG)["finished"] is False

    def test_unconfigured_it_reaches_the_target_and_reports_the_login(self):
        out = run(self.CFG, {"http": [{"url_contains": "/api/chat", "method": "POST",
                                       "status": 401, "body": {"error": "login required"}}]})
        body = out["reply"]["body"]
        assert out["reply"]["status_code"] == 200
        assert body["reached"] is True and body["logged_in"] is False and body["target_status"] == 401
        assert len(http_calls(out)) == 1, "it must not invent a login URL it was not given"

    def test_configured_it_mints_once_and_carries_the_bearer(self):
        out = run(self.CFG, {"http": [
            {"url_contains": "/oauth/token", "method": "POST", "status": 200,
             "body": {"access_token": "MINTED"}},
            {"url_contains": "/api/chat", "method": "POST", "status": 200, "body": {"reply": "hi"}}]},
            params={"_adaptor_login_url": "https://idp.example.com/oauth/token"})
        assert out["reply"]["body"]["logged_in"] is True
        calls = http_calls(out)
        token = [c for c in calls if "/oauth/token" in c["url"]]
        chat = [c for c in calls if "/api/chat" in c["url"]]
        assert len(token) == 1 and token[0]["method"] == "POST"
        assert chat[0]["headers"]["Authorization"] == "Bearer MINTED"
        assert out["state"]["login_token"] == "MINTED"
