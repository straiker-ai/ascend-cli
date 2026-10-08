"""The generated adapter modules, exercised against fake wires: each must send exactly the request
its contract pins, with the prompt and the environment-held secret in place, and return the reply.
Shapes follow the Target Lab's four transports and an OpenAI-compatible gateway."""
from __future__ import annotations

import asyncio
import re
import json
import os
import sys
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from runtime.discovery import codegen  # noqa: E402


def load(src: str, fake_requests=None, fake_websockets=None, monkeypatch=None):
    """Execute a generated module with a stand-in `requests` / `websockets` and return its namespace."""
    ns: dict = {}
    if fake_requests is not None:
        monkeypatch.setitem(sys.modules, "requests", fake_requests)
    if fake_websockets is not None:
        monkeypatch.setitem(sys.modules, "websockets", fake_websockets)
    exec(compile(src, "<generated>", "exec"), ns)
    return ns


class Resp:
    def __init__(self, body, status=200, lines=None, headers=None):
        self._body, self.status_code, self._lines, self.headers = body, status, lines or [], headers or {}
        self.text = body if isinstance(body, str) else json.dumps(body)
    def json(self): return self._body if not isinstance(self._body, str) else json.loads(self._body)
    def raise_for_status(self):
        if self.status_code >= 400: raise RuntimeError(f"HTTP {self.status_code}")
    def iter_lines(self, decode_unicode=False): return iter(self._lines)
    def close(self): pass


def fake_requests_module(handler):
    m = types.ModuleType("requests")
    calls = []
    def request(method, url, **kw):
        calls.append({"method": method, "url": url, **kw}); return handler(method, url, kw)
    m.request = request
    m.post = lambda url, **kw: request("POST", url, **kw)
    m.get = lambda url, **kw: request("GET", url, **kw)
    class Session:
        def __init__(self): self.cookies = {}
        def request(self, method, url, **kw): return request(method, url, **kw)
        def get(self, url, **kw): return request("GET", url, **kw)
    m.Session = Session
    m.calls = calls
    return m


def test_direct_api_puts_the_query_credential_and_header_from_the_environment(monkeypatch):
    cfg = {"adapter": "direct_api", "url": "https://t.example.test/rest/api/chat", "headers": {"X-Api-Key": "env:T_KEY"},
           "body": {"message": "{{PROMPT}}"}, "response_path": "response",
           "auth": [{"type": "static", "mode": "api_key", "in": "query", "name": "code", "value_ref": "env:T_CODE"}]}
    src = codegen.generate_adapter_module("rest", cfg)
    assert "secret-value" not in src and "raise NotImplementedError" not in src
    fr = fake_requests_module(lambda m, u, kw: Resp({"response": "pong"}))
    monkeypatch.setenv("T_KEY", "k-1"); monkeypatch.setenv("T_CODE", "lab-code")
    ns = load(src, fr, monkeypatch=monkeypatch)
    assert ns["send_prompt"]("ping?") == "pong"
    call = fr.calls[0]
    assert call["url"] == "https://t.example.test/rest/api/chat?code=lab-code"
    assert call["headers"]["X-Api-Key"] == "k-1" and call["json"] == {"message": "ping?"}


def test_a_missing_secret_fails_loudly_with_its_name(monkeypatch):
    src = codegen.generate_adapter_module("rest", {"adapter": "direct_api", "url": "https://t.example.test/c", "headers": {"X-Api-Key": "env:T_KEY"}})
    monkeypatch.delenv("T_KEY", raising=False)
    ns = load(src, fake_requests_module(lambda m, u, kw: Resp({})), monkeypatch=monkeypatch)
    with pytest.raises(RuntimeError, match="set T_KEY"):
        ns["send_prompt"]("x")


def test_session_api_creates_then_sends_through_the_session(monkeypatch):
    cfg = {"adapter": "session_api", "session_endpoint": "https://t.example.test/session/api/conversations",
           "message_endpoint": "https://t.example.test/session/api/conversations/{{SESSION_ID}}/messages",
           "session_extract": "id", "message_body": {"text": "{{PROMPT}}", "conversation": "{{SESSION_ID}}"},
           "response_path": "reply", "headers": {"Cookie": "env:T_COOKIE"}, "warmup": "hi"}
    def handler(method, url, kw):
        if url.endswith("/conversations"): return Resp({"id": "conv-7"})
        return Resp({"reply": "pong " + kw["json"]["text"]})
    fr = fake_requests_module(handler)
    monkeypatch.setenv("T_COOKIE", "sid=abc")
    ns = load(codegen.generate_adapter_module("session", cfg), fr, monkeypatch=monkeypatch)
    assert ns["send_prompt"]("ping") == "pong ping"
    urls = [c["url"] for c in fr.calls]
    assert urls == ["https://t.example.test/session/api/conversations",
                    "https://t.example.test/session/api/conversations/conv-7/messages",      # the warm-up
                    "https://t.example.test/session/api/conversations/conv-7/messages"]
    assert fr.calls[2]["json"] == {"text": "ping", "conversation": "conv-7"} and fr.calls[2]["headers"]["Cookie"] == "sid=abc"


def test_sse_stream_reassembles_token_frames_and_stops_at_done(monkeypatch):
    cfg = {"adapter": "sse_stream", "base_url": "https://t.example.test", "chat_path": "/sse/api/chat",
           "request_template": {"message": "{{PROMPT}}"}, "stream": {"text_path": "text", "done_when": {"path": "type", "equals": "done"}}}
    lines = [b'data: {"type":"token","text":"po"}', b"", b'data: {"type":"status","text":"thinking"}', b"",
             b'data: {"type":"token","text":"ng"}', b"", b'data: {"type":"done"}', b"", b'data: {"type":"token","text":"LATE"}', b""]
    fr = fake_requests_module(lambda m, u, kw: Resp("", lines=lines))
    ns = load(codegen.generate_adapter_module("sse", cfg), fr, monkeypatch=monkeypatch)
    assert ns["send_prompt"]("ping") == "pong"
    call = fr.calls[0]
    assert call["url"] == "https://t.example.test/sse/api/chat" and json.loads(call["data"].decode()) == {"message": "ping"}
    assert call["headers"]["Accept"] == "text/event-stream" and call["stream"] is True


def test_sse_named_events_and_plain_text_frames(monkeypatch):
    cfg = {"adapter": "sse_stream", "base_url": "https://t.example.test", "chat_path": "/chat",
           "stream": {"token_events": ["response"], "done_events": ["end"]}}
    lines = [b"event: status", b'data: {"content":"Searching..."}', b"", b"event: response", b"data: pong", b"", b"event: end", b""]
    fr = fake_requests_module(lambda m, u, kw: Resp("", lines=lines))
    ns = load(codegen.generate_adapter_module("sse2", cfg), fr, monkeypatch=monkeypatch)
    assert ns["send_prompt"]("ping") == "pong"


def test_websocket_sends_the_frame_and_assembles_until_done(monkeypatch):
    cfg = {"adapter": "websocket_direct", "ws_url": "wss://w.example.test/prod", "headers": {"x-api-key": "env:W_KEY"},
           "send_template": {"action": "chat", "text": "{{PROMPT}}"}, "response_path": "delta", "done_when": {"path": "done", "equals": True}, "idle_ms": 200}
    sent = []
    class FakeWS:
        def __init__(self): self.frames = iter([json.dumps({"delta": "po"}), json.dumps({"message": "Internal server error", "requestId": "r1"}), json.dumps({"delta": "ng", "done": True})])
        async def send(self, data): sent.append(json.loads(data))
        async def recv(self):
            try: return next(self.frames)
            except StopIteration: raise RuntimeError("closed")
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
    seen = {}
    def connect(url, **kw):
        seen.update(url=url, **kw); return FakeWS()
    fws = types.ModuleType("websockets"); fws.connect = connect
    monkeypatch.setenv("W_KEY", "wk")
    ns = load(codegen.generate_adapter_module("ws", cfg), fake_requests_module(lambda *a: Resp({})), fws, monkeypatch=monkeypatch)
    assert ns["send_prompt"]("ping") == "pong"
    assert sent == [{"action": "chat", "text": "ping"}] and seen["url"] == "wss://w.example.test/prod" and seen["additional_headers"]["x-api-key"] == "wk"


def test_openai_compatible_picks_a_model_and_reads_the_completion(monkeypatch):
    cfg = {"adapter": "openai_compatible", "endpoint": "http://127.0.0.1:4141", "headers": {"Authorization": "env:LITELLM_KEY"}}
    def handler(method, url, kw):
        if url.endswith("/v1/models"): return Resp({"data": [{"id": "demo-model"}]})
        return Resp({"choices": [{"message": {"content": "pong"}}]})
    fr = fake_requests_module(handler)
    monkeypatch.setenv("LITELLM_KEY", "Bearer sk-x")
    ns = load(codegen.generate_adapter_module("oai", cfg), fr, monkeypatch=monkeypatch)
    assert ns["send_prompt"]("ping") == "pong"
    assert fr.calls[0]["url"] == "http://127.0.0.1:4141/v1/models"
    post = fr.calls[1]
    assert post["url"] == "http://127.0.0.1:4141/v1/chat/completions" and post["json"]["model"] == "demo-model"
    assert post["json"]["messages"][-1] == {"role": "user", "content": "ping"} and post["headers"]["Authorization"] == "Bearer sk-x"


def test_every_generated_module_runs_from_the_command_line_and_the_scaffold_still_says_so():
    for kind in ("direct_api", "session_api", "sse_stream", "websocket_direct", "openai_compatible"):
        src = codegen.generate_adapter_module("x", {"adapter": kind, "url": "https://t.example.test", "base_url": "https://t.example.test", "chat_path": "/c",
                                                     "session_endpoint": "https://t.example.test/s", "message_endpoint": "https://t.example.test/m/{{SESSION_ID}}"})
        assert '__name__ == "__main__"' in src and "raise NotImplementedError" not in src, kind
        compile(src, kind, "exec")
    scaffold = codegen.generate_adapter_module("x", {"adapter": "browser", "url": "https://t.example.test"})
    assert "raise NotImplementedError" in scaffold


def test_the_lab_style_auth_block_puts_the_cookie_on_the_wire(monkeypatch):
    cfg = {"adapter": "direct_api", "endpoint": "https://t.example.test/rest/api/chat", "body": {"message": "{{PROMPT}}"}, "response_path": "reply",
           "headers": {"Referer": "https://t.example.test/rest?code=lab-SECRET", "Sec-Fetch-Mode": "cors", "User-Agent": "Mozilla"},
           "auth": {"type": "static", "mode": "headers", "headers": {"Cookie": "env:T_COOKIE"}}}
    src = codegen.generate_adapter_module("rest", cfg)
    assert "lab-SECRET" not in src and "Sec-Fetch-Mode" not in src and "Referer" in src
    fr = fake_requests_module(lambda m, u, kw: Resp({"reply": "pong"}))
    monkeypatch.setenv("T_COOKIE", "lab_access=abc")
    ns = load(src, fr, monkeypatch=monkeypatch)
    assert ns["send_prompt"]("ping") == "pong"
    assert fr.calls[0]["headers"]["Cookie"] == "lab_access=abc" and fr.calls[0]["headers"]["Referer"] == "https://t.example.test/rest"


def test_every_static_mode_and_an_oauth2_grant_resolve_from_the_environment(monkeypatch):
    base = {"adapter": "direct_api", "endpoint": "https://t.example.test/c", "body": {"q": "{{PROMPT}}"}, "response_path": "a"}
    cases = {
        "bearer": ({"type": "static", "mode": "bearer", "value_ref": "env:TOK"}, {"TOK": "t1"}, lambda c: c["headers"]["Authorization"] == "Bearer t1"),
        "cookie": ({"type": "static", "mode": "cookie", "name": "sid", "value_ref": "env:SID"}, {"SID": "s1"}, lambda c: c["headers"]["Cookie"] == "sid=s1"),
        "basic": ({"type": "static", "mode": "basic", "username_ref": "literal:bob", "password_ref": "env:PW"}, {"PW": "pw"}, lambda c: c["headers"]["Authorization"] == "Basic Ym9iOnB3"),
        "custom": ({"type": "static", "mode": "custom", "name": "X-Token", "template": "Tok {{VALUE}}", "value_ref": "env:XT"}, {"XT": "v"}, lambda c: c["headers"]["X-Token"] == "Tok v"),
        "api_key_query": ({"type": "static", "mode": "api_key", "in": "query", "name": "key", "value_ref": "env:K"}, {"K": "kk"}, lambda c: c["url"].endswith("/c?key=kk")),
    }
    for label, (auth, env, check) in cases.items():
        fr = fake_requests_module(lambda m, u, kw: Resp({"a": "ok"}))
        for k, v in env.items():
            monkeypatch.setenv(k, v)
        ns = load(codegen.generate_adapter_module(label, {**base, "auth": auth}), fr, monkeypatch=monkeypatch)
        assert ns["send_prompt"]("x") == "ok" and check(fr.calls[-1]), label
    # oauth2 client credentials: the token endpoint is called once, then the bearer rides every request
    auth = {"type": "oauth2", "grant": "client_credentials", "token_url": "https://id.example.test/token", "client_id_ref": "literal:app", "client_secret_ref": "env:CS", "scope": "chat"}
    def handler(method, url, kw):
        if url.endswith("/token"):
            assert kw["data"] == {"grant_type": "client_credentials", "client_id": "app", "client_secret": "shh", "scope": "chat"}
            return Resp({"access_token": "jwt-1"})
        return Resp({"a": "ok"})
    fr = fake_requests_module(handler); monkeypatch.setenv("CS", "shh")
    ns = load(codegen.generate_adapter_module("oauth", {**base, "auth": auth}), fr, monkeypatch=monkeypatch)
    assert ns["send_prompt"]("x") == "ok" and ns["send_prompt"]("y") == "ok"
    assert [c["url"] for c in fr.calls].count("https://id.example.test/token") == 1
    assert fr.calls[-1]["headers"]["Authorization"] == "Bearer jwt-1"


def test_a_literal_credential_header_is_lifted_to_an_environment_name_not_shipped():
    src = codegen.generate_adapter_module("x", {"adapter": "direct_api", "endpoint": "https://t.example.test/c", "headers": {"Authorization": "Bearer eyJ-real-token"}})
    assert "eyJ-real-token" not in src and "env:ASCEND_SECRET_AUTHORIZATION" in src and "set in the environment before running: ASCEND_SECRET_AUTHORIZATION" in src


def test_forms_that_need_the_runtime_say_so_instead_of_guessing(monkeypatch):
    src = codegen.generate_adapter_module("x", {"adapter": "direct_api", "endpoint": "https://t.example.test/c", "auth": {"type": "csrf", "url": "/csrf"}})
    ns = load(src, fake_requests_module(lambda m, u, kw: Resp({})), monkeypatch=monkeypatch)
    with pytest.raises(RuntimeError, match="needs the Ascend runtime"):
        ns["send_prompt"]("x")


def test_a_credential_in_a_url_query_is_lifted_to_the_environment_and_put_back_on_the_wire(monkeypatch):
    cfg = {"adapter": "websocket_direct", "ws_url": "wss://w.example.test/prod?code=lab-SECRETVALUE&lang=en",
           "send_template": {"text": "{{PROMPT}}"}, "response_path": "delta", "done_when": {"path": "done", "equals": True}}
    src = codegen.generate_adapter_module("ws", cfg)
    assert "lab-SECRETVALUE" not in src and "lang=en" in src and "Set before running: ASCEND_SECRET_" in src
    listed = re.search(r"Set before running: ([^\n]*)", src).group(1)
    assert listed.startswith("ASCEND_SECRET_") and "NAME" not in listed.split(", ")
    env_name = re.search(r"env:(ASCEND_SECRET_[A-Z0-9_]+)", src).group(1)
    class FakeWS:
        def __init__(self): self.frames = iter([json.dumps({"delta": "pong", "done": True})])
        async def send(self, data): pass
        async def recv(self): return next(self.frames)
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
    seen = {}
    def connect(url, **kw):
        seen["url"] = url; return FakeWS()
    fws = types.ModuleType("websockets"); fws.connect = connect
    monkeypatch.setenv(env_name, "lab-SECRETVALUE")
    ns = load(src, fake_requests_module(lambda *a: Resp({})), fws, monkeypatch=monkeypatch)
    assert ns["send_prompt"]("ping") == "pong"
    assert seen["url"] == "wss://w.example.test/prod?lang=en&code=lab-SECRETVALUE"
