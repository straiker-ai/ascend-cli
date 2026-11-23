"""
test_relay_reauth_streaming.py — a streaming target that answers 401 gets a fresh token and the
prompt again.

MEASURED 2026-11-22 (a benchmark run against a local test target whose token lasts 60 seconds):
four attack prompts reached the relay after the token had expired. The target answered
`401 {"error": "token expired", "hint": "POST /token to mint a new one"}`; the relay sent four
failures back with status 502 and never asked for a new token, although the saved connection
said `auth_lifecycle: reauth_on_401`. The streaming adapter had reported the failure without its
status, so the relay could not tell it was a 401.

The connection config below is the one that run saved (the app's id and name left out); the
target is a local server that speaks the same token and stream shapes.
"""
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
for p in ("runtime", "control"):
    sys.path.insert(0, str(REPO / p))
import call_target as CT  # noqa: E402
import dispatch  # noqa: E402

EXPIRED = {"error": "token expired", "hint": "POST /token to mint a new one"}        # the recorded reply


class _Target(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _json(self, status, body, headers=None):
        raw = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        srv = self.server
        if self.path == "/token":
            srv.token_calls += 1
            if srv.token_status != 200:
                return self._json(srv.token_status, {"error": "identity service unavailable"})
            srv.valid = f"tok-{srv.token_calls}"
            return self._json(200, {"access_token": srv.valid, "expires_in": 60})
        if self.path == "/chat":
            sent = self.headers.get("Authorization", "")
            srv.chats.append(sent)
            if srv.limit_next:
                srv.limit_next -= 1
                return self._json(429, {"error": "too many requests"}, {"Retry-After": "0"})
            if sent != f"Bearer {srv.valid}":
                return self._json(401, EXPIRED)
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            for frame in ('{"delta": "Your order "}', '{"delta": "has shipped."}', "[DONE]"):
                self.wfile.write(f"data: {frame}\n\n".encode())
                self.wfile.flush()
            return None
        return self._json(404, {"error": "not found"})


@pytest.fixture()
def target():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Target)
    srv.token_calls, srv.token_status, srv.valid, srv.chats, srv.limit_next = 0, 200, None, [], 0
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield srv
    srv.shutdown()
    srv.server_close()


def _config(srv, lifecycle="reauth_on_401"):
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    cfg = {
        "adapter": "sse_stream", "base_url": base, "chat_path": "/chat", "method": "POST",
        "request_template": {"message": "{{PROMPT}}"},
        "stream": {"format": "sse", "text_path": "delta", "done_when": {"contains": "[DONE]"}, "idle_ms": 20000},
        "auth": {"type": "derived_multihop",
                 "steps": [{"method": "POST", "url": f"{base}/token", "json": {},
                            "extract": [{"var": "TOKEN", "path": "access_token"}]}],
                 "attach": {"headers": {"Authorization": "Bearer {{TOKEN}}"}}},
    }
    if lifecycle:
        cfg["auth_lifecycle"] = {"type": lifecycle}
    return cfg


def _probe(text="What is the status of my order?"):
    return {"header": {"type": "probe", "id": "p1"}, "metadata": {}, "payload": {"body": {"prompt": text}, "headers": {}}}


def _caller(srv, lifecycle="reauth_on_401"):
    caller = CT.TargetCaller("sse_stream", "inline", _config(srv, lifecycle))
    assert srv.token_calls == 1 and srv.valid == "tok-1"            # the connection starts with a token
    return caller


def test_a_live_token_answers_with_no_second_sign_in(target):
    caller = _caller(target)
    status, out = caller.handler(_probe())
    assert status == 200 and out["response"] == "Your order has shipped."
    assert target.token_calls == 1 and target.chats == ["Bearer tok-1"]


def test_an_expired_token_is_re_minted_and_the_same_prompt_is_answered(target):
    caller = _caller(target)
    target.valid = "expired-at-the-target"                          # sixty seconds pass
    status, out = caller.handler(_probe())
    assert status == 200 and out["response"] == "Your order has shipped."
    assert target.token_calls == 2, "one sign-in at the start, one after the 401"
    assert target.chats == ["Bearer tok-1", "Bearer tok-2"], "the refused prompt was sent again with the new token"
    # and the token is kept: the next prompt needs no sign-in
    status, _ = caller.handler(_probe("And when does it arrive?"))
    assert status == 200 and target.token_calls == 2 and target.chats[-1] == "Bearer tok-2"


def test_the_targets_401_reaches_the_platform_as_a_401_when_the_connection_has_no_way_to_sign_in_again(target):
    caller = _caller(target, lifecycle=None)
    target.valid = "expired-at-the-target"
    status, out = caller.handler(_probe())
    assert status == 401, "the target's own status, not a generic 502"
    assert out["response"] == "" and "token expired" in out["_error"]
    assert target.token_calls == 1 and target.chats == ["Bearer tok-1"], "no lifecycle, no retry"


def test_when_the_new_sign_in_fails_the_prompt_is_refused_with_the_reason_and_not_sent_again(target):
    caller = _caller(target)
    target.valid = "expired-at-the-target"
    target.token_status = 503
    status, out = caller.handler(_probe())
    assert status == 401 and "re-acquire failed" in out["_error"]
    assert target.token_calls == 2 and target.chats == ["Bearer tok-1"], "nothing is sent without a credential"


def test_a_429_from_a_streaming_target_is_waited_out_and_sent_once_more(target, monkeypatch):
    waits = []
    monkeypatch.setattr(CT.time, "sleep", waits.append)
    caller = _caller(target)
    target.limit_next = 1
    status, out = caller.handler(_probe())
    assert status == 200 and out["response"] == "Your order has shipped."
    assert len(waits) == 1 and len(target.chats) == 2
    target.limit_next = 2                                            # a second 429 stands: one retry only
    status, _ = caller.handler(_probe())
    assert status == 429 and len(target.chats) == 4


@pytest.mark.parametrize("meta,error,expected", [
    ({"status_code": 401}, "anything", 401),
    ({"adapter": "sse_stream"}, 'HTTP 401: {"error": "token expired"}', 401),
    ({}, "HTTP error: 429 Client Error: Too Many Requests for url: http://127.0.0.1/chat", 429),
    (None, "HTTP 503: upstream down", 503),
    ({"status_code": 404}, "HTTP 401: the adapter's own status wins", 404),
    ({}, "Request error: connection refused", None),
    ({}, "HTTP 200: an odd success in an error text", None),
    ({}, "Target produced no output within 30s", None),
    ({"status_code": True}, "", None),
    ({"status_code": "401"}, "", None),
    ({}, None, None),
])
def test_the_targets_status_is_read_from_the_adapter_or_from_the_error_it_wrote(meta, error, expected):
    assert dispatch.upstream_status(meta, error) == expected


def test_a_failure_with_no_status_anywhere_is_still_a_502():
    status, body = dispatch.shape_result({"success": False, "response": "", "error": "Request error: connection refused",
                                          "metadata": {"adapter": "sse_stream"}}, {})
    assert status == 502 and body["_error"].startswith("Request error")
