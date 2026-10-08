"""The SSE adapter gives the target its think time before the first frame and applies the
idle gap only between frames. One socket timeout used to serve both."""
from __future__ import annotations

import sys
import time
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "runtime"))

from adapters import sse_stream  # noqa: E402
from adapters.sse_stream import SSEStreamAdapter  # noqa: E402


class _Sock:
    def __init__(self):
        self.timeouts = []

    def settimeout(self, s):
        self.timeouts.append(s)


class _Resp:
    """Enough of requests.Response for _read_stream: iter_lines, close, and the socket under raw."""
    def __init__(self, lines, sock=None):
        self._lines = [l.encode() if l else b"" for l in lines]
        self.raw = types.SimpleNamespace(_connection=types.SimpleNamespace(sock=sock))
        self.status_code = 200

    def iter_lines(self, decode_unicode=False):
        yield from self._lines

    def close(self):
        pass


def test_the_idle_gap_is_applied_once_the_first_frame_has_arrived():
    sock = _Sock()
    resp = _Resp(['data: {"type":"token","content":"Our "}', "", 'data: {"type":"token","content":"policy."}', "", 'data: {"type":"done"}', ""], sock)
    text, truncated, stalled = SSEStreamAdapter()._read_stream(resp, {"idle_ms": 7000}, deadline=time.time() + 60)
    assert text == "Our policy."
    assert sock.timeouts == [7.0]            # switched exactly once, to the idle gap


def test_a_response_without_a_reachable_socket_keeps_the_request_timeout():
    resp = _Resp(['data: {"type":"token","content":"x"}', ""])
    assert sse_stream._set_read_timeout(resp, 3.0) is False
    text, _, _ = SSEStreamAdapter()._read_stream(resp, {}, deadline=time.time() + 60)
    assert text == "x"


def test_the_request_read_timeout_is_the_think_time_not_the_idle_gap(monkeypatch):
    seen = {}

    class _Session:
        def request(self, method, url, **kw):
            seen["timeout"] = kw.get("timeout")
            return _Resp(['data: {"type":"token","content":"ok"}', "", 'data: {"type":"done"}', ""])

    a = SSEStreamAdapter()
    monkeypatch.setattr(a, "_get_session", lambda cfg: _Session())
    import asyncio
    r = asyncio.run(a.send_prompt("hi", {"base_url": "https://t", "chat_path": "/chat", "timeout_ms": 60000,
                                         "stream": {"format": "sse", "idle_ms": 2000}}))
    assert r.get("response") == "ok"
    connect, read = seen["timeout"]
    assert read > 30                          # the think-time budget, not the 2 s idle gap


def test_first_frame_ms_caps_the_think_time(monkeypatch):
    seen = {}

    class _Session:
        def request(self, method, url, **kw):
            seen["timeout"] = kw.get("timeout")
            return _Resp(['data: {"type":"token","content":"ok"}', ""])

    a = SSEStreamAdapter()
    monkeypatch.setattr(a, "_get_session", lambda cfg: _Session())
    import asyncio
    asyncio.run(a.send_prompt("hi", {"base_url": "https://t", "chat_path": "/chat", "timeout_ms": 60000,
                                     "stream": {"format": "sse", "idle_ms": 2000, "first_frame_ms": 9000}}))
    assert seen["timeout"][1] == 9.0
