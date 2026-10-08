"""The WebSocket adapter waits for the target's first frame; the idle gap is a rule about
silence BETWEEN frames.

MEASURED on a Lambda-backed socket (2026-09-30): first frame in 2.5-3.8 s, idle_ms 1500 applied
from the start -> 25 of 26 probes under a run came back "No response frames collected".
"""
from __future__ import annotations

import asyncio
import json
import sys
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "runtime"))

from adapters.websocket_direct import WebSocketAdapter  # noqa: E402


class _Socket:
    def __init__(self, script):
        self.script = list(script)      # (delay_s, frame) pairs; frame None = close
        self.sent = []

    async def send(self, s):
        self.sent.append(s)

    async def recv(self):
        if not self.script:
            raise ConnectionError("closed")
        delay, frame = self.script.pop(0)
        await asyncio.sleep(delay)
        if frame is None:
            raise ConnectionError("closed")
        return frame


class _Connect:
    def __init__(self, sock):
        self.sock = sock

    async def __aenter__(self):
        return self.sock

    async def __aexit__(self, *a):
        return False


def _fake_websockets(sock):
    mod = types.ModuleType("websockets")
    mod.connect = lambda url, **kw: _Connect(sock)
    return mod


def _run(script, cfg, monkeypatch):
    sock = _Socket(script)
    monkeypatch.setitem(sys.modules, "websockets", _fake_websockets(sock))
    a = WebSocketAdapter()
    return asyncio.run(a.send_prompt("hello", {"ws_url": "wss://x/s", "timeout_ms": 8000, **cfg})), sock


def test_a_first_frame_slower_than_the_idle_gap_is_still_collected(monkeypatch):
    script = [(0.5, json.dumps({"type": "token", "text": "Our "})), (0.05, json.dumps({"type": "token", "text": "policy."})),
              (0.05, json.dumps({"type": "done"}))]
    r, sock = _run(script, {"idle_ms": 100, "done_when": {"path": "type", "equals": "done"}, "response_path": "text"}, monkeypatch)
    assert r.get("response") == "Our policy."
    assert json.loads(sock.sent[0]) == {"type": "message", "text": "hello"}


def test_first_frame_ms_bounds_the_think_time(monkeypatch):
    script = [(0.6, json.dumps({"type": "token", "text": "late"}))]
    r, _ = _run(script, {"idle_ms": 100, "first_frame_ms": 200}, monkeypatch)
    assert not r.get("response")
    assert "No response frames collected within 0s" in r["error"]


def test_the_idle_gap_still_ends_an_answer_after_frames_flow(monkeypatch):
    script = [(0.05, json.dumps({"text": "a"})), (0.05, json.dumps({"text": "b"})), (0.8, json.dumps({"text": "never read"}))]
    r, _ = _run(script, {"idle_ms": 150}, monkeypatch)
    assert r.get("response") == "ab"


def test_a_gateway_error_frame_is_reported_not_scored(monkeypatch):
    script = [(0.05, json.dumps({"message": "Internal server error", "connectionId": "c1", "requestId": "r1"})), (0.05, None)]
    r, _ = _run(script, {"idle_ms": 100}, monkeypatch)
    assert not r.get("response")
    assert "error frame" in r["error"] and "Internal server error" in r["error"]


def test_frames_without_answer_text_point_at_response_path(monkeypatch):
    script = [(0.05, json.dumps({"type": "token", "payload": {"chunk": "x"}})), (0.05, json.dumps({"type": "done"}))]
    r, _ = _run(script, {"idle_ms": 100, "done_when": {"path": "type", "equals": "done"}, "response_path": "text"}, monkeypatch)
    assert not r.get("response")
    assert "check response_path" in r["error"]
