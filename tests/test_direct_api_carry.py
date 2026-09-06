"""
test_direct_api_carry — a conversation id handed back in every reply is echoed on the next turn.

Some targets return a conversation id in each reply and expect it on the next request; some
ROTATE it, so the id you used is invalid the moment you have the reply, and after N turns the
conversation closes. A stateless adapter sends turn 2 without the id (a new conversation, so
multi-turn attacks never land) or with a stale one (a hard 409 -- every probe after that is a
transport error). `carry` in the config names the reply path and the request field; the adapter
instance keeps the latest id, echoes it, and when the target rejects it (409 stale / 410 closed)
drops it and sends once more without -- a fresh conversation, which is what the target asked for.
"""
import asyncio
import json
import sys
from pathlib import Path

import pytest
import requests

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "runtime"))
from adapters import direct_api as da  # noqa: E402


class _RotatingTarget:
    """POST /chat -> reply + a NEW conversation_id; the old one 409s; closes after 3 turns."""
    MAX_TURNS = 3

    def __init__(self):
        self.live = {}          # current id -> turns so far
        self.n = 0
        self.calls = []

    def request(self, method, url, headers=None, timeout=None, json=None, **kw):
        body = json or {}
        self.calls.append(dict(body))
        given = body.get("conversation_id")
        if given is not None:
            turns = self.live.pop(given, None)
            if turns is None:
                return _resp(409, {"error": "stale conversation id"})
            if turns >= self.MAX_TURNS:
                return _resp(410, {"error": "conversation closed", "hint": "omit conversation_id"})
        else:
            turns = 0
        self.n += 1
        new = f"conv-{self.n}"
        self.live[new] = turns + 1
        return _resp(200, {"reply": f"turn {turns + 1} ok", "conversation_id": new})


class _Resp:
    def __init__(self, status, body):
        self.status_code = status
        self._body = body
        self.text = json.dumps(body)
        self.content = self.text.encode()
        self.headers = {"content-type": "application/json"}
        self.encoding = "utf-8"

    def json(self):
        return self._body

    def raise_for_status(self):
        if self.status_code >= 400:
            e = requests.HTTPError(f"{self.status_code}")
            e.response = self
            raise e


def _resp(status, body):
    return _Resp(status, body)


CFG = {"adapter": "direct_api", "endpoint": "http://t/chat", "method": "POST",
       "body": {"message": "{{PROMPT}}"}, "response_path": "reply",
       "carry": {"reply_path": "conversation_id", "request_field": "conversation_id"}}


@pytest.fixture
def target(monkeypatch):
    t = _RotatingTarget()
    monkeypatch.setattr(da.requests, "request", t.request)
    return t


def _send(adapter, prompt, cfg=CFG):
    return asyncio.run(adapter.send_prompt(prompt, cfg))


def test_each_turn_echoes_the_id_from_the_previous_reply(target):
    a = da.DirectAPIAdapter()
    for i in range(3):
        out = _send(a, f"q{i}")
        assert out["success"], out
    sent = [c.get("conversation_id") for c in target.calls]
    assert sent == [None, "conv-1", "conv-2"], sent          # turn 1 has no id; each later turn echoes the latest


def test_a_closed_conversation_is_reopened_without_the_id(target):
    a = da.DirectAPIAdapter()
    for i in range(4):
        out = _send(a, f"q{i}")
        assert out["success"], (i, out)
    sent = [c.get("conversation_id") for c in target.calls]
    # turn 4 carried conv-3 -> 410 -> retried once with no id -> a fresh conversation
    assert sent[:3] == [None, "conv-1", "conv-2"] and sent[3] == "conv-3" and sent[4] is None
    assert target.calls[-1]["message"] == "q3"


def test_without_carry_nothing_changes(target):
    a = da.DirectAPIAdapter()
    cfg = {k: v for k, v in CFG.items() if k != "carry"}
    for i in range(2):
        assert _send(a, f"q{i}", cfg)["success"]
    assert all("conversation_id" not in c for c in target.calls)
