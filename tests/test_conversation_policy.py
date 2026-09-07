"""
test_conversation_policy — a probe is its own conversation unless a run says otherwise.

The platform puts only the prompt on the wire, so the relay cannot tell a single-shot probe from
turn 3 of a multi-turn attack. Chaining every probe into one conversation (what a carried id or a
kept session does) puts hundreds of unrelated attacks into one thread on the target. Pins:
  * per-probe (default): a carried conversation id never crosses a probe boundary;
  * sequential: consecutive probes share the conversation, the latest id is echoed;
  * sequential is bounded: after conversation.max_turns the next probe starts fresh;
  * the supervisor hands the policy to the relay child and records it for `assess results`.
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


class _Target:
    """Returns a fresh id every reply; records what each request carried."""
    def __init__(self):
        self.n = 0
        self.carried = []

    def request(self, method, url, headers=None, timeout=None, json=None, **kw):
        self.carried.append((json or {}).get("conversation_id"))
        self.n += 1
        return _Resp(200, {"reply": "ok", "conversation_id": f"c{self.n}"})


class _Resp:
    def __init__(self, status, body):
        self.status_code, self._body = status, body
        self.text = json.dumps(body); self.content = self.text.encode()
        self.headers = {"content-type": "application/json"}; self.encoding = "utf-8"

    def json(self): return self._body

    def raise_for_status(self):
        if self.status_code >= 400:
            e = requests.HTTPError(str(self.status_code)); e.response = self; raise e


BASE = {"adapter": "direct_api", "endpoint": "http://t/chat", "method": "POST",
        "body": {"message": "{{PROMPT}}"}, "response_path": "reply",
        "carry": {"reply_path": "conversation_id", "request_field": "conversation_id"}}


@pytest.fixture
def target(monkeypatch):
    t = _Target(); monkeypatch.setattr(da.requests, "request", t.request); return t


def _run(a, cfg, n):
    for i in range(n):
        assert asyncio.run(a.send_prompt(f"p{i}", cfg))["success"]


def test_per_probe_is_the_default_and_never_carries(target):
    a = da.DirectAPIAdapter()
    _run(a, BASE, 4)
    assert target.carried == [None, None, None, None]
    assert a._carry_value is None and a._turns == 0          # nothing recorded either


def test_sequential_carries_the_latest_id(target):
    cfg = {**BASE, "conversation": {"policy": "sequential"}}
    _run(da.DirectAPIAdapter(), cfg, 4)
    assert target.carried == [None, "c1", "c2", "c3"]


def test_sequential_is_bounded_by_max_turns(target):
    cfg = {**BASE, "conversation": {"policy": "sequential", "max_turns": 3}}
    _run(da.DirectAPIAdapter(), cfg, 7)
    # turns 1-3 one conversation, turn 4 fresh, turns 5-6 continue it, turn 7 fresh again
    assert target.carried == [None, "c1", "c2", None, "c4", "c5", None]


def test_the_supervisor_hands_the_policy_to_the_child_and_records_it(tmp_path, monkeypatch):
    for p in ("control", "shells/cli"):
        sys.path.insert(0, str(REPO / p))
    import supervisor
    d = tmp_path / "configs"; d.mkdir()
    (d / "c.json").write_text(json.dumps({"adapter": "direct_api", "endpoint": "http://127.0.0.1:9/chat"}))
    seen = {}

    class _Popen:
        def __init__(self, argv, **kw): seen["argv"] = argv; self.pid, self.returncode = 77, None
        def poll(self): return None
    monkeypatch.setattr(supervisor.subprocess, "Popen", _Popen)
    monkeypatch.setattr(supervisor, "_startup_grace_s", lambda: 0.0)
    monkeypatch.setattr(supervisor, "relays_dir", lambda: tmp_path)
    supervisor.start("aapp_pol", config=str(d / "c.json"), adapter=None, api_key="tc-x",
                     self_reconcile=False, conversation="sequential")
    assert "--conversation" in seen["argv"] and seen["argv"][seen["argv"].index("--conversation") + 1] == "sequential"
    assert (supervisor.read_status("aapp_pol") or {}).get("conversation") == "sequential"
    supervisor._clear("aapp_pol")
    supervisor.start("aapp_pol2", config=str(d / "c.json"), adapter=None, api_key="tc-x", self_reconcile=False)
    assert "--conversation" not in seen["argv"]
    assert (supervisor.read_status("aapp_pol2") or {}).get("conversation") == "per-probe"
    supervisor._clear("aapp_pol2")


class _SessionTarget:
    """POST /session -> {sessionId}; POST /session/{id}/message -> a reply. Counts sessions."""
    def __init__(self):
        self.sessions = 0
        self.messages = []

    def post(self, url, json=None, headers=None, timeout=None, **kw):
        if url.endswith("/session"):
            self.sessions += 1
            return _Resp(200, {"sessionId": f"s{self.sessions}"})
        self.messages.append(url.rsplit("/", 2)[1])
        return _Resp(200, {"messages": [{"message": "ok"}]})


SESSION_CFG = {"adapter": "session_api", "session_endpoint": "http://t/session",
               "message_endpoint": "http://t/session/{{SESSION_ID}}/message",
               "session_extract": "sessionId", "message_body": {"text": "{{PROMPT}}"},
               "response_path": "messages.0.message"}


@pytest.fixture
def session_target(monkeypatch):
    from adapters import session_api as sa
    t = _SessionTarget(); monkeypatch.setattr(sa.requests, "post", t.post); return t


def test_session_api_per_probe_opens_a_session_per_probe(session_target):
    from adapters import session_api as sa
    a = sa.SessionAPIAdapter()
    for i in range(3):
        assert asyncio.run(a.send_prompt(f"p{i}", SESSION_CFG))["success"]
    assert session_target.sessions == 3 and session_target.messages == ["s1", "s2", "s3"]


def test_session_api_sequential_keeps_the_session_bounded(session_target):
    from adapters import session_api as sa
    a = sa.SessionAPIAdapter()
    cfg = {**SESSION_CFG, "conversation": {"policy": "sequential", "max_turns": 2}}
    for i in range(5):
        assert asyncio.run(a.send_prompt(f"p{i}", cfg))["success"]
    # turns 1-2 on s1, 3-4 on s2, 5 on s3
    assert session_target.sessions == 3 and session_target.messages == ["s1", "s1", "s2", "s2", "s3"]
