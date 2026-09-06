"""
test_create_then_transition_connection — the request after a 201 must not inherit a dead socket.

The platform closes the connection after `POST …/assessments` returns 201 without announcing it.
The CLI's very next request -- pause, milliseconds later -- reused that socket and died with
`RemoteDisconnected` before the FIN was visible; urllib3 rightly never retries a POST, so it
surfaced as `recovered: true … the connection dropped (ConnectionError)` on ~43% of 28 real runs,
and on 3 of 3 when the sequence is replayed without a pause. Two pins:
  * the create sends `Connection: close`, so the transitions open a fresh connection;
  * a transition that gets a no-response drop is retried exactly once (it is 409-tolerant, so a
    request that did land is harmless to repeat); any other connection error is not retried.
"""
import sys
from pathlib import Path

import pytest
import requests

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "control"))
import api as apimod  # noqa: E402


class _Resp:
    def __init__(self, status=201, body=None):
        import json as _json
        self.status_code, self.ok, self._body = status, status < 400, body or {}
        self.text = _json.dumps(self._body)
        self.content = self.text.encode()           # _req returns None on an empty body
        self.headers, self.reason = {}, "x"

    def json(self):
        return self._body


@pytest.fixture
def client(monkeypatch):
    c = apimod.AscendAPI(token="s6r_pat_dummy", cache=False)
    monkeypatch.setattr(c, "_bearer", lambda: "jwt")
    return c


def test_create_assessment_sends_connection_close(client, monkeypatch):
    seen = {}

    def fake_request(method, url, headers=None, json=None, timeout=None, **kw):
        seen.update(method=method, url=url, headers=headers)
        return _Resp(201, {"id": "asmt_1"})
    monkeypatch.setattr(client._s, "request", fake_request)
    out = client.create_assessment("aapp_1", "run")
    assert out.get("id") == "asmt_1"
    assert seen["method"] == "POST" and seen["headers"].get("Connection") == "close", seen


def _drop():
    return requests.exceptions.ConnectionError(
        "('Connection aborted.', RemoteDisconnected('Remote end closed connection without response'))")


def test_transition_retries_once_after_a_no_response_drop(client):
    calls = []

    def pause(app, aid):
        calls.append(1)
        if len(calls) == 1:
            raise _drop()
    client._safe_transition(pause, "aapp_1", "asmt_1", want="paused")
    assert len(calls) == 2


def test_transition_gives_up_after_a_second_drop(client):
    def pause(app, aid):
        raise _drop()
    with pytest.raises(requests.exceptions.ConnectionError):
        client._safe_transition(pause, "aapp_1", "asmt_1", want="paused")


def test_other_connection_errors_are_not_retried(client):
    calls = []

    def pause(app, aid):
        calls.append(1)
        raise requests.exceptions.ConnectionError("Max retries exceeded with url")
    with pytest.raises(requests.exceptions.ConnectionError):
        client._safe_transition(pause, "aapp_1", "asmt_1", want="paused")
    assert len(calls) == 1


def test_a_409_still_means_already_there(client):
    def pause(app, aid):
        raise apimod.AscendAPIError("POST …/pause -> 409: invalid_assessment_state")
    client._safe_transition(pause, "aapp_1", "asmt_1", want="paused")   # returns, no raise
