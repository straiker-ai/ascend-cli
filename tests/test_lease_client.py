"""
test_lease_client.py — the pull-mode bridge client, fully offline.

The lease client is the piece that can lose a probe or leak a secret if it gets
this wrong, so the invariants under test are the load-bearing ones:
  * an empty poll is normal, not an error;
  * a handler that raises still submits a 500 (a probe is NEVER dropped);
  * 401/403 from the bridge is fatal (bad key) — stop, don't hammer;
  * transient network errors back off and retry;
  * stop() ends the loop cleanly;
  * capture files are 0600 and redact Authorization/Cookie/token headers;
  * stats counters reflect what happened.

All HTTP is mocked at urllib.request.urlopen — no sockets are opened.
"""
import importlib
import json
import os
import stat
import urllib.request

import pytest

from conftest import FakeHTTPResponse, http_error

lease_client = importlib.import_module("lease_client")
LeaseClient = lease_client.LeaseClient


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def make_probes(n, prefix="r"):
    return [{"request_id": f"{prefix}{i}", "msg_id": f"m{i}",
             "message": {"payload": {"body": {"prompt": f"probe {i}"}}}}
            for i in range(n)]


def ok_handler(message):
    return 200, {"response": "ok"}


def boom_handler(message):
    raise RuntimeError("handler exploded")


class UrlopenHarness:
    """Serves /v2/lease and /v2/result and records result submissions.

    First lease returns `first_batch`; the second lease stops the client and
    returns empty, giving a deterministic single-cycle run_forever.
    """

    def __init__(self, client, first_batch):
        self.client = client
        self.first_batch = first_batch
        self.submissions = []
        self.lease_calls = 0

    def __call__(self, req, timeout=None, **kw):
        url = req.full_url
        data = getattr(req, "data", None)
        if url.endswith("/v2/lease"):
            self.lease_calls += 1
            if self.lease_calls == 1:
                body = {"probes": self.first_batch}
            else:
                self.client.stop()
                body = {"probes": []}
            return FakeHTTPResponse(json.dumps(body).encode())
        # /v2/result
        self.submissions.append(json.loads(data.decode()))
        return FakeHTTPResponse(b"{}")


# --------------------------------------------------------------------------- #
# empty poll is not an error
# --------------------------------------------------------------------------- #
def test_empty_poll_no_error(monkeypatch):
    client = LeaseClient(api_key="tc-x", handler=ok_handler)
    harness = UrlopenHarness(client, first_batch=[])
    monkeypatch.setattr(urllib.request, "urlopen", harness)
    client.run_forever()
    assert client.stats["empty_polls"] >= 1
    assert client.stats["answered"] == 0
    assert client.stats["failed"] == 0
    assert harness.submissions == []


# --------------------------------------------------------------------------- #
# single + batch probes get answered and submitted
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("n", [1, 2, 3, 5, 10, 25])
def test_batch_all_answered_and_submitted(monkeypatch, n):
    client = LeaseClient(api_key="tc-x", handler=ok_handler, max_workers=4)
    harness = UrlopenHarness(client, first_batch=make_probes(n))
    monkeypatch.setattr(urllib.request, "urlopen", harness)
    client.run_forever()
    assert client.stats["leased"] == n
    assert client.stats["answered"] == n
    assert client.stats["failed"] == 0
    assert len(harness.submissions) == n
    for sub in harness.submissions:
        assert sub["payload"]["status_code"] == 200


@pytest.mark.parametrize("n", [1, 4, 8])
@pytest.mark.parametrize("workers", [1, 2, 10])
def test_batch_permute_workers(monkeypatch, n, workers):
    client = LeaseClient(api_key="tc-x", handler=ok_handler, max_workers=workers)
    harness = UrlopenHarness(client, first_batch=make_probes(n))
    monkeypatch.setattr(urllib.request, "urlopen", harness)
    client.run_forever()
    assert client.stats["answered"] == n
    submitted_ids = {s["request_id"] for s in harness.submissions}
    assert submitted_ids == {f"r{i}" for i in range(n)}


# --------------------------------------------------------------------------- #
# handler exception → 500 submitted, never dropped
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("n", [1, 3, 5])
def test_handler_exception_submits_500(monkeypatch, n):
    client = LeaseClient(api_key="tc-x", handler=boom_handler)
    harness = UrlopenHarness(client, first_batch=make_probes(n))
    monkeypatch.setattr(urllib.request, "urlopen", harness)
    client.run_forever()
    # every probe still produced a submission, all 500, and counted as failed
    assert len(harness.submissions) == n
    assert client.stats["failed"] == n
    assert client.stats["answered"] == 0
    for sub in harness.submissions:
        assert sub["payload"]["status_code"] == 500
        assert "_error" in sub["payload"]["body"]
        assert "handler exploded" in sub["payload"]["body"]["_error"]


def test_mixed_success_and_failure(monkeypatch):
    calls = {"n": 0}

    def flaky(message):
        calls["n"] += 1
        if calls["n"] % 2 == 0:
            raise ValueError("even fails")
        return 200, {"response": "ok"}

    client = LeaseClient(api_key="tc-x", handler=flaky, max_workers=1)
    harness = UrlopenHarness(client, first_batch=make_probes(6))
    monkeypatch.setattr(urllib.request, "urlopen", harness)
    client.run_forever()
    assert len(harness.submissions) == 6  # none dropped
    codes = sorted(s["payload"]["status_code"] for s in harness.submissions)
    assert codes == [200, 200, 200, 500, 500, 500]


# --------------------------------------------------------------------------- #
# 401 / 403 fatal
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("code", [401, 403])
def test_auth_failure_is_fatal(monkeypatch, code):
    """A rejected thin key must set fatal_error and RETURN (not SystemExit): run_forever
    often runs in a daemon thread where SystemExit dies silently and the caller then
    misreports a bad key as an egress timeout (P0.7)."""
    client = LeaseClient(api_key="tc-bad", handler=ok_handler)

    def responder(req, timeout=None, **kw):
        raise http_error(req.full_url, code)

    monkeypatch.setattr(urllib.request, "urlopen", responder)
    client.run_forever()   # returns, does not raise
    assert client.fatal_error is not None
    assert "bridge key" in client.fatal_error


# --------------------------------------------------------------------------- #
# transient network error backs off then can be stopped
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("code", [500, 502, 503, 429])
def test_transient_http_error_backoff(monkeypatch, code):
    client = LeaseClient(api_key="tc-x", handler=ok_handler)

    def responder(req, timeout=None, **kw):
        client.stop()  # end the loop after this error is handled
        raise http_error(req.full_url, code)

    monkeypatch.setattr(urllib.request, "urlopen", responder)
    client.run_forever()  # must not raise
    assert client.stats["lease_errors"] >= 1


def test_url_error_backoff(monkeypatch):
    import urllib.error
    client = LeaseClient(api_key="tc-x", handler=ok_handler)

    def responder(req, timeout=None, **kw):
        client.stop()
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr(urllib.request, "urlopen", responder)
    client.run_forever()
    assert client.stats["lease_errors"] >= 1


# --------------------------------------------------------------------------- #
# stop() works
# --------------------------------------------------------------------------- #
def test_stop_before_run_exits_immediately(monkeypatch):
    client = LeaseClient(api_key="tc-x", handler=ok_handler)
    client.stop()

    def responder(req, timeout=None, **kw):
        raise AssertionError("should never lease after stop()")

    monkeypatch.setattr(urllib.request, "urlopen", responder)
    client.run_forever()  # returns without leasing


# --------------------------------------------------------------------------- #
# capture: 0600 + redaction
# --------------------------------------------------------------------------- #
def test_capture_file_mode_and_redaction(monkeypatch, tmp_path):
    cap = tmp_path / "cap.jsonl"
    client = LeaseClient(api_key="tc-secret", handler=ok_handler,
                         capture_path=str(cap))
    probe = {
        "request_id": "r0", "msg_id": "m0",
        "message": {"payload": {
            "headers": {"Authorization": "Bearer super-secret-token",
                        "Cookie": "session=abc123",
                        "X-Api-Key": "key-should-hide",
                        "X-Safe": "keepme"},
            "body": {"prompt": "hello"}}}}
    harness = UrlopenHarness(client, first_batch=[probe])
    monkeypatch.setattr(urllib.request, "urlopen", harness)
    client.run_forever()

    assert cap.exists()
    mode = stat.S_IMODE(os.stat(cap).st_mode)
    assert mode == 0o600

    text = cap.read_text()
    assert "super-secret-token" not in text
    assert "session=abc123" not in text
    assert "key-should-hide" not in text
    assert "[REDACTED]" in text
    assert "keepme" in text  # non-sensitive header preserved
    # both a probe and a result record were written
    kinds = [json.loads(ln)["kind"] for ln in text.splitlines()]
    assert "probe" in kinds and "result" in kinds


def test_no_capture_when_path_unset(monkeypatch, tmp_path):
    client = LeaseClient(api_key="tc-x", handler=ok_handler)
    harness = UrlopenHarness(client, first_batch=make_probes(1))
    monkeypatch.setattr(urllib.request, "urlopen", harness)
    client.run_forever()
    # nothing to assert on a file; just ensure the run completed with capture off
    assert client.capture_path is None
    assert client.stats["answered"] == 1


# --------------------------------------------------------------------------- #
# redaction unit coverage (nested / case-insensitive)
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("key", ["Authorization", "authorization", "COOKIE",
                                 "Set-Cookie", "x-api-key", "X-Csrf-Token",
                                 "proxy-authorization", "x-amz-security-token"])
def test_redact_sensitive_keys(key):
    client = LeaseClient(api_key="tc-x", handler=ok_handler)
    out = client._redact({"headers": {key: "SENSITIVE", "keep": "ok"}})
    assert out["headers"][key] == "[REDACTED]"
    assert out["headers"]["keep"] == "ok"


def test_redact_recurses_into_lists_and_nested():
    client = LeaseClient(api_key="tc-x", handler=ok_handler)
    out = client._redact({"a": [{"Cookie": "x"}, {"b": {"Authorization": "y"}}]})
    assert out["a"][0]["Cookie"] == "[REDACTED]"
    assert out["a"][1]["b"]["Authorization"] == "[REDACTED]"


# --------------------------------------------------------------------------- #
# result delivery: retried with backoff, counted separately, on a shorter timeout
# --------------------------------------------------------------------------- #
def test_submit_failure_retried_then_counted(monkeypatch):
    # a result that never delivers is retried, then counted as submit_errors — never crashes,
    # and `answered` (local) diverges from `delivered` (server-acked), which is the signal to watch
    import urllib.error
    client = LeaseClient(api_key="tc-x", handler=ok_handler)
    monkeypatch.setattr(client, "_sleep", lambda s: None)   # no real backoff waits in the test
    state = {"lease": 0}

    def responder(req, timeout=None, **kw):
        if req.full_url.endswith("/v2/lease"):
            state["lease"] += 1
            if state["lease"] == 1:
                return FakeHTTPResponse(json.dumps({"probes": make_probes(2)}).encode())
            client.stop()
            return FakeHTTPResponse(json.dumps({"probes": []}).encode())
        raise urllib.error.URLError("result endpoint down")

    monkeypatch.setattr(urllib.request, "urlopen", responder)
    client.run_forever()  # must not raise despite submit failures
    assert client.stats["answered"] == 2        # handler produced answers (local)
    assert client.stats["delivered"] == 0        # none acked by the server
    assert client.stats["submit_errors"] == 2    # both dropped after retries


def test_submit_transient_failure_then_delivers(monkeypatch):
    import urllib.error
    client = LeaseClient(api_key="tc-x", handler=ok_handler)
    monkeypatch.setattr(client, "_sleep", lambda s: None)
    state = {"lease": 0, "result": 0}

    def responder(req, timeout=None, **kw):
        if req.full_url.endswith("/v2/lease"):
            state["lease"] += 1
            if state["lease"] == 1:
                return FakeHTTPResponse(json.dumps({"probes": make_probes(1)}).encode())
            client.stop()
            return FakeHTTPResponse(json.dumps({"probes": []}).encode())
        state["result"] += 1
        if state["result"] == 1:
            raise urllib.error.URLError("first attempt times out")
        return FakeHTTPResponse(b"{}")           # the retry succeeds

    monkeypatch.setattr(urllib.request, "urlopen", responder)
    client.run_forever()
    assert client.stats["answered"] == 1
    assert client.stats["delivered"] == 1        # the retry recovered it
    assert client.stats["submit_errors"] == 0
    assert state["result"] == 2                  # exactly one retry


def test_result_uses_shorter_timeout_than_lease(monkeypatch):
    # /v2/result is an ordinary POST and must NOT inherit the long-poll's (wait_ms + 10)s ceiling
    client = LeaseClient(api_key="tc-x", handler=ok_handler)
    seen = {}

    def responder(req, timeout=None, **kw):
        if req.full_url.endswith("/v2/lease"):
            seen["lease_timeout"] = timeout
            return FakeHTTPResponse(json.dumps({"probes": make_probes(1)}).encode())
        seen["result_timeout"] = timeout
        client.stop()
        return FakeHTTPResponse(b"{}")

    monkeypatch.setattr(urllib.request, "urlopen", responder)
    client.run_forever()
    assert seen["lease_timeout"] == client.http_timeout        # long-poll ceiling (35s)
    assert seen["result_timeout"] == client.result_timeout     # separate result ceiling (20s)
    assert seen["result_timeout"] < seen["lease_timeout"]
