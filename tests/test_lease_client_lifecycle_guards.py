"""Offline admission and acknowledgement boundaries for the pull client."""
import json
import socket
import threading
import time
import urllib.request

import pytest

import lease_client
from lease_client import LeaseClient


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Lifecycle regression tests must not access a network")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(urllib.request, "urlopen", forbidden)


def probe(request_id="synthetic-request"):
    return {"request_id": request_id, "msg_id": "priv:" + request_id,
            "message": {"payload": {"body": {"prompt": "Synthetic question"}}}}


def test_stop_during_lease_does_not_start_target_or_report_ready():
    calls, ready = [], []
    client = LeaseClient(api_key="synthetic", handler=lambda message: (
        calls.append(message) or (200, {"response": "Synthetic"})))
    client._submit = lambda *args: {"status": "ok"}

    def lease():
        client.stop()
        return {"consumer": client.consumer, "probes": [probe()]}

    client._lease = lease
    client.run_forever(ready_cb=lambda: ready.append(True))
    assert calls == ready == []
    assert client.stats["answered"] == client.stats["delivered"] == 0


@pytest.mark.parametrize("receipt", [{}, {"status": "error"}, {"ok": True}, None, []])
def test_malformed_ack_is_not_delivery_or_an_automatic_retry(receipt):
    client = LeaseClient(api_key="synthetic", handler=lambda message: (200, {}))
    attempts = []
    client._submit = lambda *args: attempts.append(args) or receipt
    assert not client._submit_with_retry("r", "priv:r", 200, {"response": "Synthetic"})
    assert len(attempts) == 1
    assert client.stats["delivered"] == 0
    assert client.stats["submit_errors"] == 1


def test_transient_ack_retry_preserves_answer_without_repeating_target():
    calls, attempts = [], []
    client = LeaseClient(api_key="synthetic", handler=lambda message: (
        calls.append(message) or (200, {"response": "Synthetic answer"})))

    def submit(*args):
        attempts.append(args)
        if len(attempts) == 1:
            raise TimeoutError()
        return {"status": "ok"}

    client._submit = submit
    client._sleep = lambda seconds: None
    client._process(probe())
    assert len(calls) == 1 and len(attempts) == 2
    assert attempts[0] == attempts[1]
    assert client.stats["delivered"] == 1


def test_rate_limit_applies_to_first_concurrent_batch(monkeypatch):
    monkeypatch.setattr(lease_client.time, "time", lambda: 1000.0)
    first_entered, second_entered = threading.Event(), threading.Event()
    waits, errors = [], []

    def handler(message):
        if not first_entered.is_set():
            first_entered.set()
            if not second_entered.wait(1):
                errors.append("second worker did not enter")
        else:
            second_entered.set()
        return 200, {"response": "Synthetic"}

    client = LeaseClient(api_key="synthetic", handler=handler, qpm=600)
    client._stop.wait = lambda timeout: waits.append(timeout) or False
    client._submit = lambda *args: {"status": "ok"}
    first = threading.Thread(target=client._process, args=(probe("first"),))
    second = threading.Thread(target=client._process, args=(probe("second"),))
    first.start()
    assert first_entered.wait(1)
    second.start()
    first.join(2)
    second.join(2)
    assert not first.is_alive() and not second.is_alive() and not errors
    assert waits == [pytest.approx(0.1)]
    assert client.stats["delivered"] == 2


def test_stop_interrupts_rate_wait_before_target_dispatch():
    calls, waiting = [], threading.Event()
    client = LeaseClient(api_key="synthetic", handler=lambda message: (
        calls.append(message) or (200, {"response": "Synthetic"})), qpm=1)
    client._submit = lambda *args: {"status": "ok"}
    client._last_call = time.time()
    original_wait = client._stop.wait

    def wait(timeout):
        waiting.set()
        return original_wait(timeout)

    client._stop.wait = wait
    worker = threading.Thread(target=client._process, args=(probe(),))
    worker.start()
    try:
        assert waiting.wait(1)
        client.stop()
        worker.join(1)
        assert not worker.is_alive() and calls == []
    finally:
        client.stop()
        worker.join(1)


def test_stop_skips_queued_work_but_can_deliver_current_answer():
    calls = []
    client = LeaseClient(api_key="synthetic", handler=lambda message: (
        calls.append(message) or client.stop() or (200, {"response": "Synthetic"})))
    client._submit = lambda *args: {"status": "ok"}
    client._process(probe())
    client._process(probe("queued"))
    assert len(calls) == 1
    assert client.stats["answered"] == client.stats["delivered"] == 1


def test_first_probe_is_captured_when_parent_directory_is_new(tmp_path):
    capture = tmp_path / "new" / "capture.jsonl"
    client = LeaseClient(api_key="synthetic", handler=lambda message: (200, {"response": "Synthetic"}),
                         capture_path=str(capture))
    client._submit = lambda *args: {"status": "ok"}
    client._process(probe())
    assert [json.loads(line)["kind"] for line in capture.read_text().splitlines()] == ["probe", "result"]
