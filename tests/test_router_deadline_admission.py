"""A caller deadline must not admit abandoned work into a live conversation."""
import threading
import time

import pytest

from dispatch import ConversationRouter


@pytest.fixture
def runtime(tmp_path):
    routers, releases = [], []

    def make(kind="locked"):
        path = tmp_path / (kind + ".py")
        if kind == "async":
            handler = '''async def send_prompt(prompt):
    starts.append(prompt)
    if prompt == "first":
        started.set()
        await asyncio.to_thread(release.wait, 2)
    return prompt
'''
        elif kind in ("error", "cancel"):
            failure = "RuntimeError('fixture')" if kind == "error" else "asyncio.CancelledError()"
            handler = ("async def send_prompt(prompt):\n"
                       "    if prompt == 'bad': raise " + failure + "\n"
                       "    return prompt\n")
        else:
            handler = '''def send_prompt(prompt):
    with lock:
        starts.append(prompt)
        if prompt == "first":
            started.set()
            release.wait(2)
        return prompt
'''
        path.write_text('''import asyncio, threading
from contextlib import nullcontext
starts = []
started, release = threading.Event(), threading.Event()
''' + ("lock = threading.Lock()\n" if kind == "locked" else "lock = nullcontext()\n") + handler)
        router = ConversationRouter()
        routers.append(router)
        config = {"adapter_module": str(path)}

        def send(prompt, *, conv="a", timeout=0.05):
            return router.send("custom", config, "fixture", prompt, conv, timeout)

        def state(conv="a"):
            values = router._instances[f"custom:fixture:{conv}"]._fn.__globals__
            releases.append(values["release"])
            return values

        return router, send, state

    yield make
    for event in releases:
        event.set()
    for router in routers:
        # Drain test-owned executor work before closing its event loop.
        import asyncio
        future = asyncio.run_coroutine_threadsafe(router._loop.shutdown_default_executor(), router._loop)
        future.result(timeout=3)
        router._loop.call_soon_threadsafe(router._loop.stop)
        router._loop_thread.join(2)
        router._loop.close()


@pytest.mark.parametrize("kind", ["locked", "unlocked", "async"])
def test_expired_turn_does_not_admit_another_prompt_and_other_conversations_progress(runtime, kind):
    router, send, state = runtime(kind)
    assert send("first")["success"] is False
    first = state()
    assert first["started"].is_set()
    rejected = send("second")
    assert rejected["success"] is False
    assert send("independent", conv="b", timeout=0.5)["response"] == "independent"
    assert first["starts"] == ["first"]
    first["release"].set()
    # A completed overdue turn releases admission, without replaying either input.
    deadline = time.monotonic() + 1
    while time.monotonic() < deadline:
        after = send("after", timeout=0.1)
        if after["success"]:
            break
        time.sleep(0.005)
    assert after["response"] == "after"
    assert first["starts"] == ["first", "after"]


def test_reset_does_not_hide_work_still_running_for_the_same_conversation(runtime):
    router, send, state = runtime()
    assert not send("first")["success"]
    first = state()
    assert router.reset() == 1
    assert send("second")["success"] is False
    assert first["starts"] == ["first"]
    first["release"].set()


@pytest.mark.parametrize("kind", ["error", "cancel"])
def test_completed_error_or_cancellation_does_not_block_the_next_call(runtime, kind):
    _, send, _ = runtime(kind)
    assert send("bad", timeout=0.5)["success"] is False
    assert send("after", timeout=0.5)["response"] == "after"


def test_waiting_for_the_conversation_lock_uses_the_callers_deadline(runtime):
    _, send, state = runtime()
    first_result = []
    first = threading.Thread(target=lambda: first_result.append(send("first", timeout=1)))
    first.start()
    deadline = time.monotonic() + 0.5
    while time.monotonic() < deadline:
        try:
            values = state()
            if values["started"].is_set():
                break
        except (KeyError, AttributeError):
            pass
        time.sleep(0.005)
    release = threading.Timer(0.3, values["release"].set)
    release.start()
    try:
        start = time.monotonic()
        second = send("second", timeout=0.04)
        elapsed = time.monotonic() - start
    finally:
        values["release"].set()
        release.cancel()
        first.join(2)
    assert not first.is_alive() and first_result[0]["success"]
    assert second["success"] is False
    assert elapsed < 0.2
    assert values["starts"] == ["first"]


def test_healthy_calls_still_serialize_and_complete_inside_their_deadlines(runtime):
    _, send, state = runtime()
    first_result = []
    thread = threading.Thread(target=lambda: first_result.append(send("first", timeout=1)))
    thread.start()
    deadline = time.monotonic() + 0.5
    while time.monotonic() < deadline:
        try:
            values = state()
            if values["started"].is_set():
                break
        except (KeyError, AttributeError):
            pass
        time.sleep(0.005)
    release = threading.Timer(0.03, values["release"].set)
    release.start()
    try:
        second = send("second", timeout=0.5)
    finally:
        values["release"].set()
        release.cancel()
        thread.join(2)
    assert first_result[0]["response"] == "first" and second["response"] == "second"
    assert values["starts"] == ["first", "second"]
