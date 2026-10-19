"""Offline response-contract timelines; no browser or provider is contacted."""

import asyncio
import sys
import time
from types import ModuleType, SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from adapters import browser


class Element:
    def __init__(self, text="", visible=True, identity=None):
        self.text = text
        self.visible = visible
        self.identity = identity if identity is not None else object()

    async def inner_text(self):
        return self.text

    async def is_visible(self):
        return self.visible

    async def query_selector(self, selector):
        if selector == "[":
            raise ValueError("Invalid selector")
        return self

    async def evaluate(self, expression, previous):
        return self.identity == previous.identity


def state(text="", *, done=False, error=False, identity="reply", marker="done"):
    return {
        ".reply": [Element(text, identity=identity)] if text else [],
        ".done": [Element(visible=done, identity=marker)],
        ".error": [Element(visible=error)],
    }


class Target:
    def __init__(self, states):
        self.states = states
        self.index = 0
        self.submissions = 0
        self.input = SimpleNamespace(click=AsyncMock(), fill=AsyncMock(),
                                     press=AsyncMock(side_effect=self.submit))

    async def submit(self, *args):
        self.submissions += 1
        self.index = min(self.index + 1, len(self.states) - 1)

    async def query_selector_all(self, selector):
        if selector == "[":
            raise ValueError("Invalid selector")
        return self.states[self.index].get(selector, [])

    async def query_selector(self, selector):
        elements = await self.query_selector_all(selector)
        return elements[0] if elements else None

    async def wait_for_selector(self, selector, **kwargs):
        if selector == ".send":
            return SimpleNamespace(click=self.submit)
        return self.input


@pytest.fixture
def harness(monkeypatch):
    pw = ModuleType("playwright")
    api = ModuleType("playwright.async_api")
    pw.async_api = api
    monkeypatch.setitem(sys.modules, "playwright", pw)
    monkeypatch.setitem(sys.modules, "playwright.async_api", api)

    def run(states, overrides=None, send="enter", omit=(), setup=None, turns=1):
        target = Target(states)
        adapter = browser.BrowserAdapter()
        adapter._target = target
        adapter._page = SimpleNamespace(screenshot=AsyncMock())
        adapter._ensure_session = AsyncMock()
        clock = SimpleNamespace(now=0.0)
        real_sleep = asyncio.sleep

        async def sleep(seconds):
            clock.now += seconds
            target.index = min(target.index + 1, len(states) - 1)
            await real_sleep(0)

        monkeypatch.setattr(browser, "time", SimpleNamespace(
            time=time.time, monotonic=lambda: clock.now))
        monkeypatch.setattr(browser, "asyncio", SimpleNamespace(
            sleep=sleep, wait_for=asyncio.wait_for, create_task=asyncio.create_task,
            gather=asyncio.gather, TimeoutError=asyncio.TimeoutError))
        response = {"container_selector": ".reply", "completion_selector": ".done",
                    "error_selector": ".error", "timeout_ms": 10,
                    "poll_interval_ms": 1, "stabilization_delay_ms": 0,
                    "fixed_wait_ms": 0}
        response.update(overrides or {})
        for key in omit:
            response.pop(key, None)
        config = {"url": "https://example.invalid", "send": {"method": send,
                  "selector": ".send"}, "response": response}
        if setup:
            setup(adapter, target, clock)

        async def exercise():
            results = [await adapter.send_prompt("question", config) for _ in range(turns)]
            return results[0] if turns == 1 else results

        result = asyncio.run(exercise())
        return result, target, adapter, clock

    return run


@pytest.mark.parametrize("strategy", ["new_element", "text_change", "loading_indicator", "fixed"])
@pytest.mark.parametrize("send", ["enter", "click"])
def test_waits_for_visible_completion_not_partial_text(harness, strategy, send):
    result, target, _, _ = harness(
        [state(), state("partial"), state("more"), state("complete", done=True)],
        {"wait_strategy": strategy}, send)
    assert result["success"] is True
    assert result["response"] == "complete"
    assert target.submissions == 1


@pytest.mark.parametrize("states", [
    [state(), state("partial")],
    [state("old", done=True), state("partial", done=True)],
    [state("old"), state("old", done=True)],
])
def test_missing_or_stale_completion_or_response_times_out(harness, states):
    result, target, _, clock = harness(states)
    assert result["success"] is False
    assert result["response"] == ""
    assert "Timed out" in result["error"]
    assert target.submissions == 1
    assert clock.now <= 0.011


def test_reused_marker_must_clear_before_completing(harness):
    result, _, _, _ = harness([state("old", done=True), state("partial"),
                               state("final", done=True)])
    assert result["response"] == "final"


def test_new_marker_and_replaced_response_can_repeat_same_text(harness):
    result, _, _, _ = harness([state("same", done=True),
        state("same", done=True, marker="next", identity="next")])
    assert result["success"] is True
    assert result["response"] == "same"


@pytest.mark.parametrize("done", [False, True])
def test_visible_error_wins_over_text_and_completion(harness, done):
    result, target, _, _ = harness([state(), state("partial", done=done, error=True)])
    assert result["success"] is False
    assert result["response"] == ""
    assert "error_selector" in result["error"]
    assert target.submissions == 1


def test_preexisting_error_prevents_submission(harness):
    result, target, _, _ = harness([state(error=True)])
    assert result["success"] is False
    assert target.submissions == 0


@pytest.mark.parametrize("override", [
    {"completion_selector": ""}, {"completion_selector": None},
    {"completion_selector": 2}, {"error_selector": []},
    {"error_selector": None}, {"error_selector": " "},
    {"container_selector": ""}, {"timeout_ms": 0}, {"timeout_ms": float("inf")},
    {"timeout_ms": float("nan")}, {"timeout_ms": 10**400},
    {"timeout_ms": True}, {"poll_interval_ms": -1}, {"poll_interval_ms": "2"},
    {"fixed_wait_ms": -1}, {"stabilization_delay_ms": float("inf")},
    {"completion_selector": "["}, {"error_selector": "["},
    {"container_selector": "["}, {"text_selector": "["},
])
def test_invalid_contract_rejected_before_submission(harness, override):
    result, target, _, _ = harness([state(), state("answer", done=True)], override)
    assert result["success"] is False
    assert target.submissions == 0


def test_completion_only_contract(harness):
    # Absence, not an empty value, disables an optional selector.
    result, _, _, _ = harness([state(), state("final", done=True)], omit=("error_selector",))
    assert result["success"] is True


def test_extracts_text_after_observing_completion(harness):
    def setup(adapter, target, clock):
        query = target.query_selector_all

        async def query_with_final_update(selector):
            if target.submissions and selector == ".done":
                target.states[target.index][".reply"][0].text = "final"
            return await query(selector)

        target.query_selector_all = query_with_final_update

    result, _, _, _ = harness([state(), state("partial", done=True)], setup=setup)
    assert result["response"] == "final"


def test_error_appearing_during_text_extraction_wins(harness):
    def setup(adapter, target, clock):
        extract = adapter._extract_text

        async def extract_with_error(element, selector):
            result = await extract(element, selector)
            if target.submissions:
                target.states[target.index][".error"][0].visible = True
            return result

        adapter._extract_text = extract_with_error

    result, _, _, _ = harness([state(), state("final", done=True)], setup=setup)
    assert result["success"] is False
    assert "error_selector" in result["error"]


def test_two_turns_do_not_reuse_first_completion(harness):
    results, target, _, _ = harness([
        state(), state("first", done=True), state("second partial", done=True),
        state("second partial"), state("second final", done=True)], turns=2)
    assert [result["response"] for result in results] == ["first", "second final"]
    assert target.submissions == 2


@pytest.mark.parametrize("error", [False, True])
def test_error_only_contract_retains_legacy_wait_with_error_guard(harness, error):
    def setup(adapter, target, clock):
        adapter._wait_for_response = AsyncMock(return_value="final")

    result, target, adapter, _ = harness([state(), state("final", error=error)],
        omit=("completion_selector",), setup=setup)
    assert result["success"] is not error
    assert result["response"] == ("" if error else "final")
    assert target.submissions == 1
    if not error:
        adapter._wait_for_response.assert_awaited_once()


@pytest.mark.parametrize("strategy", ["new_element", "text_change", "loading_indicator", "fixed"])
def test_no_contract_dispatches_unchanged_legacy_strategy(harness, strategy):
    def setup(adapter, target, clock):
        adapter._wait_for_response = AsyncMock(return_value="legacy")

    result, _, adapter, _ = harness([state(), state("legacy")],
        {"wait_strategy": strategy}, omit=("completion_selector", "error_selector"), setup=setup)
    assert result["response"] == "legacy"
    assert adapter._wait_for_response.await_args.args[2] == strategy


def test_contract_does_not_invoke_legacy_wait(harness):
    def setup(adapter, target, clock):
        adapter._wait_for_response = AsyncMock(side_effect=AssertionError("legacy wait invoked"))

    result, _, adapter, _ = harness([state(), state("final", done=True)], setup=setup)
    assert result["success"] is True
    adapter._wait_for_response.assert_not_awaited()


def test_poll_sleep_is_clamped_to_monotonic_deadline(harness):
    result, _, _, clock = harness([state(), state("partial")], {"poll_interval_ms": 1000})
    assert result["success"] is False
    assert clock.now == pytest.approx(0.01)


def test_hung_dom_read_is_cancelled_by_deadline(harness):
    cancelled = []

    def setup(adapter, target, clock):
        query = target.query_selector_all

        async def hanging_query(selector):
            if target.submissions:
                try:
                    await asyncio.Event().wait()
                finally:
                    cancelled.append(True)
            return await query(selector)

        target.query_selector_all = hanging_query

    result, target, _, _ = harness([state(), state("partial")], setup=setup)
    assert result["success"] is False
    assert "Timed out" in result["error"]
    assert target.submissions == 1
    assert cancelled == [True]


def test_error_only_cancels_pending_legacy_wait(harness):
    cancelled = []

    def setup(adapter, target, clock):
        async def wait(*args):
            try:
                await asyncio.Event().wait()
            finally:
                cancelled.append(True)

        adapter._wait_for_response = wait

    result, target, _, _ = harness([state(), state("partial"), state("partial", error=True)],
        omit=("completion_selector",), setup=setup)
    assert result["success"] is False
    assert target.submissions == 1
    assert cancelled == [True]


def test_any_visible_error_match_is_fatal(harness):
    final = state("final", done=True)
    final[".error"].append(Element(visible=True))
    result, _, _, _ = harness([state(), final])
    assert result["success"] is False


def test_hidden_response_is_not_returned(harness):
    final = state("final", done=True)
    final[".reply"][0].visible = False
    result, _, _, _ = harness([state(), final])
    assert result["success"] is False


def test_preflight_dom_timeout_never_submits(harness):
    def setup(adapter, target, clock):
        async def hang(selector):
            await asyncio.Event().wait()

        target.query_selector_all = hang

    result, target, _, _ = harness([state()], setup=setup)
    assert result["success"] is False
    assert "before submission" in result["error"]
    assert target.submissions == 0


def test_error_during_preflight_never_submits(harness):
    def setup(adapter, target, clock):
        snapshot = adapter._response_snapshot

        async def snapshot_with_error(*args):
            result = await snapshot(*args)
            target.states[target.index][".error"][0].visible = True
            return result

        adapter._response_snapshot = snapshot_with_error

    result, target, _, _ = harness([state()], setup=setup)
    assert result["success"] is False
    assert target.submissions == 0


def test_wall_clock_changes_do_not_control_contract_deadline(harness, monkeypatch):
    def setup(adapter, target, clock):
        calls = []

        def wall_time():
            calls.append(True)
            assert len(calls) == 1, "response waiting consulted wall time"
            return 0

        monkeypatch.setattr(browser.time, "time", wall_time)

    result, _, _, clock = harness([state(), state("partial")], setup=setup)
    assert "Timed out" in result["error"]
    assert clock.now == pytest.approx(0.01)


def test_late_completion_after_deadline_is_not_accepted(harness):
    def setup(adapter, target, clock):
        snapshot = adapter._response_snapshot

        async def late_snapshot(*args):
            result = await snapshot(*args)
            if target.submissions:
                clock.now = 1
            return result

        adapter._response_snapshot = late_snapshot

    result, _, _, _ = harness([state(), state("final", done=True)], setup=setup)
    assert result["success"] is False
    assert "Timed out" in result["error"]


def test_new_visible_marker_is_accepted_beside_old_marker(harness):
    final = state("final", done=True)
    final[".done"].append(Element(identity="new"))
    result, _, _, _ = harness([state("old", done=True), final])
    assert result["response"] == "final"


@pytest.mark.parametrize("insert_before", [False, True])
def test_history_count_change_alone_is_not_a_fresh_response(harness, insert_before):
    before, after = state("old"), state("old", done=True)
    changed = before if insert_before else after
    changed[".reply"].insert(0, Element("earlier", identity="earlier"))
    result, _, _, _ = harness([before, after])
    assert result["success"] is False
    assert "Timed out" in result["error"]


def test_no_contract_preserves_new_element_stabilization(harness):
    result, target, _, _ = harness([state(), state("partial"), state("stable")],
        omit=("completion_selector", "error_selector"))
    assert result["response"] == "stable"
    assert target.submissions == 1


def test_no_contract_preserves_fixed_wait(harness):
    result, target, _, _ = harness([state(), state("partial"), state("fixed result")],
        {"wait_strategy": "fixed"}, omit=("completion_selector", "error_selector"))
    assert result["response"] == "fixed result"
    assert target.submissions == 1


def test_no_contract_preserves_text_change_wait(harness):
    result, target, _, _ = harness([
        state(), state("initial"), state("changed"), state("stable")],
        {"wait_strategy": "text_change"}, omit=("completion_selector", "error_selector"))
    assert result["response"] == "stable"
    assert target.submissions == 1


def test_no_contract_preserves_loading_indicator_wait(harness):
    loading = state("partial")
    loading[".loading"] = [Element()]
    result, target, _, _ = harness([state(), loading, state("settling"), state("final")],
        {"wait_strategy": "loading_indicator", "loading_selector": ".loading"},
        omit=("completion_selector", "error_selector"))
    assert result["response"] == "final"
    assert target.submissions == 1


@pytest.mark.parametrize("text_selector", [None, ""])
def test_existing_optional_text_selector_remains_supported(harness, text_selector):
    result, _, _, _ = harness([state(), state("final", done=True)],
                              {"text_selector": text_selector})
    assert result["response"] == "final"


def test_error_only_legacy_count_includes_hidden_containers(harness):
    before = state("old")
    before[".reply"].insert(0, Element("hidden", visible=False))

    def setup(adapter, target, clock):
        adapter._wait_for_response = AsyncMock(return_value="final")

    result, _, adapter, _ = harness([before, state("final")],
        omit=("completion_selector",), setup=setup)
    assert result["success"] is True
    assert adapter._wait_for_response.await_args.args[3] == 2


def test_cdp_cleanup_does_not_close_user_browser():
    adapter = browser.BrowserAdapter()
    owned = SimpleNamespace(close=AsyncMock())
    driver = SimpleNamespace(stop=AsyncMock())
    adapter._browser, adapter._playwright = owned, driver
    adapter._cdp_attached = True
    asyncio.run(adapter._cleanup())
    owned.close.assert_not_awaited()
    driver.stop.assert_awaited_once()
