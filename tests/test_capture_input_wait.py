"""The browser capture keeps looking for the chat input instead of trusting one fixed settle.

A bot challenge (a WAF interstitial) solves itself in the page and then RELOADS it. One scan
straight after the settle looked at the interstitial, found no textarea, and the capture came
back holding only the page bootstrap — the HAR had the challenge, the token cookie and the 200
reload, never the chat call. Seen live against a WAF-challenged Straiker range: two captures in
a row ended in "no chat input found" while the next one, a second luckier, went through.
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "runtime"))

from discovery.capture import _await_chat_input  # noqa: E402


class _Page:
    def __init__(self, urls):
        self._urls = list(urls)          # the url the page reports on each poll
        self.url = self._urls[0]
        self.slept_ms = 0

    async def wait_for_timeout(self, ms):
        self.slept_ms += ms
        if len(self._urls) > 1:
            self._urls.pop(0)
            self.url = self._urls[0]


class _Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        self.t += 1.0                    # every look at the clock is a second later
        return self.t


def _run(scans, urls, wait_s, notes):
    page = _Page(urls)
    it = iter(scans)

    async def scan():
        try:
            return next(it)
        except StopIteration:
            return scans[-1]

    found = asyncio.run(_await_chat_input(page, scan, wait_s, notes, clock=_Clock()))
    return page, found


def test_input_that_lands_after_the_challenge_reload_is_found():
    """Interstitial first (nothing), then the reload with the real widget: the third scan wins."""
    good = (7.0, "frame", "loc", "textarea")
    notes = []
    page, found = _run([[], [], [good]], ["https://x/rest", "https://x/rest", "https://x/rest"], 20, notes)
    assert found == [good]
    assert page.slept_ms == 2000
    assert notes == ["waited 2s more for the chat input"]


def test_navigation_during_the_wait_is_noted():
    good = (7.0, "frame", "loc", "textarea")
    notes = []
    _, found = _run([[], [good]], ["https://x/challenge", "https://x/rest"], 20, notes)
    assert found == [good]
    assert notes == ["waited 1s more for the chat input (the page navigated meanwhile: bot challenge or redirect)"]


def test_only_a_search_box_keeps_the_driver_waiting():
    """A negative score is a search box, never the bot: keep looking, then give up at the deadline."""
    search = (-4.0, "frame", "loc", "input[type='text']")
    notes = []
    page, found = _run([[search]], ["https://x/"], 3, notes)
    assert found == [search]
    assert page.slept_ms >= 1000
    assert notes and notes[0].endswith("— none appeared")


def test_zero_wait_is_a_single_scan():
    notes = []
    page, found = _run([[]], ["https://x/"], 0, notes)
    assert found == [] and page.slept_ms == 0 and notes == []


def test_a_good_input_on_the_first_scan_never_waits():
    good = (2.0, "frame", "loc", "textarea")
    notes = []
    page, found = _run([[good]], ["https://x/"], 20, notes)
    assert found == [good] and page.slept_ms == 0 and notes == []
