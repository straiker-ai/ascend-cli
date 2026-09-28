"""
The browser adapter must reach a chat widget that NESTS its frames.

Real widgets (Genesys, Intercom, Salesforce) don't expose the chat as a top-level <iframe> a CSS
selector on the page can reach — the input lives several frames deep. Resolving the frame by URL
(which discovery already knows) handles that. And a configured iframe that never appears must fail
LOUD: the old code silently fell back to the main page, where `textarea` matched a hidden reCAPTCHA
field and the run timed out with a misleading error.

Covers an anti-automation target (a Genesys-nested widget): frame-by-URL resolved the
chat frame and the adapter drove a real reply, where HTTP replay of the same request 403s.
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "runtime"))

from adapters.browser import BrowserAdapter  # noqa: E402


class _Frame:
    def __init__(self, url):
        self.url = url


class _Page:
    def __init__(self, frames):
        self.frames = frames
    async def wait_for_timeout(self, ms):
        return None
    async def wait_for_selector(self, sel, timeout=0):
        raise AssertionError("should not fall back to a CSS selector when url_contains is set")


def _resolve(page, cfg):
    return asyncio.new_event_loop().run_until_complete(
        BrowserAdapter()._resolve_frame(page, cfg))


class TestFrameByUrl:
    def test_finds_a_nested_frame_by_url(self):
        target = _Frame("https://vendor.example.com/chat/support?x=1")
        page = _Page([_Frame("https://vendor.example.com/support"), target,
                      _Frame("https://recaptcha/anchor")])
        assert _resolve(page, {"url_contains": "chat/support"}) is target

    def test_a_missing_frame_fails_loud_not_silent(self):
        """The whole point: never silently return the main page and search the wrong context."""
        page = _Page([_Frame("https://vendor.example.com/support"),
                      _Frame("https://recaptcha/anchor")])
        with pytest.raises(RuntimeError):
            _resolve(page, {"url_contains": "chat/support"})

    def test_no_iframe_config_returns_the_page(self):
        page = _Page([_Frame("https://x")])
        assert _resolve(page, None) is page
        assert _resolve(page, {}) is page
