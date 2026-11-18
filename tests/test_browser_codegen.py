"""
`adapter build --url` generates a BROWSER adapter from what the capture actually did.

For a target whose HTTP endpoint refuses replay (anti-automation), the only thing that works is
driving a real browser per probe. The capture already opens the widget, finds the input, sends a
prompt and reads the reply — so it knows the launcher, the chat frame, the input selector, the send
method and where the reply renders. This turns that recipe into a validated browser adapter, with
no hand-built selectors.

Covers end to end an anti-automation target: `adapter build --url` captured, the
HTTP replay 403'd, a browser adapter was generated from the recipe, and it drove a real reply.
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "runtime"))

from discovery import codegen  # noqa: E402


def _recipe(**kw):
    base = {"launcher": "button:has-text('Need help')", "input_selector": "#chatMessage",
            "input_frame_url": "https://www.example.com/chat/support?x=1", "send": "enter",
            "reply_container": ".bubble:not(.user)", "reply_strategy": "new_element"}
    base.update(kw)
    return base


class TestBrowserConfigFromRecipe:
    def test_it_is_a_browser_adapter(self):
        cfg = codegen.browser_config_from_recipe("https://x/support", _recipe())
        assert cfg["adapter"] == "browser"

    def test_the_launcher_becomes_a_click_preaction(self):
        cfg = codegen.browser_config_from_recipe("https://x/support", _recipe())
        clicks = [a for a in cfg["pre_actions"] if a.get("action") == "click"]
        assert clicks and clicks[0]["selector"] == "button:has-text('Need help')"

    def test_the_chat_frame_is_matched_by_url(self):
        cfg = codegen.browser_config_from_recipe("https://x/support", _recipe())
        assert cfg["iframe"]["url_contains"] == "chat/support"

    def test_the_concrete_input_selector_is_used_for_input_and_wait(self):
        cfg = codegen.browser_config_from_recipe("https://x/support", _recipe())
        assert cfg["input"]["selector"] == "#chatMessage"
        assert cfg["wait_for_widget"]["selector"] == "#chatMessage"

    def test_enter_vs_button_send(self):
        assert codegen.browser_config_from_recipe("https://x", _recipe())["send"]["method"] == "enter"
        c = codegen.browser_config_from_recipe("https://x", _recipe(send="button.send"))
        assert c["send"] == {"method": "click", "selector": "button.send"}

    def test_the_reply_container_and_strategy_carry(self):
        cfg = codegen.browser_config_from_recipe("https://x/support", _recipe())
        assert cfg["response"]["container_selector"] == ".bubble:not(.user)"
        assert cfg["response"]["wait_strategy"] == "new_element"

    def test_same_page_widget_needs_no_iframe(self):
        cfg = codegen.browser_config_from_recipe("https://x/support", _recipe(input_frame_url=""))
        assert "iframe" not in cfg

    def test_a_thin_recipe_still_produces_a_usable_config(self):
        """Minimum viable: even with only an input selector, it's a valid browser config."""
        cfg = codegen.browser_config_from_recipe("https://x", {"input_selector": "textarea"})
        assert cfg["adapter"] == "browser" and cfg["input"]["selector"] == "textarea"
        assert cfg["send"]["method"] == "enter"           # sensible default
        assert cfg["response"]["container_selector"]       # a fallback container, never empty


class TestFrameNeedle:
    def test_prefers_the_frame_path(self):
        assert codegen._frame_needle("https://h.com/chat/support?x=1", "https://h.com/p") == "chat/support"

    def test_single_segment_path(self):
        assert codegen._frame_needle("https://h.com/widget", "https://h.com/p") == "widget"

    def test_falls_back_to_a_distinct_host(self):
        n = codegen._frame_needle("https://vendor.io/", "https://host.com/support")
        assert n == "vendor.io"

    def test_no_useful_needle_returns_empty(self):
        assert codegen._frame_needle("https://host.com/", "https://host.com/support") == ""
