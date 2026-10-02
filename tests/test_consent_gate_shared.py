"""The consent step is one list for both halves of browser-drive, and a capture's click is replayed
first by the adapter."""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / "runtime"))
from runtime import consent  # noqa: E402
from runtime.discovery import codegen  # noqa: E402


def test_capture_and_adapter_use_the_one_list():
    # source discipline: neither half carries its own consent selectors
    cap = (ROOT / "runtime/discovery/capture.py").read_text()
    adp = (ROOT / "runtime/adapters/browser.py").read_text()
    assert "from consent import selectors" in cap and "from consent import selectors" in adp
    assert "CybotCookiebotDialogBodyButtonAccept" not in adp   # was a private copy
    assert "[id*='accept-btn' i]" in consent.CONSENT_SELECTORS


def test_the_clicked_selector_is_replayed_first():
    assert consent.selectors("button#accept")[0] == "button#accept"
    assert consent.selectors("button:has-text('Accept')")[0] == "button:has-text('Accept')"
    assert consent.selectors("button:has-text('Accept')").count("button:has-text('Accept')") == 1
    assert consent.selectors(None) == consent.CONSENT_SELECTORS


def test_recipe_consent_becomes_the_first_pre_action_selector():
    recipe = {"url": "https://lab.example.test/session", "consent": "button:has-text('Accept & continue')",
              "launcher": None, "input_selector": "#in", "input_frame_url": "https://lab.example.test/session/frame"}
    cfg = codegen.browser_config_from_recipe(recipe["url"], recipe)
    first = cfg["pre_actions"][0]
    assert first["action"] == "dismiss_cookie" and first["selectors"] == ["button:has-text('Accept & continue')"]


def test_no_consent_in_recipe_keeps_the_generic_step():
    cfg = codegen.browser_config_from_recipe("https://lab.example.test/rest", {"url": "https://lab.example.test/rest"})
    first = cfg["pre_actions"][0]
    assert first["action"] == "dismiss_cookie" and "selectors" not in first
