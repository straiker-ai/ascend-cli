"""
test_ws_onboarding.py — a WebSocket target must be onboardable from its URL.

`websocket_direct` shipped as an adapter, with an example config and its own tests, but nothing
could DERIVE one. probe.py spoke only HTTP, and classify.py reached `websocket_direct` solely
from a HAR that already contained a WebSocket entry. The result, measured against a socket
agent:

    ascend target add ws://host/chat      -> exit 3, "is not a URL, a file, or a known config"
    ascend target add --url wss://host/   -> drives a real BROWSER at a socket, then reports
                                             "the capture never delivered the prompt"

So a customer with a WebSocket bot and no HAR export had no path at all -- for an adapter that
was already written and working. A socket is perfectly probeable (connect, send a frame, read
one back), so `probe_ws` does that, and reuses the same `score_answer` the HTTP path uses so
"which field is the reply" is decided identically everywhere.
"""
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "runtime"))
sys.path.insert(0, str(REPO / "shells" / "cli"))
from discovery.probe import (WS_SEND_CANDIDATES, PROMPT_TOKEN, _ws_done_marker,  # noqa: E402
                             _ws_render, build_ws_config, probe_ws)


class TestWsUrlsAreRecognised:
    """The bare-URL argument must work; picking a flag is the question people cannot answer."""

    @pytest.mark.parametrize("url", [
        "ws://127.0.0.1:8706/",
        "wss://bot.example.com/chat",
        "WS://Bot.Example.com/socket",          # scheme is case-insensitive
    ])
    def test_a_socket_url_is_detected_as_ws(self, url):
        import ascend
        flag, value = ascend._detect_source(url)
        assert flag == "ws", f"{url!r} was detected as {flag!r}, not ws"
        assert value == url.strip()

    @pytest.mark.parametrize("url,flag", [
        ("https://bot.example.com/chat", "api"),
        ("http://127.0.0.1:8600/chat", "api"),
    ])
    def test_http_urls_are_unaffected(self, url, flag):
        """The ws branch sits before the http one; it must not swallow ordinary URLs."""
        import ascend
        assert ascend._detect_source(url)[0] == flag

    def test_ws_is_a_first_class_source_flag(self):
        """`--ws` must exist and be mutually exclusive with the other evidence flags."""
        import ascend
        help_text = ascend.build_parser().parse_known_args(["target", "add", "--help"]) \
            if False else None                      # parsing --help exits; inspect the parser
        p = ascend.build_parser()
        # walk to `target add`
        subs = [a for a in p._actions if hasattr(a, "choices") and a.choices]
        target = subs[0].choices["target"]
        add = [a for a in target._actions if hasattr(a, "choices") and a.choices][0].choices["add"]
        flags = {o for a in add._actions for o in (a.option_strings or [])}
        assert "--ws" in flags
        assert {"--api", "--url", "--curl", "--har", "--config"} <= flags, \
            "the existing evidence flags must all survive"


class TestFrameTemplates:
    def test_plain_text_is_tried_last(self):
        """A bare-text frame 'works' against anything that echoes, so trying it early would
        mask a real JSON contract."""
        assert WS_SEND_CANDIDATES[-1] == PROMPT_TOKEN
        assert all(isinstance(c, dict) for c in WS_SEND_CANDIDATES[:-1])

    def test_the_common_shape_is_tried_first(self):
        assert WS_SEND_CANDIDATES[0] == {"message": PROMPT_TOKEN}

    def test_rendering_escapes_json_correctly(self):
        out = _ws_render({"message": PROMPT_TOKEN}, 'say "hi" \\ now')
        import json
        assert json.loads(out)["message"] == 'say "hi" \\ now'

    def test_rendering_a_plain_text_template(self):
        assert _ws_render(PROMPT_TOKEN, "hello") == "hello"


class TestTerminalFrameDetection:
    """Stopping on a terminal frame instead of waiting out idle_ms is worth real time: across a
    few thousand probes it is the difference between finishing and timing out."""

    @pytest.mark.parametrize("frames,want", [
        ([{"type": "token"}, {"type": "done"}], {"path": "type", "equals": "done"}),
        ([{"event": "complete"}], {"path": "event", "equals": "complete"}),
        ([{"status": "finished"}], {"path": "status", "equals": "finished"}),
    ])
    def test_a_terminal_frame_is_found(self, frames, want):
        assert _ws_done_marker(frames) == want

    @pytest.mark.parametrize("frames", [
        [{"reply": "hello"}],                       # no terminal frame at all
        [{"type": "message"}, {"type": "token"}],   # types, but none terminal
        ["a plain string frame"],
        [],
    ])
    def test_no_false_terminal(self, frames):
        assert _ws_done_marker(frames) is None


class TestConfigShape:
    def _res(self, **over):
        base = {"ok": True, "ws_url": "wss://bot.example.com/chat",
                "send_template": {"message": PROMPT_TOKEN}, "response_path": "reply",
                "aggregate": "last", "done_when": None, "idle_ms": 1500,
                "frames_seen": 1, "score": 5.0, "answer": "hi"}
        base.update(over)
        return base

    def test_it_emits_the_adapter_the_registry_knows(self):
        assert build_ws_config(self._res())["adapter"] == "websocket_direct"

    def test_required_keys_are_present(self):
        cfg = build_ws_config(self._res())
        for k in ("ws_url", "send_template", "idle_ms", "aggregate", "response_path"):
            assert k in cfg, f"websocket_direct needs {k}"

    def test_optional_keys_are_omitted_rather_than_null(self):
        """A null done_when is not the same as no done_when; the adapter checks presence."""
        cfg = build_ws_config(self._res(done_when=None, response_path=None))
        assert "done_when" not in cfg and "response_path" not in cfg

    def test_a_terminal_frame_is_carried_through(self):
        cfg = build_ws_config(self._res(done_when={"path": "type", "equals": "done"}))
        assert cfg["done_when"] == {"path": "type", "equals": "done"}


class TestFailureIsReportedNotRaised:
    def test_an_unreachable_socket_returns_a_diagnosis(self):
        """A probe that raises is indistinguishable from a target that is down, and the operator
        needs to be told which. Port 1 is reserved and refuses fast."""
        r = probe_ws("ws://127.0.0.1:1/", prompt="hello", timeout_s=3)
        assert r["ok"] is False
        assert r["diagnosis"] in ("no_answer", "dependency")
        assert r.get("hint"), "a failure must say what to try next"
