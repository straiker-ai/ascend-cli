"""
Marker-framed streams must be recognised from a LIVE probe, not just from a HAR.

A `sentinel_stream` target answers with its own wire format:

    BOT_CHAT_EVENT_BEGIN{"state":{"events":[...]}}BOT_CHAT_EVENT_END

The detector for that already existed, but only ran on the HAR path. A live probe (`map --api`,
`map --curl`) therefore fell through to `direct_api` and captured the RAW FRAMES as the answer —
a config that passes the hard gate while handing the scorer protocol noise instead of the agent's
reply. Every probe in the assessment would then be scored against wire format.

Verified before and after the fix.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "runtime"))

_spec = importlib.util.spec_from_file_location("ascend_cli", REPO / "shells" / "cli" / "ascend.py")
cli = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cli)

from runtime.discovery import classify  # noqa: E402
import manual  # noqa: E402

FRAME = (
    'BOT_CHAT_EVENT_BEGIN{"conversationID":"abc"}BOT_CHAT_EVENT_END'
    'BOT_CHAT_EVENT_BEGIN{"state":{"events":[{"author":"AGENT",'
    '"message":{"text":"I can help with billing."}}]}}BOT_CHAT_EVENT_END'
)


class TestDetection:
    def test_markers_are_found_in_a_real_shaped_reply(self):
        got = classify._detect_sentinel(FRAME)
        assert got and got["value"] == "sentinel_stream"
        assert got["params"]["begin_marker"] == "BOT_CHAT_EVENT_BEGIN"
        assert got["params"]["end_marker"] == "BOT_CHAT_EVENT_END"

    def test_adjacent_frames_do_not_confuse_the_name_match(self):
        """Real streams concatenate frames with NO separator: `..._ENDNAME_BEGIN`.

        An unanchored name match captured `BOT_CHAT_EVENT_ENDBOT_CHAT_EVENT` as a second
        candidate. Both had count 1, so picking by frequency chose between them by SET ORDERING —
        the detector recognised the same payload or not depending on hash order.
        """
        for _ in range(25):
            got = classify._detect_sentinel(FRAME)
            assert got is not None, "detection must not depend on set/hash ordering"
            assert got["params"]["begin_marker"] == "BOT_CHAT_EVENT_BEGIN"
            assert got["params"]["end_marker"] == "BOT_CHAT_EVENT_END"

    def test_the_chosen_marker_is_the_one_that_brackets_real_json(self):
        """Chosen by what parses, not by what appears most often."""
        body = ("NOISE_BEGIN not json NOISE_END "
                'REAL_BEGIN{"a":1}REAL_END REAL_BEGIN{"b":2}REAL_END')
        got = classify._detect_sentinel(body)
        assert got["params"]["begin_marker"] == "REAL_BEGIN"
        assert "2 JSON frame" in got["evidence"]

    def test_plain_json_is_not_mistaken_for_a_stream(self):
        assert classify._detect_sentinel('{"response":"hello"}') is None

    def test_markers_without_json_between_them_are_not_a_stream(self):
        assert classify._detect_sentinel("FOO_BEGIN not json FOO_END") is None

    def test_the_reply_path_is_derived_from_the_frame(self):
        got = cli._sentinel_extract_from(FRAME, "BOT_CHAT_EVENT_BEGIN", "BOT_CHAT_EVENT_END")
        assert got["events_path"] == "state.events"
        assert got["text_field"] == "text"


class TestUpgradeAfterValidation:
    """The reply is the only place the wire format is visible, so the upgrade happens there."""

    class _V:
        """Stand-in validator: the streaming shape returns the real text."""
        def __init__(self, ok=True):
            self.ok = ok
            self.calls = []

        def validate_config(self, adapter, config, prompt, expect, **kw):
            self.calls.append(adapter)
            if adapter == "sentinel_stream":
                return {"ok": self.ok, "response": "I can help with billing.", "matched": True}
            return {"ok": True, "response": FRAME, "matched": True}

    class _Args:
        prompt = "hi"
        timeout = 30
        insecure = False
        json = False

    def _cfg(self):
        return {"adapter": "direct_api", "endpoint": "https://t/x", "method": "POST",
                "body": {"userMessageText": "{{PROMPT}}"},
                "_notes": ["response_path is not set: direct_api will fall back to the deepest "
                           "string in the reply"]}

    def test_a_framed_reply_promotes_the_adapter(self):
        v = self._V()
        cfg, vres = cli._upgrade_streaming_shape(self._cfg(), {"response": FRAME}, self._Args(), v)
        assert cfg["adapter"] == "sentinel_stream"
        assert cfg["begin_marker"] == "BOT_CHAT_EVENT_BEGIN"
        assert cfg["extract"]["events_path"] == "state.events"
        assert "sentinel_stream" in v.calls, "the new shape must be proven against the target"

    def test_the_reported_answer_becomes_the_real_reply(self):
        """The whole point: before, the 'answer' was the wire frame."""
        v = self._V()
        _, vres = cli._upgrade_streaming_shape(self._cfg(), {"response": FRAME}, self._Args(), v)
        assert vres["response"] == "I can help with billing."
        assert "BOT_CHAT_EVENT_BEGIN" not in vres["response"]

    def test_notes_that_contradict_the_new_adapter_are_dropped(self):
        """A note saying "direct_api will fall back…" beside adapter: sentinel_stream is worse
        than no note at all."""
        cfg, _ = cli._upgrade_streaming_shape(self._cfg(), {"response": FRAME}, self._Args(),
                                              self._V())
        joined = " ".join(cfg["_notes"])
        assert "direct_api" not in joined
        assert "marker-framed stream" in joined

    def test_a_failed_upgrade_keeps_the_config_that_worked(self):
        """A working direct_api config beats an unproven 'better' one."""
        v = self._V(ok=False)
        cfg, vres = cli._upgrade_streaming_shape(self._cfg(), {"response": FRAME}, self._Args(), v)
        assert cfg["adapter"] == "direct_api"
        assert vres["response"] == FRAME

    def test_a_plain_json_reply_is_left_alone(self):
        v = self._V()
        original = self._cfg()
        cfg, _ = cli._upgrade_streaming_shape(original, {"response": '{"a":"b"}'},
                                              self._Args(), v)
        assert cfg is original
        assert v.calls == []


class TestSecretsAreNotPrintedByDefault:
    """`map --curl` preserves the request body verbatim, so whatever authenticated the browser is
    now in the config file. Printing that in clear leaks a live credential to a screen-share."""

    def test_body_secrets_are_masked(self):
        cfg = {"message": {"body": {"token": "live-secret", "userMessageText": "{{PROMPT}}"}}}
        out = manual.redact(cfg)
        assert out["message"]["body"]["token"] == "[REDACTED]"
        assert out["message"]["body"]["userMessageText"] == "{{PROMPT}}"

    @pytest.mark.parametrize("key", ["token", "access_token", "api_key", "password",
                                     "client_secret", "session_id", "secret_access_key"])
    def test_every_common_secret_field_name_is_covered(self, key):
        assert manual.redact({key: "x"})[key] == "[REDACTED]"

    def test_headers_are_still_masked(self):
        out = manual.redact({"headers": {"Authorization": "Bearer x", "Accept": "application/json"}})
        assert out["headers"]["Authorization"] == "[REDACTED]"
        assert out["headers"]["Accept"] == "application/json"

    def test_hyphenated_and_cased_names_are_normalised(self):
        assert manual.redact({"Access-Token": "x"})["Access-Token"] == "[REDACTED]"

    def test_non_secret_values_survive(self):
        cfg = {"adapter": "sentinel_stream", "begin_marker": "X_BEGIN", "timeout_ms": 30000}
        assert manual.redact(cfg) == cfg
