"""The envelope-shape hint becomes a correction only when the capture proves it.

Derivation picks an answer field; the self-check (verify_config) says whether it reproduces the
reply the widget showed; frameworks.recognize names the envelope and where its reply usually
sits. shape_fix joins the three: a failed field is replaced by the shape's path when replaying
that path over the captured reply reproduces it, and offered as a suggestion when it does not.
A field that passed is never touched."""
from __future__ import annotations

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "runtime"))
sys.path.insert(0, str(REPO))

from runtime.discovery.verify import shape_fix, verify_config  # noqa: E402
from runtime.discovery.frameworks import recognize  # noqa: E402

REPLY = "Your order shipped yesterday by ground and arrives tomorrow afternoon."


def _ev(body: dict, reply: str = REPLY) -> dict:
    return {"pairs": [{"request": {"url": "https://bot.example.test/api/chat", "method": "POST", "headers": {},
                                   "raw_body": json.dumps({"message": "where is my order?"})},
                       "response": {"status": 200, "headers": {}, "json": body, "raw_body": json.dumps(body)}}],
            "prompt_sent": "where is my order?", "reply_text": reply}


OPENAI = {"status": "complete", "id": "chatcmpl-9f2c41d07b3e5a8c1290ffee7781", "choices": [{"message": {"content": REPLY}}]}


def test_a_failed_field_is_corrected_when_the_shape_path_verifies():
    ev = _ev(OPENAI)
    cfg = {"adapter": "direct_api", "endpoint": "https://bot.example.test/api/chat", "response_path": "status"}
    cc = verify_config(cfg, ev)
    assert cc["checked"] and not cc["ok"], cc
    fw = recognize(ev)
    assert fw["response_path"] == "choices.0.message.content"
    out = shape_fix(cfg, ev, cc, fw)
    assert out["fix"] and out["fix"]["from"] == "status" and out["fix"]["to"] == "choices.0.message.content"
    assert out["config"]["response_path"] == "choices.0.message.content" and out["fix"]["overlap"] >= 0.9
    assert out["fix"]["check"]["ok"] and out["suggestion"] is None
    assert cfg["response_path"] == "status", "the input config was mutated"


def test_a_field_that_passed_is_never_touched():
    ev = _ev(OPENAI)
    cfg = {"adapter": "direct_api", "endpoint": "https://bot.example.test/api/chat", "response_path": "choices.0.message.content"}
    out = shape_fix(cfg, ev, verify_config(cfg, ev), recognize(ev))
    assert out["fix"] is None and out["suggestion"] is None and out["config"] is cfg


def test_a_shape_path_that_does_not_verify_is_only_suggested():
    body = {"status": "complete", "choices": [{"message": {"content": "Working on it, one moment please while I look that up."}}]}
    ev = _ev(body)                                     # the widget showed REPLY; neither field carries it
    cfg = {"adapter": "direct_api", "endpoint": "https://bot.example.test/api/chat", "response_path": "status"}
    out = shape_fix(cfg, ev, verify_config(cfg, ev), recognize(ev))
    assert out["fix"] is None and out["config"] is cfg
    assert out["suggestion"]["set"] == {"response_path": "choices.0.message.content"} and out["suggestion"]["verified"] is False


def test_no_field_and_nothing_checked_gives_a_suggestion():
    ev = _ev(OPENAI, reply="")                         # no captured reply: nothing can be checked offline
    cfg = {"adapter": "direct_api", "endpoint": "https://bot.example.test/api/chat"}
    cc = verify_config(cfg, ev)
    assert not cc["checked"]
    out = shape_fix(cfg, ev, cc, recognize(ev))
    assert out["fix"] is None and out["suggestion"]["set"]["response_path"] == "choices.0.message.content"
    assert "found no answer field" in out["suggestion"]["why"]


def test_streams_and_unknown_shapes_are_left_alone():
    ev = _ev(OPENAI)
    sse = {"adapter": "sse_stream", "endpoint": "https://bot.example.test/api/chat", "stream": {"format": "sse", "text_path": "delta"}}
    assert shape_fix(sse, ev, {"checked": True, "ok": False, "field": "delta"}, recognize(ev))["fix"] is None
    cfg = {"adapter": "direct_api", "response_path": "status"}
    assert shape_fix(cfg, ev, {"checked": True, "ok": False}, {"framework": None}) == {"config": cfg, "fix": None, "suggestion": None}
