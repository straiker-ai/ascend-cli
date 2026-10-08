"""The websocket_direct contract is read off the frames the page exchanged, not guessed.

MEASURED on a Lambda-backed socket (2026-09-30): the capture held {"type":"token","text":…}
frames and a {"type":"done"} terminator, the derived config carried only the URL, a fixed send
frame and idle_ms 1500, and 25 of 26 probes came back "No response frames collected".
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "runtime"))

from discovery import classify  # noqa: E402
from discovery.probe import _ws_done_marker as probe_done_marker  # noqa: E402

PROMPT = "Hello, what can you help me with?"
TOKENS = ['{"type": "token", "text": "Our return "}', '{"type": "token", "text": "policy allows 30 days."}',
          '{"type": "done"}']


def _ev(sent, received, prompt=PROMPT, url="wss://gw.example.test/demo?code=x"):
    return {"pairs": [], "prompt_sent": prompt,
            "ws_messages": [{"url": url, "sent": sent, "received": received}]}


def test_send_frame_reply_field_and_terminal_frame_come_from_the_capture():
    p = classify._ws_params(_ev(['{"text": "%s"}' % PROMPT], TOKENS))
    assert p["send_template"] == {"text": "{{PROMPT}}"}          # the page's own frame, not a guess
    assert p["response_path"] == "text"
    assert p["done_when"] == {"path": "type", "equals": "done"}
    assert p["framing"] == "json"
    assert p["idle_ms"] == 1500                                   # a fallback once a terminator exists


def test_the_derived_config_carries_the_reply_field_and_the_terminator():
    ev = _ev(['{"text": "%s"}' % PROMPT], TOKENS)
    t = classify.classify_transport(ev, None)
    assert t["value"] == "websocket"
    assert t["params"]["done_when"] == {"path": "type", "equals": "done"}
    assert t["params"]["response_path"] == "text"


def test_no_terminal_frame_means_a_longer_idle_gap_and_no_done_rule():
    p = classify._ws_params(_ev(['{"text": "%s"}' % PROMPT], TOKENS[:2]))
    assert "done_when" not in p
    assert p["idle_ms"] == 5000


def test_a_nested_reply_field_is_addressed_by_dot_path():
    frames = ['{"event": "delta", "data": {"content": "the answer text here"}}', '{"event": "complete"}']
    p = classify._ws_params(_ev(['{"message": {"text": "%s"}}' % PROMPT], frames))
    assert p["send_template"] == {"message": {"text": "{{PROMPT}}"}}
    assert p["response_path"] == "data.content"
    assert p["done_when"] == {"path": "event", "equals": "complete"}


def test_a_plain_text_socket_keeps_text_framing_and_the_prompt_placeholder():
    p = classify._ws_params(_ev([PROMPT], ["Sure, I can help with orders."]))
    assert p["framing"] == "text"
    assert p["send_template"] == "{{PROMPT}}"
    assert "response_path" not in p and "done_when" not in p


def test_without_a_known_prompt_the_send_frame_falls_back_to_the_common_shape():
    p = classify._ws_params(_ev(['{"text": "hi"}'], TOKENS, prompt=""))
    assert p["send_template"] == {"type": "message", "text": "{{PROMPT}}"}


def test_the_legacy_single_frame_shape_still_derives():
    ev = {"pairs": [], "prompt_sent": "", "ws_messages": [{"url": "https://h/s", "data": '{"type": "done"}'}]}
    p = classify._ws_params(ev)
    assert p["ws_url"] == "wss://h/s" and p["framing"] == "json" and p["done_when"]["equals"] == "done"


def test_the_capture_and_socket_onboarding_paths_agree_on_the_terminal_frame():
    frames = [{"type": "token"}, {"status": "finished"}, {"event": "complete"}]
    assert classify._ws_done_marker(frames) == probe_done_marker(frames)
    assert classify._ws_done_marker([{"reply": "x"}]) is None is probe_done_marker([{"reply": "x"}])
