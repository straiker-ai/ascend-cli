"""The offline self-check: a derived config must read the reply the capture shows, and the check
must fail OPEN whenever it cannot judge — a false alarm on a working wiring is itself a regression."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "runtime"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from discovery.verify import verify_config, _overlap  # noqa: E402

REPLY = "Our return policy allows returns within 30 days of purchase with a receipt."


def _ev(resp_body, ct="application/json", reply=REPLY, ws=None):
    return {"prompt_sent": "What is your return policy?", "reply_text": reply, "ws_messages": ws or [],
            "pairs": [{"request": {"method": "POST", "url": "https://t/api/chat", "headers": [], "raw_body": '{"message":"What is your return policy?"}'},
                       "response": {"status": 200, "headers": [], "raw_body": resp_body, "content_type": ct}}]}


def test_direct_api_right_field_passes_and_wrong_field_is_named():
    body = json.dumps({"status": "Thinking about your question", "reply": REPLY, "id": "c1"})
    good = verify_config({"adapter": "direct_api", "response_path": "reply"}, _ev(body))
    assert good["ok"] and good["checked"] and good["reason"] == "reads_the_reply"
    bad = verify_config({"adapter": "direct_api", "response_path": "status"}, _ev(body))
    assert not bad["ok"] and bad["reason"] == "wrong_field" and bad["field"] == "status" and "ascend_adapter_patch" in bad["next"]
    empty = verify_config({"adapter": "direct_api", "response_path": "nope.deep"}, _ev(body))
    assert not empty["ok"] and empty["reason"] == "empty_field"


def test_fail_open_when_it_cannot_judge():
    body = json.dumps({"reply": REPLY})
    assert verify_config({"adapter": "direct_api", "response_path": "reply"}, _ev(body, reply=""))["ok"]
    assert verify_config({"adapter": "direct_api", "response_path": "reply"}, _ev(body, reply=""))["checked"] is False
    assert verify_config({"adapter": "direct_api"}, _ev(body))["reason"] == "unpathed_text"
    assert verify_config({"adapter": "custom_module", "response_path": "x"}, _ev(body))["reason"] == "adapter_not_modelled"
    assert verify_config({"adapter": "direct_api", "response_path": "reply"}, {"pairs": [], "reply_text": REPLY})["ok"]


def test_sse_text_path_is_checked_against_the_recorded_stream():
    stream = ('data: {"type":"status","content":"Looking that up"}\n\n'
              'data: {"type":"token","content":"Our return policy allows returns "}\n\n'
              'data: {"type":"token","content":"within 30 days of purchase with a receipt."}\n\n'
              'data: {"type":"done"}\n\n')
    good = verify_config({"adapter": "sse_stream", "stream": {"format": "sse", "text_path": "content", "token_types": ["token"]}},
                         _ev(stream, ct="text/event-stream"))
    assert good["ok"] and good["checked"]
    bad = verify_config({"adapter": "sse_stream", "stream": {"format": "sse", "text_path": "content", "token_types": ["status"]}},
                        _ev(stream, ct="text/event-stream"))
    assert not bad["ok"] and bad["reason"] in ("wrong_field", "empty_field")   # status frames are ignored by default, so the field reads nothing


def test_websocket_reply_field_is_checked_against_received_frames():
    ws = [{"url": "wss://gw/demo", "sent": ['{"text":"What is your return policy?"}'],
           "received": ['{"type":"status","note":"working"}',
                        '{"type":"token","text":"Our return policy allows returns "}',
                        '{"type":"token","text":"within 30 days of purchase with a receipt."}',
                        '{"type":"done"}']}]
    good = verify_config({"adapter": "websocket_direct", "response_path": "text"}, _ev("", ws=ws))
    assert good["ok"] and good["checked"]
    bad = verify_config({"adapter": "websocket_direct", "response_path": "note"}, _ev("", ws=ws))
    assert not bad["ok"] and bad["field"] == "note"


def test_overlap_is_share_of_the_reply_reproduced():
    assert _overlap(REPLY, REPLY) == 1.0
    assert _overlap("Looking that up", REPLY) < 0.2
    assert _overlap("", REPLY) == 0.0
    assert _overlap("anything", "") == 1.0
