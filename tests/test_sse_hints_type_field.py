"""SSE hints are read from a `type` field when the stream has no named events."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "runtime"))

from discovery.classify import _sse_stream_hints  # noqa: E402

TYPED = ('data: {"type":"status","content":"thinking"}\n\n'
         'data: {"type":"token","content":"Our return policy "}\n\n'
         'data: {"type":"token","content":"allows 30 days."}\n\n'
         'data: {"type":"done"}\n\n')
NAMED = ('event: status\ndata: {"message": "Analyzing"}\n\n'
         'event: response\ndata: {"text": "the actual answer, quite long"}\n\n'
         'event: end\ndata: {}\n\n')


def test_type_field_gives_token_types_and_the_terminal_frame():
    h = _sse_stream_hints(TYPED)
    assert h == {"format": "sse", "text_path": "content", "token_types": ["token"], "done_when": {"path": "type", "equals": "done"}}


def test_named_events_keep_their_own_rule():
    h = _sse_stream_hints(NAMED)
    assert h["token_types"] == ["response"] and h["done_when"] == {"event": "end"} and h["text_path"] == "text"


def test_untyped_frames_still_get_only_the_text_path():
    h = _sse_stream_hints('data: {"content":"a"}\n\ndata: {"content":"bb"}\n\n')
    assert h == {"format": "sse", "text_path": "content"}
