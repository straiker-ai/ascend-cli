"""A streamed reply (text/event-stream, NDJSON) reaches the evidence.

MEASURED on the SSE lab widget: Playwright returns neither the body of a streamed response nor its
HAR text, so the pair was recorded with an empty body and the derived config was a bare
{"format": "sse"}. The page hook keeps the text; this folds it into the pair.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "runtime"))

from discovery import capture  # noqa: E402
from discovery.classify import _sse_stream_hints  # noqa: E402

SSE = 'data: {"type":"token","content":"Our return policy "}\n\ndata: {"type":"token","content":"allows 30 days."}\n\ndata: {"type":"done"}\n\n'


def _pair(url, ct, body=None, method="POST"):
    return {"request": {"method": method, "url": url, "headers": [], "raw_body": '{"message":"hi"}'},
            "response": {"status": 200, "headers": [], "raw_body": body, "content_type": ct}}


def test_an_empty_streamed_pair_gets_its_body_from_the_page_hook():
    pairs = [_pair("https://lab.example.test/sse/api/chat", "text/event-stream; charset=utf-8"),
             _pair("https://lab.example.test/rest/api/chat", "application/json", body='{"reply":"x"}')]
    notes = []
    n = capture._fill_streamed_bodies(pairs, [{"url": "https://lab.example.test/sse/api/chat", "method": "POST", "status": 200, "text": SSE}], notes)
    assert n == 1
    assert pairs[0]["response"]["raw_body"] == SSE
    assert pairs[1]["response"]["raw_body"] == '{"reply":"x"}'            # a JSON pair is never touched
    assert notes and "streamed reply" in notes[0]
    # and the derivation now has something to read
    hints = _sse_stream_hints(pairs[0]["response"]["raw_body"])
    assert hints["text_path"] == "content"


def test_a_recorded_body_is_never_overwritten_and_methods_must_match():
    pairs = [_pair("https://h/sse", "text/event-stream", body="data: kept\n\n"),
             _pair("https://h/sse2", "text/event-stream", method="GET")]
    n = capture._fill_streamed_bodies(pairs, [{"url": "https://h/sse", "method": "POST", "text": "data: new\n\n"},
                                              {"url": "https://h/sse2", "method": "POST", "text": "data: wrong method\n\n"}], [])
    assert n == 0
    assert pairs[0]["response"]["raw_body"] == "data: kept\n\n"
    assert pairs[1]["response"]["raw_body"] is None


def test_no_streams_is_a_no_op():
    pairs = [_pair("https://h/sse", "text/event-stream")]
    assert capture._fill_streamed_bodies(pairs, [], []) == 0


def test_the_hook_is_plain_javascript_that_tees_fetch_and_wraps_eventsource():
    js = capture.STREAM_HOOK_JS
    assert "window.__ascendStreams" in js and "tee()" in js and "EventSource" in js
    assert "event-stream" in js and "ndjson" in js
