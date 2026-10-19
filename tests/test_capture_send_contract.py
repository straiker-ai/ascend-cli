"""Offline contracts for one-shot submission and exact outbound prompt evidence."""
import asyncio
import json
import socket
import sys
from types import SimpleNamespace
from urllib.parse import urlencode

import pytest

from discovery import capture as cap


PROMPT = '  first "line" \\\nsecond\tline caf\u00e9 \U0001f680  '
URL = "https://chat.example.test/"
SEND = cap.SEND_BUTTONS[0]


class Events:
    def __init__(self):
        self.handlers = {}

    def on(self, event, handler):
        self.handlers.setdefault(event, []).append(handler)

    def emit(self, event, value):
        for handler in self.handlers.get(event, []):
            handler(value)


class Locator:
    def __init__(self, page, kind, selector, exists=True):
        self.page, self.kind, self.selector = page, kind, selector
        self.exists = exists
        self.first = self

    async def count(self):
        return int(self.exists)

    async def is_visible(self):
        return self.exists and not (self.kind == "button" and self.page.hidden)

    async def is_enabled(self):
        return not (self.kind == "button" and self.page.disabled)

    async def get_attribute(self, name):
        return {"id": self.selector if self.kind == "input" else None,
                "placeholder": "Chat message"}.get(name)

    async def click(self, **kwargs):
        if self.kind == "button":
            await self.page.submit(self.selector)

    async def fill(self, value):
        self.page.fills.append((self.selector, value))
        if self.page.fill_error and self.selector == "textarea":
            raise RuntimeError("input no longer available")
        if self.page.timing == "fill":
            self.page.traffic()

    async def press(self, key):
        assert key == "Enter"
        await self.page.submit("enter")

    async def inner_text(self, **kwargs):
        return ""


class Page(Events):
    def __init__(self, *, prompt=PROMPT, body=None, content_type="application/json",
                 transport="http", timing="submit", button=True, hidden=False,
                 disabled=False, action_error=False, fill_error=False,
                 delayed_response=False, no_response=False, in_frame=False):
        super().__init__()
        self.prompt = prompt
        self.body = json.dumps({"turn": [{"text": prompt}]}) if body is None else body
        self.content_type, self.transport, self.timing = content_type, transport, timing
        self.button, self.hidden, self.disabled = button, hidden, disabled
        self.action_error, self.fill_error = action_error, fill_error
        self.delayed_response, self.no_response = delayed_response, no_response
        self.actions, self.fills, self.requests, self.deferred = [], [], [], []
        self.url = URL
        self.ws = Events()
        self.ws.url = "wss://chat.example.test/socket"
        self.frames = [SimpleNamespace(url=URL + "widget", locator=self.widget_locator)] if in_frame else []
        self.in_frame = in_frame

    def widget_locator(self, selector):
        if selector in ("textarea", "input[type='text']"):
            return Locator(self, "input", selector)
        if selector in cap.SEND_BUTTONS:
            return Locator(self, "button", selector, self.button)
        return Locator(self, "other", selector, False)

    def locator(self, selector):
        if self.in_frame:
            return Locator(self, "other", selector, False)
        return self.widget_locator(selector)

    def traffic(self):
        if self.transport.startswith("ws"):
            self.ws.emit("framereceived" if self.transport == "ws-received" else "framesent", self.body)
            return
        request = SimpleNamespace(method="POST", url=URL + "turn", resource_type="fetch",
                                  headers={"content-type": self.content_type}, post_data=self.body)
        self.requests.append(request)
        self.emit("request", request)

        async def text():
            return '{"reply":"acknowledged"}'

        response = SimpleNamespace(request=request, status=200,
                                   headers={"content-type": "application/json"}, text=text)
        if self.delayed_response:
            self.deferred.append(response)
        elif not self.no_response:
            self.emit("response", response)

    async def goto(self, *args, **kwargs):
        self.emit("websocket", self.ws)
        if self.timing == "navigation":
            self.traffic()

    async def wait_for_timeout(self, ms):
        if self.timing == "manual" and ms == 2000:
            self.traffic()
        await asyncio.sleep(0)

    async def submit(self, mechanism):
        self.actions.append(mechanism)
        if self.timing == "submit":
            self.traffic()
        for response in self.deferred:
            self.emit("response", response)
        self.deferred.clear()
        if self.action_error:
            raise TimeoutError("submission outcome unknown")


class Browser:
    def __init__(self, page):
        self.page = page
        self.closed = self.context_closed = False
        self.new_context_calls = self.launches = self.attachments = 0
        self.context = SimpleNamespace(new_page=self.new_page, close=self.close_context)
        self.contexts = [self.context]

    async def new_page(self):
        return self.page

    async def new_context(self, **kwargs):
        self.new_context_calls += 1
        return self.context

    async def close_context(self):
        self.context_closed = True

    async def close(self):
        self.closed = True

    async def launch(self, **kwargs):
        self.launches += 1
        return self

    async def connect_over_cdp(self, endpoint):
        self.attachments += 1
        return self

    async def __aenter__(self):
        return SimpleNamespace(chromium=self)

    async def __aexit__(self, *args):
        pass


@pytest.fixture
def capture(monkeypatch, tmp_path):
    def no_network(*args, **kwargs):
        raise AssertionError("capture contracts must not open network connections")

    monkeypatch.setattr(socket.socket, "connect", no_network)
    monkeypatch.setattr(cap, "_durable_har_path", lambda url: str(tmp_path / "capture.har"))

    def run(*, manual=False, cdp=None, har_only=False, **kwargs):
        page = Page(**kwargs)
        browser = Browser(page)
        monkeypatch.setitem(sys.modules, "playwright.async_api",
                            SimpleNamespace(async_playwright=lambda: browser))
        if har_only:
            monkeypatch.setattr(cap, "_augment_pairs_from_har", lambda pairs, *_: pairs.append({
                "request": {"raw_body": json.dumps({"message": page.prompt})}}))
        evidence = asyncio.run(cap._capture_async(
            URL, prompt=page.prompt, headless=True, timeout_s=1, settle_s=0,
            manual=manual, manual_wait_s=2, cdp=cdp))
        return evidence, page, browser

    return run


def test_visible_send_is_the_only_action(capture):
    ev, page, _ = capture(prompt="one turn")
    assert page.actions == [SEND]
    assert len(page.requests) == 1
    assert ev["browser_recipe"]["send"] == SEND
    assert ev["send_attempted"] and ev["send_verified"]


@pytest.mark.parametrize("options", [{"button": False}, {"hidden": True}, {"disabled": True}])
def test_enter_only_when_no_usable_button(capture, options):
    ev, page, _ = capture(prompt="one turn", **options)
    assert page.actions == ["enter"]
    assert ev["browser_recipe"]["send"] == "enter"
    assert ev["send_verified"]


@pytest.mark.parametrize("button", [True, False])
@pytest.mark.parametrize("timing", ["submit", "never"])
def test_uncertain_submission_never_retries_action_or_candidate(capture, button, timing):
    ev, page, _ = capture(prompt="one turn", button=button, action_error=True, timing=timing)
    assert page.actions == [SEND if button else "enter"]
    assert len(page.fills) == 1
    assert ev["send_attempted"] is True
    assert ev["send_verified"] is (timing == "submit")
    assert any("uncertain" in note.lower() for note in ev["notes"])


def test_no_traffic_does_not_trigger_a_second_submission(capture):
    ev, page, _ = capture(timing="never")
    assert page.actions == [SEND]
    assert len(page.fills) == 1
    assert ev["send_attempted"] and not ev["send_verified"]
    assert ev["prompt_sent"] is None


def test_pre_submission_fill_failure_can_try_another_input(capture):
    ev, page, _ = capture(prompt="one turn", fill_error=True)
    assert len(page.fills) == 2
    assert page.actions == [SEND]
    assert ev["send_verified"]


def test_send_button_is_selected_in_the_input_frame(capture):
    ev, page, _ = capture(prompt="one turn", in_frame=True)
    assert page.actions == [SEND]
    assert ev["browser_recipe"]["input_frame_url"] == URL + "widget"
    assert "input_fr" not in ev["browser_recipe"]


@pytest.mark.parametrize("transport,body,content_type", [
    ("http", json.dumps({"nested": [{"message": PROMPT}]}), "application/json"),
    ("http", json.dumps({"message": PROMPT}, ensure_ascii=False), "application/problem+json"),
    ("http", urlencode([("other", "ignored"), ("message", PROMPT)]),
     "application/x-www-form-urlencoded; charset=UTF-8"),
    ("http", PROMPT, "text/plain"),
    ("ws", json.dumps(["message", {"text": PROMPT}]), ""),
    ("ws", PROMPT, ""),
    ("ws", PROMPT.encode("utf-8"), ""),
    ("ws", {"payload": json.dumps({"text": PROMPT})}, ""),
])
def test_exact_values_preserve_escaping_whitespace_and_unicode(capture, transport, body, content_type):
    ev, page, _ = capture(transport=transport, body=body, content_type=content_type)
    assert ev["send_verified"] is True
    assert ev["prompt_sent"] == PROMPT
    assert page.fills[0][1] == PROMPT


@pytest.mark.parametrize("transport,body,content_type,prompt", [
    ("http", '{"text":"prefix hello suffix"}', "application/json", "hello"),
    ("http", '{"hello":"other"}', "application/json", "hello"),
    ("http", '{"text":"hello"}', "application/json", "  hello  "),
    ("http", "prefix hello suffix", "text/plain", "hello"),
    ("http", "message=prefix+hello+suffix", "application/x-www-form-urlencoded", "hello"),
    ("http", "hello=other", "application/x-www-form-urlencoded", "hello"),
    ("http", '{"text":"hello"', "application/json", "hello"),
    ("http", '{"text":123}', "application/json", "123"),
    ("http", '{"text":"caf\\u00e9"}', "application/json", "cafe\u0301"),
    ("ws", '{"text":"prefix hello suffix"}', "", "hello"),
    ("ws", "prefix hello suffix", "", "hello"),
    ("ws-received", '{"text":"hello"}', "", "hello"),
    ("http", '{"text":"anything"}', "application/json", ""),
])
def test_nonexact_or_inbound_values_are_not_send_proof(capture, transport, body, content_type, prompt):
    ev, _, _ = capture(transport=transport, body=body, content_type=content_type, prompt=prompt)
    assert ev["send_verified"] is False
    assert ev["prompt_sent"] is None


@pytest.mark.parametrize("prompt", [" \t\n ", "x" * 5000 + "\n\u00e9"], ids=["whitespace", "long"])
@pytest.mark.parametrize("transport", ["http", "ws"])
def test_whitespace_only_and_long_exact_prompts(capture, prompt, transport):
    ev, _, _ = capture(prompt=prompt, transport=transport)
    assert ev["send_verified"] is True
    assert ev["prompt_sent"] == prompt


@pytest.mark.parametrize("transport", ["http", "ws"])
@pytest.mark.parametrize("timing", ["navigation", "fill"])
def test_pre_action_traffic_is_not_proof(capture, transport, timing):
    ev, page, _ = capture(prompt="one turn", transport=transport, timing=timing)
    assert ev["send_attempted"] is True
    assert ev["send_verified"] is False
    assert ev["prompt_sent"] is None


def test_response_after_action_cannot_verify_an_earlier_request(capture):
    ev, _, _ = capture(prompt="one turn", timing="navigation", delayed_response=True)
    assert ev["pairs"]
    assert ev["send_verified"] is False


def test_har_augmentation_is_not_submission_proof(capture):
    ev, _, _ = capture(prompt="one turn", timing="never", har_only=True)
    assert ev["pairs"]
    assert ev["send_verified"] is False


def test_outbound_request_does_not_need_a_completed_response(capture):
    ev, _, _ = capture(no_response=True)
    assert ev["send_verified"] is True
    assert ev["pairs"] == []


@pytest.mark.parametrize("cdp", [None, "http://127.0.0.1:9222"])
@pytest.mark.parametrize("manual", [False, True])
def test_context_ownership_and_manual_no_automation(capture, cdp, manual):
    ev, page, browser = capture(cdp=cdp, manual=manual, timing="manual" if manual else "submit")
    assert ev["send_verified"] is True
    if manual:
        assert page.actions == [] and page.fills == []
    assert browser.closed is (cdp is None)
    assert browser.context_closed is (cdp is None)
    assert browser.new_context_calls == (0 if cdp else 1)
    assert browser.launches == (0 if cdp else 1)
    assert browser.attachments == (1 if cdp else 0)


@pytest.mark.parametrize("transport", ["http", "ws"])
def test_manual_capture_rejects_pre_window_traffic(capture, transport):
    ev, page, _ = capture(prompt="one turn", manual=True, transport=transport, timing="navigation")
    assert page.actions == []
    assert ev["send_verified"] is False


@pytest.mark.parametrize("transport", ["http", "ws"])
def test_manual_capture_requires_an_exact_value(capture, transport):
    ev, _, _ = capture(prompt="hello", manual=True, transport=transport, timing="manual",
                       body='{"text":"prefix hello suffix"}')
    assert ev["send_verified"] is False


def test_json_body_with_plain_text_content_type(capture):
    ev, _, _ = capture(content_type="text/plain; charset=UTF-8")
    assert ev["send_verified"] is True


@pytest.mark.parametrize("prompt", ["123", "true", '{"literal":"text"}'])
@pytest.mark.parametrize("transport", ["http", "ws"])
def test_complete_plain_text_payload_can_look_like_json(capture, prompt, transport):
    ev, _, _ = capture(prompt=prompt, body=prompt, transport=transport, content_type="text/plain")
    assert ev["send_verified"] is True


def test_declared_json_matches_values_not_the_serialized_document(capture):
    body = '{"literal":"text"}'
    ev, _, _ = capture(prompt=body, body=body)
    assert ev["send_verified"] is False


@pytest.mark.parametrize("value,disposition,expected", [
    (PROMPT, 'name="message"', True),
    ("prefix " + PROMPT + " suffix", 'name="message"', False),
    (PROMPT.strip(), 'name="message"', False),
    (PROMPT, 'name="upload"; filename="message.txt"', False),
])
def test_multipart_matches_exact_text_fields_only(capture, value, disposition, expected):
    body = (f'--boundary\r\nContent-Disposition: form-data; {disposition}\r\n'
            f'Content-Type: text/plain; charset=UTF-8\r\n\r\n{value}\r\n--boundary--\r\n')
    ev, _, _ = capture(body=body, content_type="multipart/form-data; boundary=boundary")
    assert ev["send_verified"] is expected


def test_multipart_field_name_is_not_a_message(capture):
    body = ('--boundary\r\nContent-Disposition: form-data; name="hello"\r\n\r\n'
            'different\r\n--boundary--\r\n')
    ev, _, _ = capture(prompt="hello", body=body, content_type="multipart/form-data; boundary=boundary")
    assert ev["send_verified"] is False


@pytest.mark.parametrize("transport", ["http", "ws"])
def test_invalid_utf8_is_not_replaced_to_make_a_match(capture, transport):
    ev, _, _ = capture(prompt="\ufffd", body=b"\xff", transport=transport, content_type="text/plain")
    assert ev["send_verified"] is False
