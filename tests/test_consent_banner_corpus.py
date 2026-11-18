"""An eval corpus for the consent-banner false pass in the Salesforce Agentforce (SCRT2) adapter.

This is the shape none of the forge fixtures covered, and it is exactly where a systemic false pass
lived: a bot that answers the FIRST turn of every conversation with a fixed consent banner and only
answers for real from the second turn on. Wired without a warm-up, every probe scored the banner —
benign text — so an adversarial assessment came back clean having never seen a real response, with
nothing in the output to show it.

These tests drive the REAL adapter (`runtime.adapters.scrt2_direct.SCRT2DirectAdapter`) and the REAL
warm-up accessor (`runtime.adapters.base.warmup_text`) against an in-process fake of the three SCRT2
REST endpoints and the SSE replay stream. No network, no customer data — the fake's behaviour is the
SCRT2 protocol behaviour: the consent banner is the bot's reply to turn 1, real answers come
from turn 2, and each new SSE connection replays the whole conversation from the banner on.

Run: python3 -m pytest tests/test_consent_banner_corpus.py -q
"""
import asyncio
import json
import os
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from runtime.adapters import base                                    # noqa: E402
from runtime.adapters.scrt2_direct import SCRT2DirectAdapter          # noqa: E402

# The boilerplate first-turn reply. Fixed for every conversation — that is what makes it a false
# pass: two different probes, wired without a warm-up, both read this identical string.
CONSENT_BANNER = ("By accepting, you acknowledge that this chat may be monitored and recorded. "
                  "Hi, I'm the Acme assistant — how can I help you today?")


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


class FakeAgentforce:
    """The SCRT2 REST + SSE surface, modelled on the SCRT2 protocol.

    - `POST …/accessToken`            → a JWT
    - `POST …/conversation`           → 200 (the client picks the conversationId)
    - `POST …/conversation/{id}/message` → records a user turn
    - `GET  …/eventrouter/v1/sse`     → replays the current conversation: the consent banner as the
      bot's reply to turn 1, a real per-prompt answer for every turn after it.
    """

    def __init__(self):
        self.turns: dict[str, list[str]] = {}
        self.last_conv: str | None = None
        self.tokens_issued = 0

    def answer(self, text: str) -> str:
        # Deterministic and prompt-dependent, so two different questions get two different answers —
        # what the constant-reply guard keys on. On-topic, the way a real domain bot replies.
        return f"Sure — about {text.strip().rstrip('?')}: here is what Acme support can tell you."

    def _sender(self, role: str, text: str) -> bytes:
        payload = json.dumps({"abstractMessage": {"staticContent": {"formatType": "Text", "text": text}}})
        event = {"conversationEntry": {"sender": {"role": role}, "entryPayload": payload}}
        return f"event: CONVERSATION_MESSAGE\ndata: {json.dumps(event)}\n\n".encode()

    def _sse_stream(self) -> "_SSE":
        lines: list[bytes] = []
        turns = self.turns.get(self.last_conv or "", [])
        for i, text in enumerate(turns):
            lines.append(self._sender("EndUser", text))                # the user turn, which the adapter skips
            lines.append(self._sender("Agent", CONSENT_BANNER if i == 0 else self.answer(text)))
        # split into physical lines the way urllib iterates a response
        physical: list[bytes] = []
        for block in lines:
            physical.extend((ln + b"\n") for ln in block.rstrip(b"\n").split(b"\n"))
            physical.append(b"\n")
        return _SSE(physical)

    def urlopen(self, req, timeout=None, **kw):
        url = req.full_url if hasattr(req, "full_url") else str(req)
        data = getattr(req, "data", None)
        if url.endswith("/accessToken"):
            self.tokens_issued += 1
            return _Body(json.dumps({"accessToken": f"jwt-{self.tokens_issued}"}).encode())
        if url.endswith("/conversation"):
            conv = json.loads(data)["conversationId"]
            self.turns.setdefault(conv, [])
            self.last_conv = conv
            return _Body(b"{}")
        if "/conversation/" in url and url.endswith("/message"):
            conv = url.split("/conversation/")[1].rsplit("/message", 1)[0]
            self.turns.setdefault(conv, []).append(json.loads(data)["staticContent"]["text"])
            self.last_conv = conv
            return _Body(b"{}")
        if url.endswith("/eventrouter/v1/sse"):
            return self._sse_stream()
        raise urllib.error.HTTPError(url, 404, "not found", {}, None)


class _Body:
    """urlopen's context-manager + .read() contract for the REST calls."""
    def __init__(self, body: bytes):
        self._body = body
        self.status = 200
    def read(self, *a):
        return self._body
    def __enter__(self):
        return self
    def __exit__(self, *exc):
        return False


class _SSE:
    """An SSE response the adapter iterates line by line, as a real urllib response is iterated."""
    def __init__(self, lines: list[bytes]):
        self._lines = lines
    def __iter__(self):
        return iter(self._lines)
    def __enter__(self):
        return self
    def __exit__(self, *exc):
        return False


def _wire(fake: FakeAgentforce, monkeypatch) -> dict:
    monkeypatch.setattr(urllib.request, "urlopen", fake.urlopen)
    return {
        "adapter": "scrt2_direct",
        "scrt_base": "https://acme.my.salesforce-scrt.com",
        "org_id": "00D000000000ABC",
        "developer_name": "Acme_AgentForce",
        "widget_origin": "https://www.acme.example",
        "capabilities_ver": "260",
        "sse_timeout": 5,
    }


def _ask(cfg: dict, prompt: str) -> str:
    res = _run(SCRT2DirectAdapter().send_prompt(prompt, cfg))
    assert res.get("success"), res
    return str(res.get("response") or "")


def test_without_a_warmup_every_probe_scores_the_consent_banner(monkeypatch) -> None:
    """The false pass, reproduced: no warm-up, so both probes read the same banner. This is the
    input the two-question guard is there to catch — identical answers to different questions."""
    cfg = _wire(FakeAgentforce(), monkeypatch)
    a = _ask(cfg, "What is 2 + 2?")
    b = _ask(cfg, "What is the capital of France?")
    assert a == CONSENT_BANNER and b == CONSENT_BANNER
    assert a == b, "two different questions returned the same string — the guard must refuse this"


def test_a_warmup_clears_the_banner_and_two_questions_get_two_answers(monkeypatch) -> None:
    """The fix: a warm-up sends a throwaway turn, so the scored probe is answered from turn 2. The
    banner is gone and the answers vary — the wire is real."""
    cfg = {**_wire(FakeAgentforce(), monkeypatch), "warmup_message": "Hello"}
    a = _ask(cfg, "What is 2 + 2?")
    b = _ask(cfg, "What is the capital of France?")
    assert CONSENT_BANNER not in (a, b), f"banner leaked through the warm-up: {a!r}"
    assert a != b, "the warm-up cleared the banner but the answers did not vary"
    assert "2 + 2" in a and "capital of France" in b


def test_the_warmup_is_honoured_under_the_flag_key_not_only_the_adapter_key(monkeypatch) -> None:
    """The exact key-name bug behind the live false pass: `--warmup` writes `warmup`, the adapter
    reads `warmup_message`. The accessor now reads either, so a warm-up the flag set is not dropped."""
    assert base.warmup_text({"warmup": "Hello"}) == "Hello"
    assert base.warmup_text({"warmup_message": "Hi"}) == "Hi"
    assert base.warmup_text({"warmup_message": "native", "warmup": "flag"}) == "native"
    assert base.warmup_text({}) == ""
    # and end to end: a config carrying only the flag's key still clears the banner
    cfg = {**_wire(FakeAgentforce(), monkeypatch), "warmup": "Hello"}
    ans = _ask(cfg, "What is 2 + 2?")
    assert CONSENT_BANNER not in ans and "2 + 2" in ans
