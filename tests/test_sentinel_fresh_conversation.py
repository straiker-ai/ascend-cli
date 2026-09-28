"""
test_sentinel_fresh_conversation.py — a create-then-send target re-mints the conversation per probe.

MEASURED on a live Sierra-hosted support bot. `conversation_key` defaults to None, so the router
hands every probe the SAME adapter instance and `self._conv` stuck to one conversationID. After a
few turns the bot returned "I'm ending the conversation" and every later probe scored that refusal
instead of a real answer — because Ascend scores each probe INDEPENDENTLY, but they were all landing
in one accumulating conversation.

The fix: for a create-then-send target the adapter re-mints the conversation (a fresh conversationID
and its per-conversation encryptionKey) via the start call on EVERY probe, unless
`session_per_probe: false` opts into sticky reuse for a genuinely multi-turn target.

This drives the real adapter with a faked transport and counts create calls. Revert the per-probe
reset in `sentinel_stream.send_prompt` and the first test goes red (one create instead of two).

Run:  python3 -B tests/test_sentinel_fresh_conversation.py
"""
import asyncio
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
if str(REPO / "runtime") not in sys.path:
    sys.path.insert(0, str(REPO / "runtime"))
from adapters import sentinel_stream as SS  # noqa: E402

FAILURES = []


def check(name, cond, detail=""):
    print(f"  {'ok  ' if cond else 'FAIL'}  {name}{'' if cond else '  ' + str(detail)}")
    if not cond:
        FAILURES.append(f"{name}: {detail}")


class _Resp:
    def __init__(self, status, text, jsonobj=None):
        self.status_code = status
        self.text = text
        self.content = text.encode()
        self._json = jsonobj
        self.headers = {"content-type": "application/json" if jsonobj is not None else "text/plain"}
        self.encoding = None

    def raise_for_status(self):
        if self.status_code >= 400:
            raise SS.requests.RequestException(f"HTTP {self.status_code}")

    def json(self):
        if self._json is None:
            raise ValueError("no json")
        return self._json


def _config(**over):
    cfg = {
        "url": "https://x/-/api/chat",
        "adapter": "sentinel_stream",
        "begin_marker": "BEGIN", "end_marker": "END",
        "start": {"url": "https://x/-/api/graphql", "method": "POST", "response": "json",
                  "conv_path": "conversationID", "key_path": "encryptionKey",
                  "body": {"op": "create"}},
        "message": {"body": {"conversationID": "{{CONV}}", "encryptionKey": "{{KEY}}",
                             "clientEvent": {"type": "message", "message": {"content": "{{PROMPT}}"}}}},
    }
    cfg.update(over)
    return cfg


def _drive(session_per_probe=None):
    counter = {"create": 0, "message": 0, "convs": []}

    def fake_request(method, url, **kw):
        if "graphql" in url:
            counter["create"] += 1
            n = counter["create"]
            return _Resp(200, "", {"conversationID": f"conv-{n}", "encryptionKey": f"key-{n}"})
        counter["message"] += 1
        body = kw.get("json") or {}
        counter["convs"].append(body.get("conversationID"))
        frame = "BEGIN" + json.dumps(
            {"state": {"events": [{"author": "assistant", "message": {"text": f"answer {counter['message']}"}}]}}
        ) + "END"
        return _Resp(200, frame)

    orig = SS.requests.request
    SS.requests.request = fake_request
    try:
        cfg = _config()
        if session_per_probe is not None:
            cfg["session_per_probe"] = session_per_probe
        ad = SS.SentinelStreamAdapter()

        async def go():
            await ad.send_prompt("first question", cfg)
            await ad.send_prompt("second question", cfg)
        asyncio.run(go())
    finally:
        SS.requests.request = orig
    return counter


def test_default_re_mints_a_fresh_conversation_per_probe():
    c = _drive()  # default: session_per_probe True
    check("two probes → two create calls (fresh conversation each)", c["create"] == 2, c)
    check("both probes were answered", c["message"] == 2, c)
    check("each probe used a DIFFERENT conversationID",
          len(set(c["convs"])) == 2 and None not in c["convs"], c["convs"])


def test_opt_out_reuses_one_sticky_conversation():
    c = _drive(session_per_probe=False)
    check("session_per_probe:false → one create, reused across probes", c["create"] == 1, c)
    check("both probes still answered on the sticky conversation", c["message"] == 2, c)
    check("both probes used the SAME conversationID", len(set(c["convs"])) == 1, c["convs"])


def main():
    print("a create-then-send target re-mints its conversation per probe")
    test_default_re_mints_a_fresh_conversation_per_probe()
    print("\nand holds one conversation only when explicitly opted out")
    test_opt_out_reuses_one_sticky_conversation()
    print()
    if FAILURES:
        print(f"{len(FAILURES)} failure(s)")
        return 1
    print("no probe accumulates in a conversation the bot would end")
    return 0


if __name__ == "__main__":
    sys.exit(main())
