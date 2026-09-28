"""
test_sierra_create_then_send.py — a create-then-send chat that GREETS derives from the SCORED turn.

MEASURED on a live Sierra-hosted support bot (`sierra.chat`). The capture is a create-then-send
conversation: a create call mints `conversationID`+`encryptionKey`, then a `resume-session` INIT
turn (empty message) precedes the real `type:"message"` turn that carries what the operator typed.

The derivation used to build the probe body from the FIRST id-using turn — the `resume-session`
init — so the config froze `clientEvent.type:"resume-session"`, left `userMessageText` empty, and
mismapped `{{PROMPT}}` into `memory.variables.VisitorID` (a tracking id). Every probe was then an
empty session-resume, so the target returned its verbatim greeting to all of them and validation
died on `constant_response`. `_pick_chat_index` already identifies the RIGHT turn (the one carrying
`prompt_sent`); the fix sources the probe body from THAT turn, so `{{PROMPT}}` lands in the real
message field and `clientEvent.type` is `message`.

This is a synthetic fixture in the same shape (no real credentials, no captured traffic). Revert
`message_body = _body_template(msg_req)` back to `_body_template(later)` in `classify_session` and
the first two assertions go red.

Run:  python3 -B tests/test_sierra_create_then_send.py   (or pytest tests/test_sierra_create_then_send.py)
"""
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
for p in ("shells/cli", "runtime", "control"):
    if str(REPO / p) not in sys.path:
        sys.path.insert(0, str(REPO / p))
from discovery import classify as C  # noqa: E402

BEGIN, END = "BOT_CHAT_EVENT_BEGIN", "BOT_CHAT_EVENT_END"
PROMPT = "what are your customer support hours"
HOST = "https://sierra.example"


def _framed(text: str) -> str:
    return f'{BEGIN}{json.dumps({"role": "assistant", "text": text})}{END}'


def _pair(url, body, resp_raw, resp_json=None, ct="text/plain"):
    return {
        "request": {"method": "POST", "url": url, "raw_body": json.dumps(body) if body is not None else ""},
        "response": {"status": 200, "headers": {"content-type": ct},
                     "raw_body": resp_raw, "content_type": ct,
                     **({"json": resp_json} if resp_json is not None else {})},
    }


def _evidence():
    # 0: create the conversation (JSON create response mints the id + key)
    create = _pair(f"{HOST}/-/api/graphql", {"op": "embedChatExtractConversationState"},
                   json.dumps({"conversationID": "CONV-1", "encryptionKey": "KEY-1"}),
                   resp_json={"conversationID": "CONV-1", "encryptionKey": "KEY-1"},
                   ct="application/json")
    # 1: a resume-session INIT turn — carries the id, NO real message (this is the wrong turn to
    #    template from, and the bug used it)
    resume = _pair(f"{HOST}/-/api/chat",
                   {"conversationID": "CONV-1", "encryptionKey": "KEY-1",
                    "clientEvent": {"type": "resume-session", "idempotencyKey": "idem-a"},
                    "userMessageText": "", "memory": {"variables": {"VisitorID": "VIS-9"}}},
                   _framed("I'm happy to help. What do you need?"))
    # 2: the real message turn — the SCORED prompt lives here (userMessageText + clientEvent.message.content)
    message = _pair(f"{HOST}/-/api/chat",
                    {"conversationID": "CONV-1", "encryptionKey": "KEY-1",
                     "clientEvent": {"type": "message", "message": {"content": PROMPT}, "idempotencyKey": "idem-b"},
                     "userMessageText": PROMPT, "memory": {"variables": {"VisitorID": "VIS-9"}}},
                    _framed("Our support hours are 7 AM to 9 PM CT."))
    return {"pairs": [create, resume, message], "ws_messages": [], "prompt_sent": PROMPT}


def _derive():
    return C.classify_evidence(_evidence())


def _prompt_paths(body):
    out = []
    def walk(o, p=""):
        if isinstance(o, dict):
            for k, v in o.items():
                walk(v, f"{p}.{k}")
        elif isinstance(o, list):
            for i, v in enumerate(o):
                walk(v, f"{p}[{i}]")
        elif isinstance(o, str) and "{{PROMPT}}" in o:
            out.append(p)
    walk(body)
    return out


def test_the_probe_is_a_message_turn_not_a_session_resume():
    cfg = _derive()["config"]
    body = cfg["message"]["body"]
    ce = body.get("clientEvent") or {}
    assert cfg["adapter"] == "sentinel_stream", cfg.get("adapter")
    assert ce.get("type") == "message", (
        f"probe templated from the resume-session init, not the scored turn: type={ce.get('type')!r}")


def test_prompt_lands_in_the_message_field_not_a_tracking_id():
    body = _derive()["config"]["message"]["body"]
    paths = _prompt_paths(body)
    assert any("message.content" in p or p.endswith(".userMessageText") for p in paths), (
        f"{{{{PROMPT}}}} is not in the message field: {paths}")
    assert not any("VisitorID" in p for p in paths), (
        f"{{{{PROMPT}}}} mismapped into a tracking id: {paths}")


def test_the_session_id_and_key_are_templated_not_frozen():
    body = _derive()["config"]["message"]["body"]
    dumped = json.dumps(body)
    assert "CONV-1" not in dumped, "the captured conversationID was frozen into the probe body"
    assert "KEY-1" not in dumped, "the captured encryptionKey was frozen into the probe body"


def test_a_plain_single_shot_target_is_unaffected():
    # A stateless target with no create call keeps its ordinary shape — the change is scoped to
    # the create-then-send path.
    one = _pair(f"{HOST}/api/chat", {"message": PROMPT}, json.dumps({"reply": "9 to 5"}),
                resp_json={"reply": "9 to 5"}, ct="application/json")
    cfg = C.classify_evidence({"pairs": [one], "ws_messages": [], "prompt_sent": PROMPT})["config"]
    assert cfg.get("adapter") != "sentinel_stream" or "start" not in cfg, (
        "a single-shot target was given a create-then-send shape")


def main() -> int:
    failures = []
    for t in (test_the_probe_is_a_message_turn_not_a_session_resume,
              test_prompt_lands_in_the_message_field_not_a_tracking_id,
              test_the_session_id_and_key_are_templated_not_frozen,
              test_a_plain_single_shot_target_is_unaffected):
        try:
            t()
            print(f"  ok    {t.__name__}")
        except AssertionError as e:
            failures.append(f"{t.__name__}: {e}")
            print(f"  FAIL  {t.__name__}  {e}")
    if failures:
        print(f"\n{len(failures)} failure(s)")
        return 1
    print("\nthe scored turn is the probe; the greeting is not")
    return 0


if __name__ == "__main__":
    sys.exit(main())
