"""A credential header whose value came back from an earlier call in the session is MINTED per
conversation: the derived config re-mints it before every probe instead of freezing the captured one."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / "runtime"))
from runtime.discovery import classify as C  # noqa: E402

TOKEN = "ct_7Q1dP9rM4xL2kZ8vN3wB6yT0"
COOKIE = "lab_access=code-9f13"


def _pairs():
    create = {"request": {"method": "POST", "url": "https://lab.example.test/session/api/conversations",
                          "headers": {"content-type": "application/json", "cookie": COOKIE, "origin": "https://lab.example.test"},
                          "json": None, "raw_body": ""},
              "response": {"status": 200, "headers": {"content-type": "application/json"},
                           "json": {"conversation_id": "conv-1", "token": TOKEN}, "raw_body": "", "content_type": "application/json"}}
    chat = {"request": {"method": "POST", "url": "https://lab.example.test/session/api/messages",
                        "headers": {"content-type": "application/json", "cookie": COOKIE, "x-conv-token": TOKEN},
                        "json": {"message": "hello"}, "raw_body": '{"message": "hello"}'},
            "response": {"status": 200, "headers": {"content-type": "application/json"},
                         "json": {"reply": "Hi, I am Ava."}, "raw_body": "", "content_type": "application/json"}}
    return [create, chat]


def test_the_minted_header_is_found_and_the_static_one_is_not():
    out = C.minted_credentials({"X-Conv-Token": TOKEN, "Cookie": COOKIE}, _pairs(), None)
    assert out == {"X-Conv-Token": {"pair": 0, "path": "token"}}


def test_the_auth_block_reminting_per_probe_and_carrying_the_static_credential():
    minted = C.minted_credentials({"X-Conv-Token": TOKEN, "Cookie": COOKIE}, _pairs(), None)
    block = C._minted_auth_block(minted, _pairs(), {"Cookie": "env:LAB_COOKIE"})
    assert block["type"] == "derived_multihop"
    step = block["steps"][0]
    assert step["url"].endswith("/session/api/conversations") and step["method"] == "POST" and "json" not in step
    assert step["headers"]["Cookie"] == "env:LAB_COOKIE"                      # the static one rides on the mint call
    assert step["extract"] == [{"var": "MINTED_0", "path": "token"}]
    assert block["attach"]["headers"] == {"X-Conv-Token": "{{MINTED_0}}", "Cookie": "env:LAB_COOKIE"}


def test_a_value_that_only_ever_appears_in_requests_is_static():
    pairs = _pairs()
    pairs[0]["response"]["json"] = {"ok": True}          # nothing minted the token
    assert C.minted_credentials({"X-Conv-Token": TOKEN}, pairs, None) == {}


def test_json_path_finds_nested_values():
    assert C._json_path_to_value({"data": {"session": {"token": "abcdefgh"}}}, "abcdefgh") == "data.session.token"
    assert C._json_path_to_value({"items": [{"id": "x"}, {"id": "abcdefgh"}]}, "abcdefgh") == "items.1.id"
    assert C._json_path_to_value({"a": 1}, "abcdefgh") is None


def test_compose_keeps_the_per_probe_lifecycle_for_a_minted_credential():
    pairs = _pairs()
    for pr in pairs:                       # the evidence normaliser adds these on a real capture
        pr["request"].setdefault("query", {}); pr.setdefault("started_ms", 0)
    classified = C.classify_evidence({"pairs": pairs, "url": "https://lab.example.test/session"})
    cfg = classified["config"]
    assert cfg.get("auth", {}).get("type") == "derived_multihop", cfg.get("auth")
    assert cfg.get("auth_lifecycle") == {"type": "refresh_on_ttl", "ttl_s": 0}
    assert cfg["_minted_credentials"]["X-Conv-Token"]["path"] == "token"


def test_a_third_party_challenge_token_is_not_a_minter():
    # a bot-challenge flow: the browser POSTs to the WAF's host and gets a token back, then sends it
    # as a cookie to the widget — that token is a challenge answer, not a conversation credential
    waf = {"request": {"method": "POST", "url": "https://abc.token.awswaf.example/abc/challenge",
                       "headers": {"content-type": "application/json"}, "json": {"solution": "x"}, "raw_body": ""},
           "response": {"status": 200, "headers": {"content-type": "application/json"},
                        "json": {"token": "waf-token-0123456789"}, "raw_body": "", "content_type": "application/json"}}
    chat = _pairs()[1]
    chat["request"]["headers"] = {"content-type": "application/json", "cookie": "aws-waf-token=waf-token-0123456789"}
    assert C.minted_credentials({"Cookie": "aws-waf-token=waf-token-0123456789"}, [waf, chat], None,
                                chat_url="https://lab.example.test/rest/api/chat") == {}


def test_same_domain_minter_still_counts_with_the_chat_url_given():
    out = C.minted_credentials({"X-Conv-Token": TOKEN, "Cookie": COOKIE}, _pairs(), None,
                               chat_url="https://lab.example.test/session/api/messages")
    assert out == {"X-Conv-Token": {"pair": 0, "path": "token"}}


def _norm(pairs):
    for pr in pairs:
        pr["request"].setdefault("query", {}); pr.setdefault("started_ms", 0)
    return pairs


def test_classify_auth_ignores_a_third_party_challenge_origin_for_a_reused_cookie():
    waf = {"request": {"method": "POST", "url": "https://abc.token.awswaf.example/abc/challenge",
                       "headers": {"content-type": "application/json"}, "json": {"solution": "x"}, "raw_body": ""},
           "response": {"status": 200, "headers": {"content-type": "application/json"},
                        "json": {"token": "waf-token-0123456789abcdef"}, "raw_body": "", "content_type": "application/json"}}
    chat = {"request": {"method": "POST", "url": "https://lab.example.test/rest/api/chat",
                        "headers": {"content-type": "application/json", "cookie": "aws-waf-token=waf-token-0123456789abcdef; lab_access=code"},
                        "json": {"message": "hello"}, "raw_body": '{"message": "hello"}'},
            "response": {"status": 200, "headers": {"content-type": "application/json"},
                         "json": {"reply": "Hi"}, "raw_body": "", "content_type": "application/json"}}
    auth = C.classify_auth({"pairs": _norm([waf, chat])}, 1)
    assert auth["value"] == "static", auth        # a challenge token is not a login the adapter can redo


def test_classify_auth_still_derives_a_same_domain_login_cookie():
    login = {"request": {"method": "POST", "url": "https://lab.example.test/login",
                         "headers": {"content-type": "application/json"}, "json": {"user": "u"}, "raw_body": ""},
             "response": {"status": 200, "headers": {"content-type": "application/json"},
                          "json": {"session": "sess-0123456789abcdef"}, "raw_body": "", "content_type": "application/json"}}
    chat = {"request": {"method": "POST", "url": "https://lab.example.test/rest/api/chat",
                        "headers": {"content-type": "application/json", "cookie": "sid=sess-0123456789abcdef"},
                        "json": {"message": "hello"}, "raw_body": '{"message": "hello"}'},
            "response": {"status": 200, "headers": {"content-type": "application/json"},
                         "json": {"reply": "Hi"}, "raw_body": "", "content_type": "application/json"}}
    auth = C.classify_auth({"pairs": _norm([login, chat])}, 1)
    assert auth["value"] == "derived_multihop", auth
