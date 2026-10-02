"""dialogflow_cx — detectIntent per prompt with its own session, fulfilment text joined, auth named."""
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "runtime"))
sys.path.insert(0, str(REPO / "tests"))

from adapters.dialogflow_cx import DialogflowCXAdapter, detect_intent_url, extract_text  # noqa: E402
from conftest import FakeResponse, install_fake_requests, run_async as run  # noqa: E402

AGENT = "https://us-central1-dialogflow.googleapis.com/v3/projects/p1/locations/us-central1/agents/a1"
REPLY = {"queryResult": {"responseMessages": [{"text": {"text": ["Your order shipped.", "Anything else?"]}}],
                         "intent": {"displayName": "order.status"}, "currentPage": {"displayName": "Start"}}}


def test_the_session_is_appended_or_replaced():
    assert detect_intent_url(AGENT, "s1") == AGENT + "/sessions/s1:detectIntent"
    assert detect_intent_url(AGENT + "/sessions/old:detectIntent", "s2") == AGENT + "/sessions/s2:detectIntent"


def test_fulfilment_text_is_joined():
    assert extract_text(REPLY) == "Your order shipped.\nAnything else?"
    assert extract_text({"queryResult": {"responseMessages": [{"payload": {"text": "from payload"}}]}}) == "from payload"
    assert extract_text({}) == ""


def test_each_prompt_gets_its_own_session_and_the_bearer_from_the_auth_block(monkeypatch):
    seen = []

    def handler(method, url, kw):
        seen.append(url)
        assert kw["json"] == {"queryInput": {"text": {"text": "hi"}, "languageCode": "en"}}
        assert kw["headers"]["Authorization"] == "Bearer tok"
        return FakeResponse(200, json_data=REPLY)
    install_fake_requests(monkeypatch, handler)
    ad = DialogflowCXAdapter()
    cfg = {"endpoint": AGENT, "headers": {"Authorization": "Bearer tok"}}
    r1 = run(ad.send_prompt("hi", cfg)); r2 = run(ad.send_prompt("hi", cfg))
    assert r1["success"] and r1["response"].startswith("Your order shipped.") and r1["metadata"]["intent"] == "order.status"
    assert seen[0] != seen[1] and all(":detectIntent" in u for u in seen)
    fixed = run(ad.send_prompt("hi", {**cfg, "session_id": "pinned"}))
    assert fixed["metadata"]["session_id"] == "pinned" and seen[-1].endswith("/sessions/pinned:detectIntent")


def test_without_any_credential_the_failure_says_what_to_set(monkeypatch):
    install_fake_requests(monkeypatch, lambda m, u, k: FakeResponse(200, json_data=REPLY))
    ad = DialogflowCXAdapter()
    monkeypatch.setattr(ad, "_google_token", lambda config: None)
    r = run(ad.send_prompt("hi", {"endpoint": AGENT}))
    assert not r["success"] and "--bearer" in r["error"]


def test_http_errors_carry_the_api_message(monkeypatch):
    install_fake_requests(monkeypatch, lambda m, u, k: FakeResponse(403, json_data={"error": {"message": "Permission denied on agent"}}))
    r = run(DialogflowCXAdapter().send_prompt("hi", {"endpoint": AGENT, "headers": {"Authorization": "Bearer t"}}))
    assert not r["success"] and "403" in r["error"] and "Permission denied" in r["error"]
