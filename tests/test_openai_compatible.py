"""openai_compatible — one chat completion per prompt, model discovered when unset, errors named."""
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "runtime"))
sys.path.insert(0, str(REPO / "tests"))

from adapters.openai_compatible import OpenAICompatibleAdapter, chat_url, models_url, extract_text  # noqa: E402
from conftest import FakeResponse, install_fake_requests, run_async as run  # noqa: E402

COMPLETION = {"id": "chatcmpl-1", "choices": [{"index": 0, "finish_reason": "stop",
                                               "message": {"role": "assistant", "content": "Your order shipped yesterday."}}],
              "usage": {"prompt_tokens": 12, "completion_tokens": 7}}


def test_urls_are_normalised_and_the_query_is_kept():
    assert chat_url("https://gw.example.test") == "https://gw.example.test/v1/chat/completions"
    assert chat_url("https://gw.example.test/v1/") == "https://gw.example.test/v1/chat/completions"
    assert chat_url("https://r.openai.azure.com/openai/deployments/d1/chat/completions?api-version=2024-02-01") == \
        "https://r.openai.azure.com/openai/deployments/d1/chat/completions?api-version=2024-02-01"
    assert models_url("https://gw.example.test/v1/chat/completions?x=1") == "https://gw.example.test/v1/models?x=1"


def test_content_shapes():
    assert extract_text(COMPLETION) == "Your order shipped yesterday."
    parts = {"choices": [{"message": {"content": [{"type": "text", "text": "a "}, {"type": "text", "text": "b"}]}}]}
    assert extract_text(parts) == "a b"
    assert extract_text({"choices": [{"text": "legacy"}]}) == "legacy"
    assert extract_text({"choices": []}) == "" and extract_text("x") == ""


def test_a_prompt_becomes_one_completion_with_the_configured_model(monkeypatch):
    def handler(method, url, kw):
        assert method == "POST" and url.endswith("/v1/chat/completions")
        body = kw["json"]
        assert body["model"] == "gpt-4o-mini" and body["stream"] is False
        assert body["messages"] == [{"role": "system", "content": "You are Ava."}, {"role": "user", "content": "where is my order?"}]
        assert kw["headers"]["Authorization"] == "Bearer k-123"
        return FakeResponse(200, json_data=COMPLETION)
    rec = install_fake_requests(monkeypatch, handler)
    ad = OpenAICompatibleAdapter()
    r = run(ad.send_prompt("where is my order?", {"endpoint": "https://gw.example.test", "model": "gpt-4o-mini",
                                                   "system_prompt": "You are Ava.", "headers": {"Authorization": "Bearer k-123"}}))
    assert r["success"] and r["response"] == "Your order shipped yesterday."
    assert r["metadata"]["model"] == "gpt-4o-mini" and r["metadata"]["usage"]["completion_tokens"] == 7
    assert len(rec.calls) == 1


def test_without_a_model_the_server_is_asked_once(monkeypatch):
    def handler(method, url, kw):
        if method == "GET":
            assert url.endswith("/v1/models")
            return FakeResponse(200, json_data={"data": [{"id": "local-llm"}, {"id": "other"}]})
        assert kw["json"]["model"] == "local-llm"
        return FakeResponse(200, json_data=COMPLETION)
    rec = install_fake_requests(monkeypatch, handler)
    ad = OpenAICompatibleAdapter()
    for _ in range(2):
        r = run(ad.send_prompt("hi", {"endpoint": "http://127.0.0.1:4141/v1/chat/completions"}))
        assert r["success"]
    assert len(rec.by_method("GET")) == 1 and len(rec.by_method("POST")) == 2


def test_errors_are_named_with_the_servers_message(monkeypatch):
    install_fake_requests(monkeypatch, lambda m, u, k: FakeResponse(401, json_data={"error": {"message": "Invalid API key"}}))
    r = run(OpenAICompatibleAdapter().send_prompt("hi", {"endpoint": "https://gw.example.test", "model": "m"}))
    assert not r["success"] and "401" in r["error"] and "Invalid API key" in r["error"] and r["metadata"]["status_code"] == 401
    install_fake_requests(monkeypatch, lambda m, u, k: FakeResponse(200, json_data={"choices": [{"message": {"content": ""}}]}))
    r = run(OpenAICompatibleAdapter().send_prompt("hi", {"endpoint": "https://gw.example.test", "model": "m"}))
    assert not r["success"] and "no assistant text" in r["error"]
    assert not run(OpenAICompatibleAdapter().send_prompt("hi", {}))["success"]
