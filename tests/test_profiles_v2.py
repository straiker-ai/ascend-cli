"""The two new published-contract profiles: detected from one GET (or the host alone), built into
the adapter config with the operator's URL kept when it already names the chat path."""
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "runtime"))

from discovery import profiles as P  # noqa: E402


def test_openai_compatible_is_detected_by_a_model_list_or_an_openai_shaped_401(monkeypatch):
    monkeypatch.setattr(P, "_get", lambda url, headers=None, verify=True: (200, {"object": "list", "data": [{"id": "m"}]}))
    assert P.OpenAICompatible.detect("http://127.0.0.1:4141")
    monkeypatch.setattr(P, "_get", lambda url, headers=None, verify=True: (401, {"error": {"message": "no key", "type": "auth_error"}}))
    assert P.OpenAICompatible.detect("https://gw.example.test")
    monkeypatch.setattr(P, "_get", lambda url, headers=None, verify=True: (404, "<html>"))
    assert not P.OpenAICompatible.detect("https://plain.example.test")
    monkeypatch.setattr(P, "_get", lambda url, headers=None, verify=True: (401, "Unauthorized"))
    assert not P.OpenAICompatible.detect("https://basic.example.test")


def test_openai_compatible_build_keeps_a_deployment_path_and_takes_body_fields():
    cfg, facts = P.OpenAICompatible.build("https://r.openai.azure.com", url="https://r.openai.azure.com/openai/deployments/d1/chat/completions?api-version=2024-02-01",
                                          headers={"api-key": "env:AZ"}, body_fields={"model": "d1", "max_tokens": 128})
    assert cfg["adapter"] == "openai_compatible" and cfg["endpoint"].endswith("/deployments/d1/chat/completions?api-version=2024-02-01")
    assert cfg["headers"] == {"api-key": "env:AZ"} and cfg["model"] == "d1" and cfg["max_tokens"] == 128
    assert facts["workspace"] == "r.openai.azure.com" and facts["tools"] == [] and facts["name"]
    cfg2, _ = P.OpenAICompatible.build("http://127.0.0.1:4141")
    assert cfg2["endpoint"] == "http://127.0.0.1:4141/v1/chat/completions" and "model" not in cfg2


def test_dialogflow_is_recognised_from_the_host_and_needs_the_agent_url():
    assert P.DialogflowCX.detect("https://us-central1-dialogflow.googleapis.com")
    assert not P.DialogflowCX.detect("https://bot.example.test")
    url = "https://us-central1-dialogflow.googleapis.com/v3/projects/p/locations/us-central1/agents/abc123/sessions/s:detectIntent"
    cfg, facts = P.DialogflowCX.build("https://us-central1-dialogflow.googleapis.com", url=url, body_fields={"language_code": "fr"})
    assert cfg["adapter"] == "dialogflow_cx" and cfg["endpoint"] == url and cfg["language_code"] == "fr"
    assert facts["name"].startswith("dialogflow-abc123")
    import pytest
    with pytest.raises(ValueError):
        P.DialogflowCX.build("https://us-central1-dialogflow.googleapis.com")


def test_detect_order_keeps_the_existing_profiles_first():
    assert [p.name for p in P.PROFILES] == ["doppelganger", "copilot_studio", "openai_compatible", "dialogflow_cx"]
