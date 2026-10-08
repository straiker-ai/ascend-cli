"""The capture fills the new presets' configs: the model and system message a page sent, the
language a Dialogflow widget used — so the agent wires them without asking for values already in
the traffic. Host hints route the URLs to the right adapter."""
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "runtime"))

from discovery import classify as C  # noqa: E402


def _ev(url, body):
    return {"pairs": [{"request": {"url": url, "method": "POST", "headers": {}, "raw_body": json.dumps(body)},
                       "response": {"status": 200, "headers": {}, "json": {"ok": True}}}], "chat_pair_index": 0}


def test_openai_filler_reads_model_system_prompt_and_max_tokens():
    url = "https://gw.example.test/v1/chat/completions"
    ev = _ev(url, {"model": "gpt-4o-mini", "max_tokens": 256, "messages": [{"role": "system", "content": "You are Ava."}, {"role": "user", "content": "hi"}]})
    cfg = C._openai_config_from_evidence(ev, url)
    assert cfg == {"endpoint": url, "model": "gpt-4o-mini", "system_prompt": "You are Ava.", "max_tokens": 256}


def test_dialogflow_filler_reads_the_language():
    url = "https://us-central1-dialogflow.googleapis.com/v3/projects/p/locations/l/agents/a/sessions/s:detectIntent"
    cfg = C._dialogflow_config_from_evidence(_ev(url, {"queryInput": {"text": {"text": "hi"}, "languageCode": "de"}}), url)
    assert cfg == {"endpoint": url, "language_code": "de"}


def test_host_hints_route_the_new_presets():
    assert C._preset_for_url("https://api.openai.com/v1/chat/completions") == "openai_compatible"
    assert C._preset_for_url("https://r.openai.azure.com/openai/deployments/d/chat/completions?api-version=1") == "openai_compatible"
    # a captured chat-completions call on an unknown host still derives as direct_api (its body and
    # reply path are explicit there); `target add --api` reaches the preset through the profile instead
    assert C._preset_for_url("http://127.0.0.1:4141/v1/chat/completions") is None
    assert C._preset_for_url("https://europe-west1-dialogflow.googleapis.com/v3/projects/p/locations/l/agents/a/sessions/s:detectIntent") == "dialogflow_cx"
    assert C._preset_for_url("https://bot.example.test/api/chat") is None
