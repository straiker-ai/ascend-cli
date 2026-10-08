"""
test_query_credentials.py — a credential in the chat request's QUERY STRING must reach the target,
and a public query parameter must stay on the endpoint.

THE BUG, measured on a Straiker-owned test target whose access code rides as `?code=…` on the
chat POST: derivation stripped the whole query string, registered `/api/chat` with no code, and
the wiring gate answered 401 — for no reason visible in the config. The same stripping breaks an
endpoint whose query is REQUIRED and public (`?api-version=` on an Azure-OpenAI-shaped target):
it 4xx'd on every probe.

The arrangement is the one captured headers already follow (test_captured_credentials.py): the
public part stays in the config, the credential's VALUE goes to the 0600 store, the config holds
an `env:` reference, and `layers/auth.py` folds it back into the query string at send time —
byte-identical to what the browser sent.

Run:  python3 -m pytest tests/test_query_credentials.py -q
"""
import json
import os
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "runtime"))

from discovery import classify as C          # noqa: E402
import target_secrets as TS                  # noqa: E402
import dispatch                              # noqa: E402

CODE = "lab-Q7tR2mX9kL4pZ8vB1nC3"
WINDOW = "wt_9f2c41d07b3e5a8c1290ffee"


def _har(url, headers=None):
    headers = headers or {"Content-Type": "application/json"}
    return {"log": {"version": "1.2", "entries": [{
        "startedDateTime": "2026-09-30T00:00:00.000Z", "time": 5,
        "request": {"method": "POST", "url": url,
                    "httpVersion": "HTTP/1.1", "queryString": [], "cookies": [],
                    "headersSize": -1, "bodySize": 30,
                    "headers": [{"name": k, "value": v} for k, v in headers.items()],
                    "postData": {"mimeType": "application/json",
                                 "text": '{"message":"where is my order?"}'}},
        "response": {"status": 200, "statusText": "OK", "httpVersion": "HTTP/1.1",
                     "headers": [{"name": "Content-Type", "value": "application/json"}],
                     "cookies": [], "redirectURL": "", "headersSize": -1, "bodySize": 24,
                     "content": {"size": 24, "mimeType": "application/json",
                                 "text": '{"reply":"It shipped."}'}},
        "cache": {}, "timings": {"send": 0, "wait": 0, "receive": 0}}]}}


def _classify(url, headers=None):
    return C.classify_evidence(C.har_to_evidence(_har(url, headers)))


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setenv("ASCEND_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("ASCEND_HOME", str(tmp_path / "home"))
    for name in list(os.environ):
        if name.startswith("ASCEND_SECRET_"):
            monkeypatch.delenv(name, raising=False)
    return tmp_path


def _materialised(res):
    """The config exactly as the relay sends it: store populated, auth merged."""
    for name, value in res["secrets"].items():
        TS.record(name, value, host="bot.example.com", header=name, source="test")
    return dispatch.merge_auth(json.loads(json.dumps(res["config"])))


class TestPublicQueryStaysOnTheEndpoint:
    def test_api_version_is_kept(self, store):
        res = _classify("https://bot.example.com/openai/chat?api-version=2024-02-01")
        assert res["config"]["endpoint"] == "https://bot.example.com/openai/chat?api-version=2024-02-01"
        assert not res["secrets"]

    def test_order_and_several_public_params(self, store):
        res = _classify("https://bot.example.com/chat?alt=sse&api-version=2024-02-01")
        assert res["config"]["endpoint"].endswith("?alt=sse&api-version=2024-02-01")


class TestCredentialQueryReachesTheTarget:
    def test_access_code_is_withheld_from_the_config(self, store):
        res = _classify(f"https://bot.example.com/api/chat?code={CODE}")
        assert CODE not in json.dumps(res["config"]), "the code was baked into the config"
        assert CODE not in json.dumps(res["layers"]), "the code is reachable through the layers"
        assert res["config"]["endpoint"] == "https://bot.example.com/api/chat"

    def test_but_its_value_is_captured_under_a_host_scoped_name(self, store):
        res = _classify(f"https://bot.example.com/api/chat?code={CODE}")
        assert CODE in res["secrets"].values(), "the credential was dropped — that is the 401"
        (name,) = [n for n, v in res["secrets"].items() if v == CODE]
        assert name.startswith("ASCEND_SECRET_") and "BOT_EXAMPLE_COM" in name and "QUERY_CODE" in name

    def test_the_config_references_it_as_a_query_api_key(self, store):
        res = _classify(f"https://bot.example.com/api/chat?code={CODE}")
        block = res["config"]["auth"]
        assert block["type"] == "static" and block["mode"] == "api_key" and block["in"] == "query"
        assert block["name"] == "code" and block["value_ref"].startswith("env:ASCEND_SECRET_")
        assert "query:code" in res["config"]["_captured_credentials"]

    def test_the_wire_carries_the_code_byte_identical(self, store):
        res = _classify(f"https://bot.example.com/api/chat?code={CODE}")
        sent = _materialised(res)
        assert "_auth_error" not in sent, sent.get("_auth_error")
        assert sent["endpoint"] == f"https://bot.example.com/api/chat?code={CODE}"

    def test_public_and_credential_params_together(self, store):
        res = _classify(f"https://bot.example.com/api/chat?api-version=2024-02-01&code={CODE}")
        assert res["config"]["endpoint"] == "https://bot.example.com/api/chat?api-version=2024-02-01"
        sent = _materialised(res)
        assert "api-version=2024-02-01" in sent["endpoint"] and f"code={CODE}" in sent["endpoint"]

    def test_beside_a_captured_header_both_are_sent(self, store):
        res = _classify(f"https://bot.example.com/api/chat?key={CODE}",
                        headers={"Content-Type": "application/json", "X-Window-Token": WINDOW})
        auth = res["config"]["auth"]
        assert isinstance(auth, list) and len(auth) == 2, auth
        assert WINDOW not in json.dumps(res["config"])
        sent = _materialised(res)
        assert "_auth_error" not in sent, sent.get("_auth_error")
        assert sent["headers"]["X-Window-Token"] == WINDOW
        assert f"key={CODE}" in sent["endpoint"]

    def test_an_inferred_reference_nothing_sets_is_not_kept_beside_it(self, store):
        """A list that still carried `env:DISCOVERED_TOKEN` would fail the whole auth at send time."""
        res = _classify(f"https://bot.example.com/api/chat?token={CODE}")
        assert "DISCOVERED_TOKEN" not in json.dumps(res["config"])
        sent = _materialised(res)
        assert "_auth_error" not in sent, sent.get("_auth_error")


class TestTheClassifierItself:
    @pytest.mark.parametrize("name,value,secret", [
        ("code", "lab-abc", True), ("key", "AIzaSyD-9tSrke72PouQMnMX-a7eZSW0jkFMBxY", True),
        ("api-version", "2024-02-01", False), ("alt", "sse", False), ("id", "conv-123", False),
        ("x-nonce-thing", "n/a", True),                      # a credential-shaped name
        ("ref", "a9B8c7D6e5F4g3H2i1J0k9L8m7N6o5P4", True),   # opaque, long, mixed: withheld
        ("ref", "short", False),
    ])
    def test_name_then_entropy(self, name, value, secret):
        assert C._looks_secret_param(name, value) is secret
