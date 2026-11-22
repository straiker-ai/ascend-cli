"""
test_importers.py — the two ZERO-GUESSING discovery inputs (`discovery.importers`).

A `curl` line the customer already runs, and a published OpenAPI document, are
*ground truth* rather than inference. So these tests hold the module to a
translation standard, not a detection one:

* every header, id, flag and sibling field in the curl survives BYTE-FOR-BYTE —
  the single edit is the prompt becoming ``{{PROMPT}}``;
* a malformed command produces an operator-readable error with a next action,
  never a traceback;
* a spec's own declarations (schemas, required fields, response shape) drive the
  config, and the score only decides what order candidates are TRIED in.

Offline by construction: curl parsing never touches the network, and
`discover_spec` — the only network path — is exercised with a fake
`requests.Session`.
"""
import json
from pathlib import Path
import sys

import pytest

import requests

from conftest import FakeResponse

importers = pytest.importorskip("discovery.importers",
                                reason="runtime/discovery/importers.py not present")

from_curl = importers.from_curl
explain_curl = importers.explain_curl
CurlParseError = importers.CurlParseError
PLACEHOLDER = importers.PROMPT_PLACEHOLDER


# =========================================================================== #
# 1. curl parsing
# =========================================================================== #
MULTILINE_CURL = """curl -X POST 'https://bot.example.com/api/v1/chat' \\
  -H 'Content-Type: application/json' \\
  -H 'Authorization: Bearer tok-abc123' \\
  -H 'X-Tenant-Id: acme-eu' \\
  -H 'X-Request-Source: web' \\
  --data-raw '{"message":"What is my order status?","session_id":"s-42","model":"gpt-4o","stream":false,"temperature":0.2,"metadata":{"channel":"web","locale":"en-GB"}}'
"""


class TestCurlShapes:
    def test_multiline_with_backslash_continuations(self):
        cfg = from_curl(MULTILINE_CURL, prompt_hint="What is my order status?")
        assert cfg["adapter"] == "direct_api"
        assert cfg["endpoint"] == "https://bot.example.com/api/v1/chat"
        assert cfg["method"] == "POST"
        assert cfg["_source"] == "curl"

    def test_repeated_H_flags_all_survive(self):
        cfg = from_curl(MULTILINE_CURL, prompt_hint="What is my order status?")
        assert cfg["headers"] == {
            "Content-Type": "application/json",
            "Authorization": "Bearer tok-abc123",
            "X-Tenant-Id": "acme-eu",
            "X-Request-Source": "web",
        }

    def test_data_raw_body_is_parsed_as_json(self):
        cfg = from_curl(MULTILINE_CURL, prompt_hint="What is my order status?")
        assert cfg["_body_kind"] == "json"
        assert isinstance(cfg["body"], dict)

    def test_single_and_double_quotes_are_equivalent(self):
        single = ("curl https://h.example.com/chat "
                  "-H 'Content-Type: application/json' "
                  "-d '{\"message\":\"where is my order\"}'")
        double = ('curl https://h.example.com/chat '
                  '-H "Content-Type: application/json" '
                  '-d "{\\"message\\":\\"where is my order\\"}"')
        a = from_curl(single, prompt_hint="where is my order")
        b = from_curl(double, prompt_hint="where is my order")
        for key in ("endpoint", "method", "headers", "body", "_prompt_field"):
            assert a[key] == b[key], f"{key} differs between quoting styles"

    def test_glued_short_option_value(self):
        cfg = from_curl("curl -XPOST https://h.example.com/chat "
                        "-H'Content-Type: application/json' "
                        "-d '{\"q\":\"where is my parcel today\"}'")
        assert cfg["method"] == "POST"
        assert cfg["headers"]["Content-Type"] == "application/json"
        assert cfg["body"] == {"q": PLACEHOLDER}

    def test_long_option_with_inline_value(self):
        cfg = from_curl("curl --header='X-Api-Key: k1' --request=POST "
                        "--data-raw='{\"message\":\"hello there my friend\"}' "
                        "https://h.example.com/chat")
        assert cfg["method"] == "POST"
        assert cfg["headers"]["X-Api-Key"] == "k1"
        assert cfg["body"] == {"message": PLACEHOLDER}

    def test_ansi_c_quoting_from_chrome_copy_as_curl(self):
        cfg = from_curl("curl https://h.example.com/chat -H $'X-Note: alpha' "
                        "--data-raw $'{\"message\":\"hello there my friend\"}'")
        assert cfg["headers"]["X-Note"] == "alpha"
        assert cfg["body"] == {"message": PLACEHOLDER}

    def test_windows_caret_continuations(self):
        cmd = ('curl https://h.example.com/chat ^\n'
               ' -H "Content-Type: application/json" ^\n'
               ' -d "{\\"message\\":\\"hello there my friend\\"}"')
        cfg = from_curl(cmd)
        assert cfg["endpoint"] == "https://h.example.com/chat"
        assert cfg["body"] == {"message": PLACEHOLDER}

    def test_x_get_with_a_query_string(self):
        cfg = from_curl('curl -X GET '
                        '"https://bot.example.com/ask?q=how%20do%20I%20reset%20my%20password&lang=en" '
                        '-H "Accept: application/json"',
                        prompt_hint="how do I reset my password")
        assert cfg["method"] == "GET"
        assert cfg["_prompt_field"] == "query:q"
        assert cfg["endpoint"] == "https://bot.example.com/ask?q={{PROMPT}}&lang=en"
        assert cfg["body"] == {}, "a GET carries no body"
        assert "lang=en" in cfg["endpoint"], "unrelated query params must survive"

    def test_G_flag_moves_the_body_into_the_query(self):
        cfg = from_curl("curl -G https://h.example.com/ask -d 'q=how do I reset my password'")
        assert cfg["method"] == "GET"
        assert cfg["endpoint"] == "https://h.example.com/ask?q={{PROMPT}}"

    def test_json_flag(self):
        cfg = from_curl("curl https://h.example.com/v1/chat "
                        "--json '{\"prompt\":\"tell me about your return policy\"}'")
        assert cfg["method"] == "POST"
        assert cfg["body"] == {"prompt": PLACEHOLDER}
        assert cfg["headers"]["Content-Type"] == "application/json"

    def test_u_basic_auth_becomes_an_authorization_header(self):
        cfg = from_curl("curl -u alice:s3cret https://h.example.com/chat "
                        "-H 'Content-Type: application/json' "
                        "-d '{\"text\":\"hello there friend how are you\"}'")
        assert cfg["headers"]["Authorization"] == "Basic YWxpY2U6czNjcmV0"
        assert explain_curl("curl -u alice:s3cret https://h.example.com/chat "
                            "-d 'x'")["basic_auth_user"] == "alice"

    def test_oauth2_bearer_flag(self):
        cfg = from_curl("curl --oauth2-bearer tok-9 https://h.example.com/chat "
                        "-H 'Content-Type: application/json' "
                        "-d '{\"message\":\"hello there my friend\"}'")
        assert cfg["headers"]["Authorization"] == "Bearer tok-9"

    def test_cookie_flag(self):
        cfg = from_curl("curl -b 'sid=abc; theme=dark' https://h.example.com/chat "
                        "-H 'Content-Type: application/json' "
                        "-d '{\"message\":\"tell me about shipping options\"}'")
        assert cfg["headers"]["Cookie"] == "sid=abc; theme=dark"

    def test_max_time_becomes_the_timeout(self):
        cfg = from_curl("curl -m 12 https://h.example.com/chat "
                        "-H 'Content-Type: application/json' "
                        "-d '{\"message\":\"what is the weather like today\"}'")
        assert cfg["timeout_ms"] == 12000

    def test_explicit_timeout_ms_wins(self):
        cfg = from_curl("curl -m 12 https://h.example.com/chat "
                        "-H 'Content-Type: application/json' "
                        "-d '{\"message\":\"what is the weather like today\"}'",
                        timeout_ms=1234)
        assert cfg["timeout_ms"] == 1234

    @pytest.mark.parametrize("flags", [
        "-k", "-L", "--compressed", "-s -S -v", "--http2 --tlsv1.2 --no-buffer",
        "-k -L --compressed -sS", "--globoff --path-as-is",
    ])
    def test_noise_flags_are_accepted_and_ignored(self, flags):
        cfg = from_curl(f"curl {flags} -X POST https://h.example.com/chat "
                        "-H 'Content-Type: application/json' "
                        "-d '{\"message\":\"how do I return an item\"}'")
        assert cfg["endpoint"] == "https://h.example.com/chat"
        assert cfg["method"] == "POST"
        assert cfg["body"] == {"message": PLACEHOLDER}

    def test_insecure_flag_is_recorded_and_explained(self):
        cfg = from_curl("curl -k https://h.example.com/chat "
                        "-H 'Content-Type: application/json' "
                        "-d '{\"message\":\"how do I return an item\"}'")
        assert cfg["_insecure"] is True
        assert any("insecure" in n for n in cfg["_notes"])

    def test_unknown_flag_is_reported_not_fatal(self):
        cfg = from_curl("curl --frobnicate https://h.example.com/chat "
                        "-H 'Content-Type: application/json' "
                        "-d '{\"message\":\"hello there my friend\"}'")
        assert cfg["body"] == {"message": PLACEHOLDER}
        assert any("--frobnicate" in n for n in cfg["_notes"])

    def test_hop_by_hop_headers_are_dropped(self):
        cfg = from_curl("curl https://h.example.com/chat "
                        "-H 'Content-Length: 42' -H 'Host: h.example.com' "
                        "-H 'Accept-Encoding: gzip' "
                        "-H 'Content-Type: application/json' "
                        "-d '{\"message\":\"hello there my friend\"}'")
        lowered = {k.lower() for k in cfg["headers"]}
        assert "content-length" not in lowered
        assert "host" not in lowered
        assert "accept-encoding" not in lowered

    def test_unexpanded_shell_variables_are_flagged(self):
        cfg = from_curl('curl https://h.example.com/chat -H "Authorization: Bearer $TOKEN" '
                        "-H 'Content-Type: application/json' "
                        "-d '{\"message\":\"what can you do for me\"}'")
        assert any("$TOKEN" in n for n in cfg["_notes"])

    def test_scheme_is_assumed_when_missing(self):
        cfg = from_curl("curl bot.example.com/chat -H 'Content-Type: application/json' "
                        "-d '{\"message\":\"hello there my friend\"}'")
        assert cfg["endpoint"] == "https://bot.example.com/chat"
        assert any("assuming https" in n for n in cfg["_notes"])


class TestPromptTemplating:
    """The prompt becomes {{PROMPT}} — and NOTHING else in the body changes."""

    BODY = {"message": "What is my order status?", "session_id": "s-42",
            "model": "gpt-4o", "stream": False, "temperature": 0.2,
            "metadata": {"channel": "web", "locale": "en-GB"}}

    def test_with_prompt_hint(self):
        cfg = from_curl(MULTILINE_CURL, prompt_hint="What is my order status?")
        assert cfg["_prompt_field"] == "body:message"
        assert cfg["_prompt_sample"] == "What is my order status?"
        assert cfg["body"]["message"] == PLACEHOLDER

    def test_without_prompt_hint_picks_the_same_field(self):
        cfg = from_curl(MULTILINE_CURL)
        assert cfg["_prompt_field"] == "body:message"
        assert cfg["body"]["message"] == PLACEHOLDER

    @pytest.mark.parametrize("hint", [None, "What is my order status?"])
    def test_every_other_field_is_preserved_exactly(self, hint):
        cfg = from_curl(MULTILINE_CURL, prompt_hint=hint)
        expected = dict(self.BODY, message=PLACEHOLDER)
        assert cfg["body"] == expected, "only the prompt field may change"
        # types survive the round-trip, not just values
        assert cfg["body"]["stream"] is False
        assert cfg["body"]["temperature"] == 0.2
        assert cfg["body"]["metadata"] == {"channel": "web", "locale": "en-GB"}

    def test_exactly_one_placeholder_in_the_config(self):
        blob = json.dumps(from_curl(MULTILINE_CURL))
        assert blob.count(PLACEHOLDER) == 1

    def test_hint_finds_the_field_a_score_would_miss(self):
        """`model` holds prose here; only the hint can settle which field is the prompt."""
        curl = ("curl https://h.example.com/chat -H 'Content-Type: application/json' "
                "-d '{\"note\":\"please answer politely and briefly\",\"q\":\"hi\"}'")
        cfg = from_curl(curl, prompt_hint="hi")
        assert cfg["_prompt_field"] == "body:q"
        assert cfg["body"] == {"note": "please answer politely and briefly", "q": PLACEHOLDER}

    def test_prompt_embedded_in_a_larger_string_keeps_the_scaffolding(self):
        curl = ("curl https://h.example.com/chat -H 'Content-Type: application/json' "
                "-d '{\"message\":\"User asked: where is my order? Answer politely.\"}'")
        cfg = from_curl(curl, prompt_hint="where is my order?")
        assert cfg["body"]["message"] == "User asked: {{PROMPT}} Answer politely."
        assert any("embedded inside a larger value" in n for n in cfg["_notes"])

    def test_chat_history_picks_the_user_turn_not_the_system_prompt(self):
        curl = ("curl https://h.example.com/chat -H 'Content-Type: application/json' "
                "-d '{\"messages\":[{\"role\":\"system\",\"content\":"
                "\"You are a helpful support assistant for a store.\"},"
                "{\"role\":\"user\",\"content\":\"where is my package\"}],\"model\":\"m1\"}'")
        cfg = from_curl(curl)
        assert cfg["_prompt_field"] == "body:messages.1.content"
        assert cfg["body"]["messages"][0]["content"].startswith("You are a helpful")
        assert cfg["body"]["messages"][1]["content"] == PLACEHOLDER
        assert cfg["body"]["model"] == "m1"

    def test_an_already_templated_command_is_left_alone(self):
        curl = ("curl https://h.example.com/chat -H 'Content-Type: application/json' "
                "-d '{\"message\":\"{{PROMPT}}\",\"top_k\":3}'")
        cfg = from_curl(curl)
        assert cfg["_prompt_field"] == "preserved"
        assert cfg["body"] == {"message": PLACEHOLDER, "top_k": 3}
        assert any("already contained" in n for n in cfg["_notes"])

    def test_response_path_is_none_unless_pinned(self):
        cfg = from_curl(MULTILINE_CURL)
        assert cfg["response_path"] is None, "a REQUEST cannot reveal where the answer lives"
        assert any("response_path is not set" in n for n in cfg["_notes"])
        pinned = from_curl(MULTILINE_CURL, response_path="data.reply")
        assert pinned["response_path"] == "data.reply"

    def test_require_prompt_false_yields_a_config_with_a_warning(self):
        curl = ("curl https://h.example.com/ping -H 'Content-Type: application/json' "
                "-d '{\"id\":\"550e8400-e29b-41d4-a716-446655440000\"}'")
        cfg = from_curl(curl, require_prompt=False)
        assert cfg["_prompt_field"] is None
        assert cfg["body"] == {"id": "550e8400-e29b-41d4-a716-446655440000"}
        assert any("NO PROMPT FIELD FOUND" in n for n in cfg["_notes"])


class TestBodyEncodings:
    def test_form_urlencoded_body(self):
        cfg = from_curl("curl https://h.example.com/chat "
                        "-H 'Content-Type: application/x-www-form-urlencoded' "
                        "-d 'question=where is my package&user=bob&lang=en'")
        assert cfg["_body_kind"] == "form"
        assert cfg["headers"]["Content-Type"] == "application/x-www-form-urlencoded"
        assert cfg["_prompt_field"] == "form:question"
        assert cfg["body"] == {"question": PLACEHOLDER, "user": "bob", "lang": "en"}

    def test_form_body_inferred_without_a_content_type(self):
        cfg = from_curl("curl https://h.example.com/chat -d 'question=where is my package&user=bob'")
        assert cfg["_body_kind"] == "form"
        assert cfg["headers"]["Content-Type"] == "application/x-www-form-urlencoded"
        assert cfg["body"] == {"question": PLACEHOLDER, "user": "bob"}

    def test_data_urlencode_is_decoded_back_to_the_real_value(self):
        cfg = from_curl("curl https://h.example.com/chat "
                        "-H 'Content-Type: application/x-www-form-urlencoded' "
                        "--data-urlencode 'q=where is my order'")
        assert cfg["_body_kind"] == "form"
        assert cfg["body"] == {"q": PLACEHOLDER}

    def test_plain_text_body(self):
        cfg = from_curl("curl https://h.example.com/chat -H 'Content-Type: text/plain' "
                        "-d 'what are your opening hours'")
        assert cfg["_body_kind"] == "text"
        assert cfg["body"] == PLACEHOLDER
        assert cfg["_prompt_field"] == "text:"
        assert any("plain text" in n for n in cfg["_notes"]), \
            "the JSON-string serialisation caveat must be stated"

    def test_json_content_type_is_added_when_the_body_is_json(self):
        cfg = from_curl("curl https://h.example.com/chat "
                        "-d '{\"message\":\"hello there my friend\"}'")
        assert cfg["headers"]["Content-Type"] == "application/json"

    def test_a_body_from_a_file_is_flagged_not_invented(self):
        cfg = from_curl("curl https://h.example.com/chat -H 'Content-Type: application/json' "
                        "-d @body.json", require_prompt=False)
        assert cfg["body"] == {}
        assert any("body.json" in n for n in cfg["_notes"])


class TestCurlErrors:
    @pytest.mark.parametrize("reader", [from_curl, explain_curl])
    def test_captured_two_request_file_is_refused_before_conversion(self, reader):
        captured = (Path(__file__).parent / "fixtures/multi-request.curl").read_text()
        with pytest.raises(CurlParseError, match="contains multiple requests"):
            reader(captured)

    @pytest.mark.parametrize("separator", ["; ", " && ", " --next ", " -: "])
    def test_inline_request_boundaries_are_refused(self, separator):
        captured = (Path(__file__).parent / "fixtures/multi-request.curl").read_text()
        first, second = captured.strip().split("\n\n")
        if separator.strip() in {"--next", "-:"}:
            second = second.partition(" ")[2]
        with pytest.raises(CurlParseError, match="contains multiple requests"):
            explain_curl(first + separator + second)

    def test_quoted_text_and_continuations_are_one_request(self):
        original = MULTILINE_CURL.replace("What is my order status?", "show curl; curl help")
        assert explain_curl(original)["prompt_value"] == "show curl; curl help"

    """Every failure is a readable sentence with a next action, never a traceback."""

    @pytest.mark.parametrize("bad,expected", [
        ("", "paste the full command"),
        ("   ", "paste the full command"),
        (None, "paste the full command"),
        ("curl", "no URL found"),
        ("curl -X POST", "no URL found"),
        ("curl -H", "truncated"),
        ("curl --header", "truncated"),
        ("curl -X POST 'https://h/chat -d '{}'", "unterminated single quote"),
        ('curl -X POST "https://h/chat -d {}', "unterminated double quote"),
        ("curl https://h/chat -H $'X-A: b", "unterminated $'"),
        ("just some prose the customer pasted", "does not look like a curl"),
    ])
    def test_clear_message_for_malformed_input(self, bad, expected):
        with pytest.raises(CurlParseError) as exc:
            from_curl(bad)
        msg = str(exc.value)
        assert expected in msg, msg
        assert len(msg) > 30, "an error must explain, not just label"

    def test_errors_are_valueerror_subclasses(self):
        assert issubclass(CurlParseError, ValueError)

    def test_unlocatable_prompt_lists_what_it_saw(self):
        curl = ("curl https://h.example.com/ping -H 'Content-Type: application/json' "
                "-d '{\"id\":\"550e8400-e29b-41d4-a716-446655440000\"}'")
        with pytest.raises(CurlParseError) as exc:
            from_curl(curl)
        msg = str(exc.value)
        assert "prompt_hint=" in msg
        assert "{{PROMPT}}" in msg
        assert "Fields seen" in msg or "No string fields" in msg

    def test_a_wrong_prompt_hint_says_so(self):
        curl = ("curl https://h.example.com/chat -H 'Content-Type: application/json' "
                "-d '{\"message\":\"abc\"}'")
        with pytest.raises(CurlParseError) as exc:
            from_curl(curl, prompt_hint="not in there")
        assert "was not found in the request" in str(exc.value)

    def test_no_traceback_leaks_from_arbitrary_junk(self):
        for junk in ("curl ''", "curl -d", "curl --data-raw", "curl -X"):
            with pytest.raises(CurlParseError):
                from_curl(junk)


class TestExplainCurl:
    def test_returns_the_parsed_pieces(self):
        info = explain_curl(MULTILINE_CURL)
        assert info["url"] == "https://bot.example.com/api/v1/chat"
        assert info["method"] == "POST"
        assert info["body_kind"] == "json"
        assert info["content_type"] == "application/json"
        assert info["prompt_field"] == "body:message"
        assert info["prompt_value"] == "What is my order status?"
        assert info["prompt_exact"] is True
        assert info["query"] == {}

    def test_shows_every_candidate_it_considered_best_first(self):
        info = explain_curl("curl https://h.example.com/chat "
                            "-H 'Content-Type: application/json' "
                            "-d '{\"message\":\"where is my order\",\"model\":\"gpt-4o\"}'")
        paths = [c["path"] for c in info["prompt_candidates"]]
        assert paths[0] == "message"
        assert "model" in paths
        scores = [c["score"] for c in info["prompt_candidates"]]
        assert scores == sorted(scores, reverse=True)
        assert scores[-1] < 0, "a structurally-never-prompt key must score negative"

    def test_is_pure_and_does_not_mutate_its_input(self):
        text = MULTILINE_CURL
        explain_curl(text)
        assert text == MULTILINE_CURL


class TestSecretsToEnv:
    def test_default_keeps_working_values(self):
        cfg = from_curl(MULTILINE_CURL, prompt_hint="What is my order status?")
        assert cfg["headers"]["Authorization"] == "Bearer tok-abc123"
        assert "auth" not in cfg

    def test_bearer_is_externalised_on_request(self):
        cfg = from_curl(MULTILINE_CURL, prompt_hint="What is my order status?",
                        secrets_to_env=True)
        assert "Authorization" not in cfg["headers"]
        assert cfg["auth"] == {"type": "static", "mode": "bearer", "name": "Authorization",
                               "prefix": "Bearer", "value_ref": "env:ASCEND_BEARER_TOKEN"}
        assert cfg["_secret_env"] == ["ASCEND_BEARER_TOKEN"]
        assert "tok-abc123" not in json.dumps(cfg), "no secret may survive in the config"
        assert any("export ASCEND_BEARER_TOKEN" in n for n in cfg["_notes"])

    def test_api_key_header_becomes_an_api_key_auth_block(self):
        cfg = from_curl("curl https://h.example.com/chat -H 'X-Api-Key: k-123' "
                        "-H 'Content-Type: application/json' "
                        "-d '{\"message\":\"hello there my friend\"}'",
                        secrets_to_env=True)
        assert cfg["auth"]["mode"] == "api_key"
        assert cfg["auth"]["name"] == "X-Api-Key"
        assert cfg["auth"]["value_ref"] == "env:ASCEND_X_API_KEY"
        assert "k-123" not in json.dumps(cfg)

    def test_extra_secret_headers_are_reported_not_silently_dropped(self):
        cfg = from_curl("curl https://h.example.com/chat -H 'Authorization: Bearer t' "
                        "-H 'X-Api-Key: k' -H 'Content-Type: application/json' "
                        "-d '{\"message\":\"hello there my friend\"}'",
                        secrets_to_env=True)
        assert cfg["_secrets_to_export"] == {"X-Api-Key": "env:ASCEND_X_API_KEY"}
        assert any("re-add these headers" in n for n in cfg["_notes"])


# =========================================================================== #
# 2. API spec import
# =========================================================================== #
SPEC = {
    "openapi": "3.0.1",
    "info": {"title": "Synthetic Support Bot", "version": "1.0.0"},
    "servers": [{"url": "https://api.example.com/v2"}],
    "paths": {
        "/health": {
            "get": {"summary": "Liveness probe", "operationId": "getHealth",
                    "tags": ["ops"],
                    "responses": {"200": {"description": "ok"}}},
        },
        "/chat": {
            "post": {
                "summary": "Send a message to the assistant",
                "operationId": "createChat",
                "tags": ["chat"],
                "requestBody": {"required": True, "content": {"application/json": {
                    "schema": {"$ref": "#/components/schemas/ChatRequest"}}}},
                "responses": {"200": {"content": {"application/json": {
                    "schema": {"$ref": "#/components/schemas/ChatResponse"}}}}},
            },
        },
        "/sessions/{sessionId}/messages": {
            "post": {
                "summary": "Post a message in an existing session",
                "operationId": "postMessage",
                "parameters": [
                    {"name": "sessionId", "in": "path", "required": True,
                     "schema": {"type": "string"}},
                    {"name": "apiVersion", "in": "query", "required": True,
                     "schema": {"type": "string", "default": "2024-01-01"}},
                ],
                "requestBody": {"content": {"application/json": {"schema": {
                    "type": "object", "required": ["text"],
                    "properties": {"text": {"type": "string"}}}}}},
                "responses": {"200": {"content": {"application/json": {"schema": {
                    "type": "object", "properties": {"reply": {"type": "string"}}}}}}},
            },
        },
        "/files/upload": {
            "post": {"summary": "Upload a document to the index",
                     "operationId": "uploadFile", "tags": ["files"],
                     "responses": {"200": {"description": "ok"}}},
        },
    },
    "components": {"schemas": {
        "ChatRequest": {
            "type": "object", "required": ["message", "model"],
            "properties": {
                "message": {"type": "string"},
                "model": {"type": "string", "enum": ["small", "large"]},
                "temperature": {"type": "number"},
                "stream": {"type": "boolean"},
            }},
        "ChatResponse": {
            "type": "object",
            "properties": {
                "id": {"type": "string"},
                "answer": {"type": "string"},
                "usage": {"type": "object", "properties": {"tokens": {"type": "integer"}}},
            }},
    }},
}


class TestEndpointsFromSpec:
    def test_chat_post_outranks_an_unrelated_health_get(self):
        eps = importers.endpoints_from_spec(SPEC, methods=("get", "post"))
        assert eps, "the /chat operation must be found"
        assert (eps[0]["path"], eps[0]["method"]) == ("/chat", "POST")
        health = [e for e in eps if e["path"] == "/health"]
        assert not health or health[0]["score"] < eps[0]["score"], \
            "an ops endpoint must never outrank the chat call"

    def test_anti_words_push_a_file_upload_below_chat(self):
        eps = importers.endpoints_from_spec(SPEC)
        by_path = {e["path"]: e["score"] for e in eps}
        assert by_path["/chat"] > by_path.get("/files/upload", -99)

    def test_scores_are_ordered_and_auditable(self):
        eps = importers.endpoints_from_spec(SPEC)
        assert [e["score"] for e in eps] == sorted((e["score"] for e in eps), reverse=True)
        assert "keyword:chat" in eps[0]["reasons"]
        assert "request-field:message" in eps[0]["reasons"]
        assert "response-field:answer" in eps[0]["reasons"]

    def test_refs_are_resolved_into_usable_schemas(self):
        chat = importers.endpoints_from_spec(SPEC)[0]
        assert chat["request_schema"]["properties"]["message"] == {"type": "string"}
        assert chat["response_schema"]["properties"]["answer"] == {"type": "string"}
        assert "$ref" not in json.dumps(chat["request_schema"])

    def test_operation_metadata_is_carried_through(self):
        chat = importers.endpoints_from_spec(SPEC)[0]
        assert chat["operation_id"] == "createChat"
        assert chat["tags"] == ["chat"]
        assert chat["server"] == "https://api.example.com/v2"
        assert chat["content_type"] == "application/json"

    def test_swagger2_body_parameter_is_understood(self):
        swagger = {
            "swagger": "2.0", "basePath": "/api",
            "consumes": ["application/json"],
            "paths": {"/chat": {"post": {
                "summary": "Chat with the assistant",
                "parameters": [{"in": "body", "name": "body", "schema": {
                    "type": "object", "required": ["message"],
                    "properties": {"message": {"type": "string"}}}}],
                "responses": {"200": {"schema": {
                    "type": "object", "properties": {"reply": {"type": "string"}}}}},
            }}},
        }
        eps = importers.endpoints_from_spec(swagger)
        assert eps[0]["path"] == "/chat"
        assert eps[0]["request_schema"]["properties"]["message"] == {"type": "string"}
        assert eps[0]["server"] == "/api"

    def test_self_referential_schema_does_not_hang(self):
        spec = {
            "openapi": "3.0.0",
            "paths": {"/chat": {"post": {"summary": "chat", "requestBody": {"content": {
                "application/json": {"schema": {"$ref": "#/components/schemas/Node"}}}},
                "responses": {}}}},
            "components": {"schemas": {"Node": {
                "type": "object",
                "properties": {"message": {"type": "string"},
                               "parent": {"$ref": "#/components/schemas/Node"}}}}},
        }
        eps = importers.endpoints_from_spec(spec)
        assert eps and eps[0]["path"] == "/chat"

    @pytest.mark.parametrize("junk", [None, "not a spec", 42, [], {}, {"openapi": "3.0.0"},
                                      {"paths": "not a dict"}])
    def test_junk_input_returns_an_empty_list(self, junk):
        assert importers.endpoints_from_spec(junk) == []


class TestConfigFromSpecEndpoint:
    def test_body_carries_the_placeholder(self):
        ep = importers.endpoints_from_spec(SPEC)[0]
        cfg = importers.config_from_spec_endpoint("https://api.example.com", ep)
        assert cfg["adapter"] == "direct_api"
        assert cfg["method"] == "POST"
        assert PLACEHOLDER in json.dumps(cfg["body"])
        assert cfg["body"]["message"] == PLACEHOLDER
        assert cfg["_prompt_field"] == "body:message"

    def test_response_path_is_plausible(self):
        ep = importers.endpoints_from_spec(SPEC)[0]
        cfg = importers.config_from_spec_endpoint("https://api.example.com", ep)
        assert cfg["response_path"] == "answer", "the declared answer field, not the id"

    def test_only_required_and_message_like_fields_are_filled(self):
        ep = importers.endpoints_from_spec(SPEC)[0]
        cfg = importers.config_from_spec_endpoint("https://api.example.com", ep)
        assert set(cfg["body"]) == {"message", "model"}
        assert cfg["body"]["model"] == "small", "an enum's first value, not an invention"
        assert "temperature" not in cfg["body"]

    def test_guessed_values_are_called_out(self):
        ep = importers.endpoints_from_spec(SPEC)[0]
        cfg = importers.config_from_spec_endpoint("https://api.example.com", ep)
        assert any("'model'" in n and "placeholder" in n for n in cfg["_notes"])

    def test_server_prefix_is_folded_into_the_url(self):
        ep = importers.endpoints_from_spec(SPEC)[0]
        cfg = importers.config_from_spec_endpoint("https://api.example.com", ep)
        assert cfg["endpoint"] == "https://api.example.com/v2/chat"

    def test_base_url_already_carrying_the_prefix_is_not_doubled(self):
        ep = importers.endpoints_from_spec(SPEC)[0]
        cfg = importers.config_from_spec_endpoint("https://api.example.com/v2", ep)
        assert cfg["endpoint"] == "https://api.example.com/v2/chat"

    def test_path_and_query_parameters_are_filled_and_flagged(self):
        ep = next(e for e in importers.endpoints_from_spec(SPEC)
                  if e["path"].startswith("/sessions"))
        cfg = importers.config_from_spec_endpoint("https://api.example.com", ep)
        assert "{sessionId}" not in cfg["endpoint"]
        assert "apiVersion=2024-01-01" in cfg["endpoint"]
        assert any("sessionId" in n and "real id" in n for n in cfg["_notes"])
        assert cfg["body"] == {"text": PLACEHOLDER}
        assert cfg["response_path"] == "reply"

    def test_provenance_is_recorded(self):
        ep = importers.endpoints_from_spec(SPEC)[0]
        cfg = importers.config_from_spec_endpoint("https://api.example.com", ep)
        assert cfg["_source"] == "openapi"
        assert cfg["_endpoint"]["operation_id"] == "createChat"
        assert cfg["_endpoint"]["reasons"]

    def test_missing_request_schema_still_gets_a_prompt_field(self):
        cfg = importers.config_from_spec_endpoint(
            "https://api.example.com", {"path": "/chat", "method": "POST"})
        assert cfg["body"] == {"message": PLACEHOLDER}
        assert cfg["endpoint"] == "https://api.example.com/chat"
        assert any("no JSON request body" in n for n in cfg["_notes"])

    def test_no_answer_like_response_field_says_so(self):
        cfg = importers.config_from_spec_endpoint("https://api.example.com", {
            "path": "/chat", "method": "POST",
            "request_schema": {"type": "object", "required": ["message"],
                               "properties": {"message": {"type": "string"}}},
            "response_schema": {"type": "object", "properties": {"id": {"type": "string"}}}})
        assert cfg["response_path"] is None
        assert any("no answer-like string" in n for n in cfg["_notes"])

    def test_a_bad_endpoint_dict_raises_with_the_fix(self):
        for bad in ({}, {"method": "POST"}, "nope", None):
            with pytest.raises(ValueError) as exc:
                importers.config_from_spec_endpoint("https://h", bad)
            assert "endpoints_from_spec" in str(exc.value)

    def test_configs_from_spec_is_ranked_and_limited(self):
        cfgs = importers.configs_from_spec("https://api.example.com", SPEC, limit=2)
        assert len(cfgs) <= 2
        assert cfgs[0]["endpoint"] == "https://api.example.com/v2/chat"
        assert all(PLACEHOLDER in json.dumps(c["body"]) for c in cfgs)
        assert importers.configs_from_spec("https://api.example.com", SPEC, limit=0) == []


# --------------------------------------------------------------------------- #
# discover_spec — the ONLY network path, exercised with a fake Session
# --------------------------------------------------------------------------- #
class FakeSession:
    """Stands in for `requests.Session`; `routes(url)` returns a response or an exception."""

    def __init__(self, routes):
        self.routes = routes
        self.urls = []
        self.closed = False

    def get(self, url, **kw):
        self.urls.append(url)
        out = self.routes(url)
        if isinstance(out, Exception):
            raise out
        return out

    def close(self):
        self.closed = True


def install_fake_session(monkeypatch, routes):
    """Patch `requests.Session` so discover_spec talks to `routes` instead of the wire."""
    made = []

    def factory():
        s = FakeSession(routes)
        made.append(s)
        return s

    monkeypatch.setattr(requests, "Session", factory)
    return made


def not_found(url):
    return FakeResponse(404, {"detail": "Not Found"}, headers={"Content-Type": "application/json"})


class TestDiscoverSpec:
    def test_finds_the_spec_at_a_well_known_path(self, monkeypatch):
        def routes(url):
            if url == "https://api.example.com/openapi.json":
                return FakeResponse(200, SPEC, headers={"Content-Type": "application/json"})
            return not_found(url)

        made = install_fake_session(monkeypatch, routes)
        res = importers.discover_spec("https://api.example.com")
        assert res["ok"] is True
        assert res["spec_url"] == "https://api.example.com/openapi.json"
        assert res["kind"] == "openapi"
        assert res["format"] == "json"
        assert res["endpoints"][0]["path"] == "/chat"
        assert made[0].closed is True, "the session must be closed"

    def test_stops_early_on_a_hit(self, monkeypatch):
        def routes(url):
            return FakeResponse(200, SPEC, headers={"Content-Type": "application/json"})

        made = install_fake_session(monkeypatch, routes)
        importers.discover_spec("https://api.example.com")
        assert len(made[0].urls) == 1, "one GET per location, and it stops at the first hit"

    def test_repeated_401_stops_without_guessing_credentials(self, monkeypatch):
        made = install_fake_session(
            monkeypatch, lambda url: FakeResponse(401, {"detail": "no"},
                                                  headers={"Content-Type": "application/json"}))
        res = importers.discover_spec("https://api.example.com")
        assert res["ok"] is False
        assert "auth failures" in res["error"]
        assert "no credential guessing" in res["error"]
        assert "read token" in res["hint"] and "Authorization" in res["hint"]
        assert len(made[0].urls) <= 2

    def test_429_stops_and_echoes_retry_after(self, monkeypatch):
        made = install_fake_session(
            monkeypatch, lambda url: FakeResponse(429, {"detail": "slow"},
                                                  headers={"Retry-After": "12"}))
        res = importers.discover_spec("https://api.example.com")
        assert res["ok"] is False
        assert "rate limited" in res["error"]
        assert "wait 12s" in res["hint"]
        assert len(made[0].urls) == 1

    def test_repeated_transport_failures_stop_the_sweep(self, monkeypatch):
        made = install_fake_session(
            monkeypatch,
            lambda url: requests.exceptions.ConnectionError("Connection refused"))
        res = importers.discover_spec("https://api.example.com")
        assert res["ok"] is False
        assert "could not reach" in res["error"]
        assert "VPN" in res["hint"] or "proxy" in res["hint"] or "verify_tls" in res["hint"]
        assert len(made[0].urls) <= 3

    def test_nothing_found_says_what_to_ask_for(self, monkeypatch):
        made = install_fake_session(monkeypatch, not_found)
        res = importers.discover_spec("https://api.example.com")
        assert res["ok"] is False
        assert "no spec found" in res["error"]
        assert "from_curl" in res["hint"]
        assert len(res["tried"]) == len(made[0].urls) == len(importers.SPEC_PATHS)

    def test_an_html_docs_page_is_not_mistaken_for_a_spec(self, monkeypatch):
        install_fake_session(
            monkeypatch,
            lambda url: FakeResponse(200, text="<!doctype html><html>Swagger UI</html>",
                                     headers={"Content-Type": "text/html"}))
        res = importers.discover_spec("https://api.example.com")
        assert res["ok"] is False
        assert any("neither JSON nor YAML" in (t["note"] or "") for t in res["tried"])

    def test_json_without_openapi_keys_is_rejected(self, monkeypatch):
        install_fake_session(
            monkeypatch,
            lambda url: FakeResponse(200, {"hello": "world"},
                                     headers={"Content-Type": "application/json"}))
        res = importers.discover_spec("https://api.example.com")
        assert res["ok"] is False
        assert any("no openapi/swagger/paths" in (t["note"] or "") for t in res["tried"])

    def test_ai_plugin_manifest_is_followed_once(self, monkeypatch):
        manifest_url = "https://api.example.com/.well-known/ai-plugin.json"
        real_spec_url = "https://api.example.com/spec/openapi.json"

        def routes(url):
            if url == manifest_url:
                return FakeResponse(200, {"schema_version": "v1",
                                          "api": {"type": "openapi", "url": real_spec_url}},
                                    headers={"Content-Type": "application/json"})
            if url == real_spec_url:
                return FakeResponse(200, SPEC, headers={"Content-Type": "application/json"})
            return not_found(url)

        install_fake_session(monkeypatch, routes)
        res = importers.discover_spec("https://api.example.com")
        assert res["ok"] is True
        assert res["spec_url"] == real_spec_url
        assert res["endpoints"][0]["path"] == "/chat"

    def test_a_base_url_with_a_path_probes_the_origin_too(self, monkeypatch):
        made = install_fake_session(monkeypatch, not_found)
        importers.discover_spec("https://api.example.com/api/v2")
        urls = made[0].urls
        assert "https://api.example.com/api/v2/openapi.json" in urls
        assert "https://api.example.com/openapi.json" in urls

    def test_a_direct_document_url_is_fetched_verbatim(self, monkeypatch):
        made = install_fake_session(
            monkeypatch,
            lambda url: FakeResponse(200, SPEC, headers={"Content-Type": "application/json"})
            if url == "https://api.example.com/static/api.json" else not_found(url))
        res = importers.discover_spec("https://api.example.com/static/api.json")
        assert res["ok"] is True
        assert made[0].urls[0] == "https://api.example.com/static/api.json"

    def test_caller_headers_and_tls_flag_reach_the_request(self, monkeypatch):
        seen = {}

        class Recording(FakeSession):
            def get(self, url, **kw):
                seen.update(kw)
                return super().get(url, **kw)

        monkeypatch.setattr(requests, "Session", lambda: Recording(not_found))
        importers.discover_spec("https://api.example.com",
                                headers={"Authorization": "Bearer t"},
                                timeout_s=3.0, verify_tls=False)
        assert seen["headers"]["Authorization"] == "Bearer t"
        assert seen["headers"]["User-Agent"].startswith("ascend-bridge-discovery")
        assert seen["timeout"] == 3.0
        assert seen["verify"] is False

    def test_custom_paths_override_the_probe_list(self, monkeypatch):
        made = install_fake_session(monkeypatch, not_found)
        importers.discover_spec("https://api.example.com", paths=["/custom/spec.json"])
        assert made[0].urls == ["https://api.example.com/custom/spec.json"]

    def test_rate_limit_is_honoured_between_probes(self, monkeypatch):
        waits = []
        monkeypatch.setattr(importers.time, "sleep", lambda s: waits.append(s))
        install_fake_session(monkeypatch, not_found)
        importers.discover_spec("https://api.example.com", rate_limit_qpm=60.0)
        assert len(waits) >= 1
        assert all(0 < w <= 1.0 for w in waits)

    def test_a_spec_with_no_chat_operation_hints_the_manual_route(self, monkeypatch):
        boring = {"openapi": "3.0.0",
                  "paths": {"/health": {"get": {"summary": "health", "responses": {}}}}}
        install_fake_session(
            monkeypatch,
            lambda url: FakeResponse(200, boring, headers={"Content-Type": "application/json"}))
        res = importers.discover_spec("https://api.example.com")
        assert res["ok"] is True
        assert res["endpoints"] == []
        assert "config_from_spec_endpoint" in res["hint"]


YAML_SPEC = (
    "openapi: 3.0.1\n"
    "info:\n"
    "  title: Synthetic Support Bot\n"
    "paths:\n"
    "  /chat:\n"
    "    post:\n"
    "      summary: Send a message to the assistant\n"
    "      responses:\n"
    "        '200':\n"
    "          description: ok\n"
)


class TestYamlDegradation:
    def _yaml_routes(self, url):
        if url.endswith("/openapi.yaml"):
            return FakeResponse(200, text=YAML_SPEC,
                                headers={"Content-Type": "application/yaml"})
        return not_found(url)

    def test_yaml_spec_without_pyyaml_degrades_gracefully(self, monkeypatch):
        # `import yaml` raises ImportError when sys.modules holds None for it.
        monkeypatch.setitem(sys.modules, "yaml", None)
        install_fake_session(monkeypatch, self._yaml_routes)
        res = importers.discover_spec("https://api.example.com")
        assert res["ok"] is False, "no spec, but no traceback either"
        assert "PyYAML" in res["hint"]
        assert "pip install pyyaml" in res["hint"]
        assert "convert the spec to JSON" in res["hint"]
        assert any("PyYAML" in (t["note"] or "") for t in res["tried"])

    def test_endpoints_from_spec_still_works_on_a_hand_converted_dict(self, monkeypatch):
        """The documented workaround must actually work: convert to JSON, call directly."""
        monkeypatch.setitem(sys.modules, "yaml", None)
        converted = {"openapi": "3.0.1", "paths": {"/chat": {"post": {
            "summary": "Send a message to the assistant", "responses": {}}}}}
        eps = importers.endpoints_from_spec(converted)
        assert eps[0]["path"] == "/chat"

    def test_yaml_spec_is_parsed_when_pyyaml_is_available(self, monkeypatch):
        pytest.importorskip("yaml", reason="PyYAML is an optional dependency")
        install_fake_session(monkeypatch, self._yaml_routes)
        res = importers.discover_spec("https://api.example.com")
        assert res["ok"] is True
        assert res["format"] == "yaml"
        assert res["endpoints"][0]["path"] == "/chat"


class TestModuleHygiene:
    def test_import_is_network_free(self, monkeypatch):
        """Reimporting must not construct a Session or hit the wire."""
        import importlib

        def explode(*a, **kw):  # pragma: no cover - only runs on regression
            raise AssertionError("network machinery touched at import time")

        monkeypatch.setattr(requests, "Session", explode)
        monkeypatch.setattr(requests, "get", explode)
        mod = importlib.reload(importers)
        assert mod.PROMPT_PLACEHOLDER == "{{PROMPT}}"

    def test_public_api_is_exported(self):
        for name in ("from_curl", "explain_curl", "discover_spec", "endpoints_from_spec",
                     "config_from_spec_endpoint", "configs_from_spec", "CurlParseError",
                     "PROMPT_PLACEHOLDER", "BENIGN_PROMPT", "SPEC_PATHS"):
            assert name in importers.__all__
            assert hasattr(importers, name)

    def test_the_benign_prompt_is_benign(self):
        prompt = importers.BENIGN_PROMPT
        assert prompt == "Hello, what can you help me with?"
        for banned in ("ignore", "system prompt", "DAN", "<script", "'; --"):
            assert banned not in prompt.lower()
