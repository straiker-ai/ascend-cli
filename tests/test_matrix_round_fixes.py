"""
test_matrix_round_fixes.py — four derivation gaps the live matrix exposed once it covered every shape.

The first full-coverage run scored 17/24. Two of the misses were stale expectations; five were
real, and four of those are fixed here. Each was found by a forge shape a real customer API
resembles, and each is pinned at the seam that failed rather than end to end, because the live
matrix already covers end to end.
"""
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
for p in ("shells/cli", "runtime", "control", "runtime/adapters"):
    if str(REPO / p) not in sys.path:
        sys.path.insert(0, str(REPO / p))
from discovery import probe as P  # noqa: E402
from adapters.direct_api import _extract  # noqa: E402


class TestEnvelopeDecode:
    """`envelope`: the reply is a JSON document encoded as a string. Accepting the string as the
    answer validated green on a blob and scored every probe against the encoding."""

    def test_extract_walks_through_a_json_string(self):
        d = {"schema": "v2", "envelope": json.dumps({"result": {"reply": "hi there"}})}
        assert _extract(d, "envelope~json.result.reply") == "hi there"

    def test_extract_tolerates_a_non_json_string(self):
        assert _extract({"envelope": "not json"}, "envelope~json.result") is None

    def test_plain_paths_are_untouched(self):
        assert _extract({"reply": "ok"}, "reply") == "ok"
        assert _extract({"content": [{"text": "a"}, {"text": "b"}]}, "content.*.text") == "ab"

    def test_understand_response_descends_into_the_envelope(self):
        body = json.dumps({"schema": "acme.v2",
                           "envelope": json.dumps({"result": {"reply": "Hello! I am Anna from AcmeShop, "
                                                                        "how can I help you with your order today?"}})})
        _t, path, answer, _h, _r = P._understand_response(body, "application/json", "what is my order?")
        assert path == "envelope~json.result.reply", path
        assert answer.startswith("Hello! I am Anna")


class TestFormHint:
    """`form`: the target said exactly what it wanted -- `hint: message=<text>&channel=web` --
    and an unquoted `channel is required`. Both were invisible to the quoted-field patterns."""

    def test_a_form_body_hint_becomes_the_first_shape(self):
        body = '{"error": "channel is required", "hint": "message=<text>&channel=web"}'
        shapes = P._shapes_from_error(body, json.loads(body))
        assert shapes, "the server handed over its contract; use it"
        first = shapes[0]
        assert first.label == "hint_form"
        assert first.body == {"message": P.PROMPT_TOKEN, "channel": "web"}
        assert first.content_type == "application/x-www-form-urlencoded"

    def test_an_unquoted_required_field_is_read(self):
        body = '{"error": "question is required"}'
        shapes = P._shapes_from_error(body, json.loads(body))
        assert any(s.body == {"question": P.PROMPT_TOKEN} for s in shapes)

    def test_a_quoted_field_still_works(self):
        body = "field required: 'query'"
        shapes = P._shapes_from_error(body, None)
        assert any(s.body == {"query": P.PROMPT_TOKEN} for s in shapes)


class TestGreetingGate:
    """`widget`: a session that 409s any first question until greeted. A customer types "hi"
    without thinking; the prober does too, and records it so the adapter does as well."""

    def test_build_config_carries_the_greeting(self):
        r = P.ProbeResult()
        r.endpoint, r.method, r.transport = "http://h/api/chat/v1/sessions/S/turns", "POST", "rest_json"
        r.request_body = {"text": "{{PROMPT}}"}
        r.response_path, r.response_text = "text", "hi"
        r.session_flow = {"session_endpoint": "http://h/api/chat/v1/sessions", "session_body": {},
                          "session_extract": "sessionId",
                          "message_endpoint": "http://h/api/chat/v1/sessions/{{SESSION_ID}}/turns",
                          "session_greeting": "hello"}
        cfg = P.build_config(r)
        assert cfg["adapter"] == "session_api" and cfg["session_greeting"] == "hello"

    def test_nested_create_paths_are_candidates(self):
        assert "api/chat/v1/sessions" in P.CANDIDATE_PATHS
        assert "api/v1/conversations" in P.CANDIDATE_PATHS

    def test_the_follow_up_greets_on_a_409(self):
        import inspect
        src = inspect.getsource(P._follow_create_then_message)
        assert 'att.status == 409 and "greet" in' in src
        assert "_greet_then(" in src


class TestCurlDerivesResponsePath:
    """`graphql` via curl: the request was described, the reply was never read, so the adapter
    fell back to 'deepest string' -- a __typename -- and the constant guard refused a healthy
    target. One replay derives the path."""

    def test_the_curl_branch_replays_when_no_path_is_known(self):
        import inspect, ascend
        src = inspect.getsource(ascend.cmd_onboard)
        assert "_response_path_from_replay(cfg, args)" in src
        assert src.index("from_curl(text") < src.index("_response_path_from_replay(cfg, args)")

    def test_the_helper_reads_the_reply_with_the_probe(self):
        import inspect, ascend
        src = inspect.getsource(ascend._response_path_from_replay)
        assert "_understand_response(" in src
        assert "return path if (path and answer) else None" in src


class TestCandidateOrderRespectsTheBudget:
    """The blind search tries candidate paths in order until its attempt budget runs out; anything
    past the budget is never tried. Adding five nested create paths ABOVE `session` pushed the single
    most common create path from index 19 to 24 and it stopped deriving -- on this very branch. The
    live matrix caught it; this pins it. Common nouns first, always."""

    def test_every_candidate_path_is_inside_the_sweep(self):
        """The sweep cap is derived from the candidate count, so a new path can never be added
        past the point where it is tried. This is the invariant that failed twice in one day."""
        import inspect
        src = inspect.getsource(P.probe_api)
        assert "min(_n_paths, max_attempts - 24)" in src, "the sweep is sized to the candidate list"
        assert "max_attempts: int = 64" in src
        assert len(P.CANDIDATE_PATHS) <= 64 - 24, "candidate list outgrew the default budget"

    def test_the_common_create_nouns_come_first(self):
        cp = list(P.CANDIDATE_PATHS)
        for noun in ("chat", "message", "conversations", "conversation", "sessions", "session"):
            assert cp.index(noun) < 20, f"{noun!r} at {cp.index(noun)}: common nouns lead the list"

    def test_nested_variants_come_after_their_plain_nouns(self):
        cp = list(P.CANDIDATE_PATHS)
        assert cp.index("session") < cp.index("api/chat/v1/sessions")
        assert cp.index("conversation") < cp.index("api/v1/conversations")
