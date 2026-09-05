"""
test_derive_session_flow.py — a create-then-message target derives from its URL alone.

`ascend target add http://host` against a bot that requires POST /session before POST
/session/{id}/message used to fail with `bad_shape`. The prober found /session, got a real 2xx,
and gave up — while the diagnosis text ALREADY named the contract exactly ("that is what a
create-then-message contract looks like") and then told the operator to go export a HAR.

Measured cost of not following it: in a 22-agent trial this was the only scenario where using the
CLI still required writing code. One operator captured a HAR by hand; another hand-wrote an
adapter module. It was also the only scenario where the CLI's advantage over the raw API
disappeared.

The second call is one request and the id is right there, so the prober makes it. What it must
NOT do is bake that id into the endpoint: that validates green and then runs every probe of the
assessment through a single conversation, which a turn cap or an expiry silently breaks.
"""
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
for p in ("shells/cli", "runtime", "control"):
    if str(REPO / p) not in sys.path:
        sys.path.insert(0, str(REPO / p))
from discovery import probe as P  # noqa: E402


class TestIdExtraction:
    def test_finds_a_session_id(self):
        assert P._session_id_from('{"session_id":"abc","other":1}') == "abc"

    def test_finds_a_conversation_id(self):
        assert P._session_id_from('{"conversation_id":"c1"}') == "c1"

    def test_falls_back_to_bare_id(self):
        assert P._session_id_from('{"id":"z9"}') == "z9"

    def test_ignores_a_body_with_no_id(self):
        assert P._session_id_from('{"reply":"hello"}') is None

    def test_survives_a_non_json_body(self):
        assert P._session_id_from("<html>nope</html>") is None
        assert P._session_id_from(None) is None

    def test_names_the_field_the_id_came_from(self):
        assert P._session_id_field('{"session_id":"abc"}', "abc") == "session_id"
        assert P._session_id_field('{"threadId":"t1"}', "t1") == "threadId"


class TestConfigShape:
    def _result(self):
        r = P.ProbeResult()
        r.endpoint = "http://h:1/session/SID123/message"
        r.method, r.transport = "POST", "rest_json"
        r.request_body = {"message": "{{PROMPT}}"}
        r.response_path, r.response_text = "reply", "hi there"
        r.session_flow = {
            "session_endpoint": "http://h:1/session",
            "session_body": {},
            "session_extract": "session_id",
            "message_endpoint": "http://h:1/session/{{SESSION_ID}}/message",
        }
        return r

    def test_it_emits_the_session_adapter(self):
        cfg = P.build_config(self._result())
        assert cfg["adapter"] == "session_api"

    def test_the_session_id_is_a_template_not_a_value(self):
        cfg = P.build_config(self._result())
        assert "{{SESSION_ID}}" in cfg["message_endpoint"]
        assert "SID123" not in json.dumps(cfg), (
            "baking the id in runs every probe through one conversation")

    def test_it_carries_what_the_adapter_needs(self):
        cfg = P.build_config(self._result())
        for k in ("session_endpoint", "message_endpoint", "session_extract", "response_path"):
            assert cfg.get(k), f"session_api requires {k}"

    def test_a_single_shot_target_is_untouched(self):
        r = P.ProbeResult()
        r.endpoint, r.method, r.transport = "http://h:1/chat", "POST", "rest_json"
        r.request_body = {"message": "{{PROMPT}}"}
        r.response_path, r.response_text = "reply", "hi"
        cfg = P.build_config(r)
        assert cfg["adapter"] != "session_api"
        assert cfg["endpoint"] == "http://h:1/chat"


def test_the_prober_actually_follows_the_create():
    """Source discipline: the helper existing is not the fix; being called is."""
    import inspect
    src = inspect.getsource(P.probe_api)
    assert "_follow_create_then_message(state, shapes)" in src
    assert "session_flow" in src, "the flow must be recorded, not just the winning URL"


class TestThreePlacements:
    """The wild puts the session id in three places. A prober that knows one finds one."""

    def _res(self, endpoint, flow):
        r = P.ProbeResult()
        r.endpoint, r.method, r.transport = endpoint, "POST", "rest_json"
        r.request_body = {"message": "{{PROMPT}}"}
        r.response_path, r.response_text = "reply", "hi"
        r.session_flow = flow
        return r

    def test_body_placement_templates_the_id_in_the_body(self):
        cfg = P.build_config(self._res("http://h:1/messages", {
            "session_endpoint": "http://h:1/conversation", "session_body": {},
            "session_extract": "conversation_id", "message_endpoint": "http://h:1/messages",
            "message_body": {"message": "{{PROMPT}}", "conversation_id": "{{SESSION_ID}}"}}))
        assert cfg["adapter"] == "session_api"
        assert cfg["message_body"]["conversation_id"] == "{{SESSION_ID}}"
        assert "{{SESSION_ID}}" not in cfg["message_endpoint"], "body placement: id is not in the URL"

    def test_both_placement_templates_url_and_body(self):
        cfg = P.build_config(self._res("http://h:1/threads/T/messages", {
            "session_endpoint": "http://h:1/threads", "session_body": {},
            "session_extract": "thread_id",
            "message_endpoint": "http://h:1/threads/{{SESSION_ID}}/messages",
            "message_body": {"message": "{{PROMPT}}", "thread_id": "{{SESSION_ID}}"}}))
        assert "{{SESSION_ID}}" in cfg["message_endpoint"]
        assert cfg["message_body"]["thread_id"] == "{{SESSION_ID}}"

    def test_with_id_in_body_adds_the_field_and_keeps_the_prompt(self):
        sh = P.Shape(label="message", body={"message": "{{PROMPT}}"})
        got = P._with_id_in_body(sh, "conversation_id", "abc")
        assert got.body == {"message": "{{PROMPT}}", "conversation_id": "abc"}
        assert got.label == "message+conversation_id"

    def test_with_id_in_body_refuses_a_non_dict_shape(self):
        sh = P.Shape(label="raw_text", raw="{{PROMPT}}")
        assert P._with_id_in_body(sh, "conversation_id", "abc") is None

    def test_a_proven_sibling_path_is_tried_before_guessing(self):
        """A 400 on /messages during the blind search means the path is real and wanted the id."""
        import inspect
        src = inspect.getsource(P._follow_create_then_message)
        assert "(400, 405, 415, 422)" in src
        assert src.index("exists") < src.index("_MESSAGE_SUFFIXES]"), (
            "proven-real siblings must come before the guessed suffixes")
