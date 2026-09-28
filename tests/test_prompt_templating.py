"""
test_prompt_templating.py — the prompt must be templated, not frozen.

This locks down a FALSE PASS, which is the worst outcome the tool can produce: a config that
validates green while measuring nothing.

A GraphQL body looks like
`{"query": "<graphql document>", "variables": {"input": {"message": "<the real question>"}}}`.
`query` is in `_PROMPT_FIELDS` (plenty of REST bots do call their field that), and
`_request_has_prompt` returned the FIRST field-name match at the top level -- so it returned the
GraphQL *document*. `_body_template` then replaced the document with `{{PROMPT}}` and left the
real question sitting in `variables` as a literal.

The consequence: `target add` reported
`validated: true` and a real on-topic answer, and re-deriving with a completely different
`--prompt` produced the *same* answer to the capture-time question. Every probe in an assessment
would have scored the reply to "what is the status of order AC-10482273?" no matter what the
control actually asked. Nothing looks wrong anywhere.

Two independent guards, because either can be absent:
  1. ground truth -- when `--prompt` was supplied, an exact match anywhere in the body wins over
     field-name order outright;
  2. a GraphQL-document check on `query`, for a HAR imported with no `--prompt`.

The fallback matters as much as the guard. The first fix skipped the document in the field loop
and then handed it straight back from the `_longest_string` fallback, so the guard fired and was
immediately undone -- which is why there is an explicit test for the no-ground-truth path.
"""
import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "runtime"))
from discovery import classify as C     # noqa: E402

PROMPT = "What is the status of order AC-10482273?"
GQL_DOC = "mutation SendMessage($input: MsgInput!) { sendMessage(input: $input) { reply } }"
GQL_BODY = {"query": GQL_DOC, "variables": {"input": {"message": PROMPT, "channel": "web"}}}


@pytest.fixture(autouse=True)
def _clear_ground_truth():
    """`_PROMPT_SENT` is module state; a leaked value would make these tests lie to each other."""
    before = C._PROMPT_SENT.get("v")
    C._PROMPT_SENT["v"] = None
    yield
    C._PROMPT_SENT["v"] = before


class TestGraphqlPromptIsNotFrozen:
    @pytest.mark.parametrize("ground_truth", [PROMPT, None],
                             ids=["with --prompt", "without --prompt"])
    def test_the_question_is_templated_and_the_document_is_not(self, ground_truth):
        C._PROMPT_SENT["v"] = ground_truth
        tpl = C._body_template({"json": GQL_BODY})
        assert tpl["variables"]["input"]["message"] == "{{PROMPT}}", \
            "the real question was frozen — every probe would re-ask the captured one"
        assert "{{PROMPT}}" not in tpl["query"], "the GraphQL operation was templated away"
        assert tpl["query"] == GQL_DOC, "the operation must survive verbatim"

    @pytest.mark.parametrize("ground_truth", [PROMPT, None],
                             ids=["with --prompt", "without --prompt"])
    def test_the_captured_question_does_not_survive_anywhere(self, ground_truth):
        """The strongest form: the capture-time text must not appear in the template at all."""
        C._PROMPT_SENT["v"] = ground_truth
        assert PROMPT not in json.dumps(C._body_template({"json": GQL_BODY}))

    def test_sibling_fields_are_preserved(self):
        tpl = C._body_template({"json": GQL_BODY})
        assert tpl["variables"]["input"]["channel"] == "web"


class TestOrdinaryBodiesAreUnaffected:
    def test_a_rest_bot_that_really_uses_query(self):
        """`query` is a legitimate prompt field name; only a GraphQL document is excluded."""
        tpl = C._body_template({"json": {"query": "where is my order?", "lang": "en"}})
        assert tpl["query"] == "{{PROMPT}}"
        assert tpl["lang"] == "en"

    @pytest.mark.parametrize("field", ["prompt", "message", "input", "text", "question", "msg"])
    def test_every_top_level_prompt_field(self, field):
        tpl = C._body_template({"json": {field: PROMPT, "channel": "web"}})
        assert tpl[field] == "{{PROMPT}}"

    def test_a_nested_dto_wrapper(self):
        """A prompt one or more levels down is found without needing ground truth."""
        tpl = C._body_template({"json": {"payload": {"data": {"text": PROMPT}}}})
        assert tpl["payload"]["data"]["text"] == "{{PROMPT}}"

    def test_a_bare_string_body(self):
        assert C._body_template({"json": "just the prompt"}) == "{{PROMPT}}"

    def test_ground_truth_wins_over_field_order(self):
        """Two prompt-named fields: the one the operator actually sent is the prompt."""
        C._PROMPT_SENT["v"] = PROMPT
        body = {"prompt": "you are a helpful assistant", "message": PROMPT}
        tpl = C._body_template({"json": body})
        assert tpl["message"] == "{{PROMPT}}"
        assert tpl["prompt"] == "you are a helpful assistant", \
            "a system-prompt field was mistaken for the question"


class TestGraphqlDocDetection:
    @pytest.mark.parametrize("doc", [
        "mutation SendMessage($i: In!) { send(input: $i) { reply } }",
        "query GetReply($q: String!) { reply(q: $q) }",
        "subscription OnReply { replyAdded { text } }",
        "  \n  mutation M { x { y } }",
    ])
    def test_documents_are_recognised(self, doc):
        assert C._looks_like_graphql_doc(doc) is True

    @pytest.mark.parametrize("text", [
        "where is my order?",
        "query the database for me please",          # starts with the word, but is prose
        "",
        "AC-10482273",
    ])
    def test_prose_is_not_a_document(self, text):
        assert C._looks_like_graphql_doc(text) is False
