"""
test_loop2_answer_paths.py — the answer path on a target that returns the whole conversation.

Loop iteration 2, against `agent-forge --shape graphql`: the derived path landed on a GraphQL
`__typename` ("SendMessagePayload"), which the constant-response guard refused — the safety net
held, but the target could not be onboarded by following the CLI's own advice. Two general gaps
behind it, neither GraphQL-specific:

  * `__typename` was an eligible answer leaf. Its value is a type name, never an answer.
  * A role-tagged transcript (`messages[]` with `role`) had no way to say "the last turn". The
    deriver picked one index by length, so it could select the probe's OWN echoed prompt, and the
    block-index rule then concatenated the echo onto the reply.
"""
import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
for p in ("runtime", "shells/cli", "control"):
    if str(REPO / p) not in sys.path:
        sys.path.insert(0, str(REPO / p))
classify = pytest.importorskip("discovery.classify")
from adapters.direct_api import _extract  # noqa: E402

GRAPHQL = json.loads('''{"data": {"sendMessage": {"__typename": "SendMessagePayload",
  "conversationId": "03d7bb57d68346f5b1c9932a912595ec",
  "messages": [{"__typename": "Message", "role": "user", "content": "{'message': 'Say pong.'}"},
               {"__typename": "Message", "role": "assistant",
                "content": "Pong! How can I help you with your AcmeShop order today?"}]}},
  "extensions": {"traceId": "b1f58d870c424786"}}''')

GATEWAY = {"data": {"result": {"messages": [
    {"role": "user", "content": "hi"},
    {"role": "assistant", "content": "Hello, how can I help with your order?"}]}}}

THREE_TURN = {"messages": [{"role": "system", "content": "You are Anna"},
                           {"role": "user", "content": "hi"},
                           {"role": "assistant", "content": "Hi! I can help with orders."}]}

BLOCKS = {"content": [{"type": "text", "text": "How can"}, {"type": "text", "text": " I help?"}]}
CHOICES = {"choices": [{"message": {"role": "assistant", "content": "First completion here"}},
                       {"message": {"role": "assistant", "content": "Second"}}]}


def derived(body):
    p = classify._guess_response_path(body)
    return p, _extract(body, p)


class TestATranscriptResolvesToTheLastAssistantTurn:
    @pytest.mark.parametrize("body,want", [(GRAPHQL, "Pong!"), (GATEWAY, "Hello,"), (THREE_TURN, "Hi! I can")])
    def test_the_answer_is_the_reply_alone(self, body, want):
        path, value = derived(body)
        assert isinstance(value, str) and value.strip().startswith(want), (path, value)

    def test_the_echoed_prompt_is_not_part_of_the_answer(self):
        _, value = derived(GRAPHQL)
        assert "Say pong." not in value, "the probe's own prompt was scored as the agent's reply"

    def test_a_transcript_is_never_wildcarded(self):
        for body in (GRAPHQL, GATEWAY, THREE_TURN):
            assert "*" not in classify._guess_response_path(body)

    def test_typename_is_never_the_answer(self):
        path, value = derived(GRAPHQL)
        assert "typename" not in path.lower() and "SendMessagePayload" not in str(value)


class TestTheOtherShapesAreUnchanged:
    def test_content_blocks_still_join(self):
        path, value = derived(BLOCKS)
        assert path == "content.*.text" and value == "How can I help?"

    def test_alternative_completions_keep_one_index(self):
        path, value = derived(CHOICES)
        assert path == "choices.0.message.content" and value == "First completion here"


class TestNegativeIndexPaths:
    def test_minus_one_is_the_last_element(self):
        assert _extract(GATEWAY, "data.result.messages.-1.content").startswith("Hello,")
        assert _extract(THREE_TURN, "messages.-1.content").startswith("Hi!")

    def test_minus_two_counts_back(self):
        assert _extract(THREE_TURN, "messages.-2.content") == "hi"

    def test_out_of_range_is_none_not_a_crash(self):
        assert _extract(GATEWAY, "data.result.messages.-9.content") is None

    def test_a_positive_index_still_works(self):
        assert _extract(THREE_TURN, "messages.0.content") == "You are Anna"


class TestPreferLastTurnIsConservative:
    def test_a_list_without_roles_is_left_alone(self):
        body = {"items": [{"text": "one"}, {"text": "two and a longer one"}]}
        assert classify._prefer_last_turn(body, "items.1.text") == "items.1.text"

    def test_a_single_element_list_is_left_alone(self):
        body = {"messages": [{"role": "assistant", "content": "only"}]}
        assert classify._prefer_last_turn(body, "messages.0.content") == "messages.0.content"

    def test_a_path_with_no_index_is_returned_unchanged(self):
        assert classify._prefer_last_turn(GATEWAY, "data.result.reply") == "data.result.reply"

    def test_a_transcript_with_no_assistant_turn_is_left_alone(self):
        body = {"messages": [{"role": "user", "content": "a"}, {"role": "user", "content": "b"}]}
        assert classify._prefer_last_turn(body, "messages.1.content") == "messages.1.content"
