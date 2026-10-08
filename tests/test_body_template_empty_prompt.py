"""A recorded create call with an empty message must not blow up the HAR contract derivation."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from runtime.discovery import classify as C  # noqa: E402


def test_empty_prompt_body_is_kept_verbatim():
    req = {"json": {"message": ""}, "headers": {}, "body": '{"message": ""}'}
    assert C._body_template(req) == {"message": ""}


def test_real_prompt_is_templated():
    req = {"json": {"message": "hello there"}, "headers": {}, "body": '{"message": "hello there"}'}
    assert C._body_template(req) == {"message": "{{PROMPT}}"}
