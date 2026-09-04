"""
test_auth_error_not_sent_naked.py — a probe whose credential could not be obtained is refused,
not sent without one.

`dispatch.merge_auth` never raises. When an `auth` block cannot be materialized — the token
endpoint is down, an `env:` ref is unset, a mid-run re-mint 401s — it records `_auth_error` on the
merged config and returns the config otherwise UNAUTHENTICATED. Exactly one caller ever read that
field: `discovery/validate.py`, the one-shot hard gate. The live relay (`call_target.TargetCaller`)
did not.

So a credential that died mid-run sent every remaining probe with no credential at all. The target
refused them; refusals are not findings; the assessment finished looking clean having measured
nothing. That is the failure this tool exists to prevent, produced by the tool.
"""
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
for p in ("runtime", "control"):
    sys.path.insert(0, str(REPO / p))
import call_target as CT  # noqa: E402


def _caller(monkeypatch, merged_configs):
    """A TargetCaller whose merge_auth returns the given configs in order."""
    seq = list(merged_configs)
    monkeypatch.setattr(CT, "merge_auth", lambda cfg, **kw: seq.pop(0) if len(seq) > 1 else seq[0])
    sent = []
    tc = CT.TargetCaller("direct_api", "inline", {"adapter": "direct_api", "url": "https://x/chat",
                                                   "auth": {"type": "oauth2", "token_url": "https://idp"}})
    tc._send_once = lambda prompt, conv: (sent.append(prompt) or (200, {"response": "ok"}))
    return tc, sent


class TestAnUnmaterializedCredentialIsNotSentNaked:
    def test_auth_error_on_the_config_refuses_the_probe(self, monkeypatch):
        tc, sent = _caller(monkeypatch, [{"adapter": "direct_api", "url": "https://x/chat",
                                          "_auth_error": "environment variable 'CID' is not set"}])
        status, out = tc.handler({"payload": {"body": {"prompt": "hi"}}})
        assert status == 401 and "auth:" in out["_error"], out
        assert sent == [], "the probe was sent to the target with no credential"

    def test_a_healthy_config_still_sends(self, monkeypatch):
        tc, sent = _caller(monkeypatch, [{"adapter": "direct_api", "url": "https://x/chat",
                                          "headers": {"Authorization": "Bearer t"}}])
        status, out = tc.handler({"payload": {"body": {"prompt": "hi"}}})
        assert status == 200 and sent == ["hi"]

    def test_a_failed_reacquire_does_not_retry_naked(self, monkeypatch):
        """First send 401s; re-auth runs; if THAT fails the retry must not go out unauthenticated."""
        good = {"adapter": "direct_api", "url": "https://x/chat", "headers": {"Authorization": "Bearer t"},
                "auth_lifecycle": {"type": "reauth_on_401"}}
        broken = {**good, "_auth_error": "oauth2 token request failed: HTTP 503"}
        seq = [good, broken]
        monkeypatch.setattr(CT, "merge_auth", lambda cfg, **kw: seq.pop(0) if len(seq) > 1 else seq[0])
        tc = CT.TargetCaller("direct_api", "inline", {**good, "auth": {"type": "oauth2", "token_url": "x"}})
        calls = []
        def send(prompt, conv):
            calls.append(prompt)
            return (401, {"response": ""}) if len(calls) == 1 else (200, {"response": "leaked"})
        tc._send_once = send
        status, out = tc.handler({"payload": {"body": {"prompt": "hi"}}})
        assert len(calls) == 1, "a second, unauthenticated send went to the target"
        assert status == 401 and "re-acquire failed" in out["_error"]

    def test_the_relay_path_reads_the_field_the_validator_already_did(self):
        src = (REPO / "runtime" / "call_target.py").read_text()
        assert src.count('get("_auth_error")') >= 2, (
            "call_target must check _auth_error before the first send AND after a re-auth")
