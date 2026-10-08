"""
test_captured_credentials.py — the credential a capture SEES must reach the target.

THE BUG. `test_secret_headers.py` (beside this file) proves a captured credential never lands in
a config on disk. It does, and that half was right. What nobody tested is the other half: that
the target can still authenticate afterwards. It could not. `_nonsecret_headers` dropped the
value, `dropped_secret_headers` recorded the NAME, and `classify_auth` wrote
`"value_ref": "env:DISCOVERED_TOKEN"` — a variable that, on a repo-wide grep, is set by nothing,
anywhere, ever. So the capture watched a signed-in human, held the exact header the target
requires, wrote a reference to a variable that does not exist, and discarded the value.

Every target behind any authentication was therefore registered in a state where it could not
answer. MEASURED on a real run: **10 probes leased, 10 delivered, 0 answered**, with
`"_withheld_headers": ["X-Window-Token"]` in the config and the endpoint rejecting every request
for a header nobody had put back. The operator was told to go and find it in DevTools by hand.

Both halves hold now, and both are asserted here, because fixing either one alone is a
regression in the other:

  * the value is in the tenant-scoped 0600 store and NOT in the config, not in `layers`, and not
    in anything a `--json` dump or a support bundle would print;
  * and the header that reaches the target is **byte-identical to the one the browser sent**.

That second assertion is the point of the whole file. A test that only checks "an auth block was
emitted" passes against a block referencing a variable nobody sets — which is precisely the bug
that shipped.

Run:  python3 -m pytest tests/test_captured_credentials.py -q
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
from layers import auth as A                 # noqa: E402
import dispatch                              # noqa: E402

# A real signed-in session presents several of these at once, which is why every existing auth
# mode — each carrying exactly one secret — was unusable for a capture.
TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.aaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbb"
WINDOW = "wt_9f2c41d07b3e5a8c1290ffee"
COOKIE = "sid=abc123def456; path=/"


def _har(headers, url="https://bot.example.com/api/chat"):
    return {"log": {"version": "1.2", "entries": [{
        "startedDateTime": "2026-09-03T00:00:00.000Z", "time": 5,
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


def _classify(headers, url="https://bot.example.com/api/chat"):
    # `har_to_evidence` takes the parsed HAR, the way the rest of the discovery tests drive it.
    return C.classify_evidence(C.har_to_evidence(_har(headers, url)))


@pytest.fixture
def store(tmp_path, monkeypatch):
    """A private credential store, so a test never reads or writes the real one."""
    monkeypatch.setenv("ASCEND_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("ASCEND_HOME", str(tmp_path / "home"))
    for name in list(os.environ):
        if name.startswith("ASCEND_SECRET_"):
            monkeypatch.delenv(name, raising=False)
    return tmp_path


# --------------------------------------------------------------------------- #
# The capture keeps what it saw                                               #
# --------------------------------------------------------------------------- #
class TestTheValueSurvivesTheCapture:
    def test_a_custom_credential_header_is_captured_not_discarded(self, store):
        """THE regression, in the exact shape it was measured: `X-Window-Token`."""
        res = _classify({"Content-Type": "application/json", "X-Window-Token": WINDOW})
        assert res["secrets"], ("the capture discarded the credential — this is the bug that "
                                "produced 10 delivered / 0 answered")
        assert WINDOW in res["secrets"].values()

    def test_several_credentials_at_once(self, store):
        """A signed-in session presents a bearer AND a cookie AND a tenant token. Every existing
        auth mode carries exactly one secret, so keeping only one is the same outage."""
        res = _classify({"Content-Type": "application/json", "Authorization": f"Bearer {TOKEN}",
                         "Cookie": COOKIE, "X-Window-Token": WINDOW})
        got = set(res["secrets"].values())
        for expected in (f"Bearer {TOKEN}", COOKIE, WINDOW):
            assert expected in got, f"{expected[:24]}… was dropped; a partial credential is none"

    def test_the_variable_name_is_specific_to_the_target(self, store):
        """`env:DISCOVERED_TOKEN` was the same string for every target anyone ever captured, so
        two targets in one shell would have overwritten each other's credential."""
        a = _classify({"X-Window-Token": WINDOW}, url="https://one.example.com/api/chat")
        b = _classify({"X-Window-Token": WINDOW}, url="https://two.example.com/api/chat")
        assert set(a["secrets"]) != set(b["secrets"]), "two targets share one variable name"
        assert not any("DISCOVERED_TOKEN" in n for n in a["secrets"]), \
            "still emitting the variable that nothing sets"


# --------------------------------------------------------------------------- #
# ...and still never writes it down                                           #
# --------------------------------------------------------------------------- #
class TestTheValueStillNeverReachesDisk:
    @pytest.mark.parametrize("header,value", [
        ("X-Window-Token", WINDOW), ("Authorization", f"Bearer {TOKEN}"), ("Cookie", COOKIE)])
    def test_not_in_the_config(self, store, header, value):
        res = _classify({"Content-Type": "application/json", header: value})
        assert value not in json.dumps(res["config"]), \
            f"{header} was baked into the config — the fix traded one bug for a worse one"

    def test_not_reachable_through_the_layers_either(self, store):
        """The leak that a `--json` dump or a support bundle would have printed. `layers` is
        returned to the caller and is the natural thing to attach to a ticket."""
        res = _classify({"X-Window-Token": WINDOW})
        assert WINDOW not in json.dumps(res["layers"]), \
            "the credential is reachable at layers.transport.params — that ends up in a ticket"

    def test_the_config_holds_a_reference_instead(self, store):
        res = _classify({"X-Window-Token": WINDOW})
        block = res["config"].get("auth") or {}
        assert block.get("type") == "static" and block.get("mode") == "headers", block
        assert list(block["headers"]) == ["X-Window-Token"]
        assert block["headers"]["X-Window-Token"].startswith("env:"), block

    def test_the_store_file_is_private(self, store):
        res = _classify({"X-Window-Token": WINDOW})
        name = next(iter(res["secrets"]))
        TS.record(name, WINDOW, host="bot.example.com", header="X-Window-Token")
        assert TS.store_path().stat().st_mode & 0o077 == 0, "the credential store is readable"


# --------------------------------------------------------------------------- #
# The header actually reaches the target — the point of all of it             #
# --------------------------------------------------------------------------- #
class TestTheTargetReceivesIt:
    def test_the_wire_header_is_what_the_browser_sent(self, store):
        """END TO END. Capture -> store -> `merge_auth` -> the headers an adapter will send.

        `dispatch.merge_auth` is the one seam both `validate_config` and the live relay go
        through, so proving it here proves the gate and the run agree — which is the other half
        of the same class of bug ("validate=ok and every probe 401s")."""
        res = _classify({"Content-Type": "application/json", "Authorization": f"Bearer {TOKEN}",
                         "X-Window-Token": WINDOW})
        for name, value in res["secrets"].items():
            TS.record(name, value, host="bot.example.com")

        wire = dispatch.merge_auth(dict(res["config"])).get("headers") or {}
        assert wire.get("X-Window-Token") == WINDOW, \
            f"the target would not receive the token it requires: {wire!r}"
        assert wire.get("Authorization") == f"Bearer {TOKEN}", \
            "the bearer was rebuilt wrongly — the captured header is replayed verbatim"
        assert wire.get("Content-Type") == "application/json", "an ordinary header was lost"

    def test_it_works_from_a_process_with_no_environment(self, store):
        """The relay is started later, by a different command. An environment variable exported
        in the capture's shell reaches none of it, so the store is what makes this work at all."""
        res = _classify({"X-Window-Token": WINDOW})
        name, value = next(iter(res["secrets"].items()))
        TS.record(name, value, host="bot.example.com")
        assert name not in os.environ, "the fixture failed to clear the environment"
        assert A.resolve_secret_ref(f"env:{name}") == WINDOW

    def test_the_environment_still_wins_over_the_store(self, store, monkeypatch):
        """So an operator can override a stale captured credential for one run without editing
        anything — the store is a fallback, not an override."""
        res = _classify({"X-Window-Token": WINDOW})
        name = next(iter(res["secrets"]))
        TS.record(name, "the-stale-captured-one", host="bot.example.com")
        monkeypatch.setenv(name, "the-fresh-one")
        assert A.resolve_secret_ref(f"env:{name}") == "the-fresh-one"

    def test_a_missing_credential_says_so_usefully(self, store):
        res = _classify({"X-Window-Token": WINDOW})
        name = next(iter(res["secrets"]))
        with pytest.raises(A.AuthError) as exc:
            A.resolve_secret_ref(f"env:{name}")          # never stored
        assert "expired" in str(exc.value) or "credential store" in str(exc.value), str(exc.value)

    def test_the_gate_reports_a_missing_credential_rather_than_passing(self, store):
        """`merge_auth` annotates instead of raising, and `validate_config` turns that into a
        refusal. A capture whose credential went missing must fail the wire-time gate, not
        register a target that 401s for the next hour."""
        res = _classify({"X-Window-Token": WINDOW})
        merged = dispatch.merge_auth(dict(res["config"]))
        assert merged.get("_auth_error"), "a config with no resolvable credential looked healthy"


# --------------------------------------------------------------------------- #
# What must NOT be replaced                                                   #
# --------------------------------------------------------------------------- #
class TestALiveMechanismIsLeftAlone:
    def test_oauth2_is_not_downgraded_to_a_frozen_header(self, store):
        """oauth2 / csrf / derived_multihop re-acquire credentials during a run. Replacing one
        with a captured header trades a working mechanism for an expiring one."""
        block = {"type": "oauth2", "grant": "client_credentials",
                 "token_url": "https://id.example.com/token"}
        cfg = C.compose({"layers": {
            "transport": {"value": "rest_json", "confidence": 0.9, "params": {
                "endpoint": "https://bot.example.com/api/chat", "method": "POST",
                "headers": {"Content-Type": "application/json"},
                "body": {"message": "{{PROMPT}}"},
                "withheld_headers": ["X-Window-Token"],
                "secret_header_values": {"X-Window-Token": WINDOW},
                "secret_header_url": "https://bot.example.com/api/chat"}},
            "auth": {"value": "oauth2", "confidence": 0.9, "params": block},
            "auth_lifecycle": {"value": "refresh_on_ttl", "confidence": 0.9, "params": {}},
            "session": {"value": "stateless", "confidence": 0.9, "params": {}},
            "identity": {"value": "fixed", "confidence": 0.9, "params": {}},
            "rate": {"value": "default", "confidence": 0.9, "params": {}}}})
        assert cfg["auth"]["type"] == "oauth2", "a live re-auth mechanism was overwritten"
        assert cfg.get("_captured_credentials_unused"), \
            "the extra headers were dropped with no explanation anywhere"
