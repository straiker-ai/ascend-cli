"""
test_assess_run_waits.py — `assess run` must never exit 0 on a run that has not finished.

Observed live, repeatedly: the platform truncates the create-assessment response often enough that
the CLI's recovery path is the COMMON path. Recovery found the run, saw `running`, and RETURNED
that row — from a `wait=True` call. `assess run` then printed the `--no-wait` hints and exited 0
in two seconds, with the assessment still going on the platform. A pipeline read that as a passing
security gate before one probe had been answered.

Two seams fed it:
  * `poll_assessment` raised on a single failed GET, so any transport blip ended the wait;
  * `run()`'s `except Exception` wrapped the poll and returned whatever state it found, terminal
    or not, regardless of `wait`.

Fixed at both layers, plus a belt in `cmd_assess_run`: asked to wait + not terminal = EXIT_ERROR.
"""
import re
import sys
import types
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
for p in ("shells/cli", "runtime", "control"):
    sys.path.insert(0, str(REPO / p))
import api  # noqa: E402

SRC = (REPO / "shells" / "cli" / "ascend.py").read_text()


def _client(get_sequence, *, transitions_ok=True):
    """An AscendAPI whose get_assessment yields from a script; exceptions in the script are raised."""
    c = api.AscendAPI.__new__(api.AscendAPI)
    seq = list(get_sequence)
    def get_assessment(app_id, aid):
        item = seq.pop(0) if seq else seq_last[0]
        seq_last[0] = item
        if isinstance(item, Exception):
            raise item
        return item
    seq_last = [get_sequence[-1]]
    c.get_assessment = get_assessment
    c.pause = lambda app_id, aid: None
    c.resume = lambda app_id, aid: None
    c.create_assessment = lambda app_id, name: {"id": "asmt_1"}
    return c


class TestPollSurvivesATransientError:
    def test_one_failed_get_does_not_end_the_wait(self, monkeypatch):
        monkeypatch.setattr(api.time, "sleep", lambda s: None)
        c = _client([ConnectionError("blip"), {"status": "running"}, {"status": "complete", "total": 4}])
        out = c.poll_assessment("aapp", "asmt_1", interval=1, timeout=60)
        assert out["status"] == "complete"

    def test_repeated_failures_eventually_raise(self, monkeypatch):
        monkeypatch.setattr(api.time, "sleep", lambda s: None)
        c = _client([ConnectionError("down")] * (api.POLL_MAX_CONSECUTIVE_ERRORS + 1))
        with pytest.raises(api.AscendAPIError) as e:
            c.poll_assessment("aapp", "asmt_1", interval=1, timeout=60)
        assert "in a row" in str(e.value)

    def test_a_success_resets_the_failure_count(self, monkeypatch):
        monkeypatch.setattr(api.time, "sleep", lambda s: None)
        n = api.POLL_MAX_CONSECUTIVE_ERRORS - 1
        script = [ConnectionError()] * n + [{"status": "running"}] + [ConnectionError()] * n + [{"status": "complete"}]
        assert _client(script).poll_assessment("aapp", "asmt_1", interval=1, timeout=60)["status"] == "complete"


class TestRunWithWaitReturnsOnlyTerminal:
    def test_a_blip_during_poll_keeps_polling(self, monkeypatch):
        """The live failure: transport error mid-poll -> recovery -> must NOT return `running`."""
        monkeypatch.setattr(api.time, "sleep", lambda s: None)
        c = _client([ConnectionError("blip"), {"status": "running"}, {"status": "complete", "total": 4}])
        # Force the first poll attempt to raise out of poll_assessment so run()'s except fires.
        real_poll = api.AscendAPI.poll_assessment
        calls = {"n": 0}
        def poll(self, app_id, aid, **kw):
            calls["n"] += 1
            if calls["n"] == 1:
                raise ConnectionError("dropped during poll")
            return real_poll(self, app_id, aid, **kw)
        monkeypatch.setattr(api.AscendAPI, "poll_assessment", poll)
        c.get_assessment = lambda a, b: {"status": "complete", "total": 4} if calls["n"] >= 2 else {"status": "running"}
        out = c.run("aapp", "run-1", wait=True, interval=1, timeout=60)
        assert out["status"] == "complete", f"returned a non-terminal row from a wait=True call: {out}"
        assert out.get("recovered") and "polling resumed" in out["recovery_note"]

    def test_no_wait_still_returns_immediately(self, monkeypatch):
        monkeypatch.setattr(api.time, "sleep", lambda s: None)
        c = _client([{"status": "running"}])
        out = c.run("aapp", "run-1", wait=False)
        assert out["status"] == "running" and "assessment_id" in out

    def test_a_paused_recovery_is_resumed_before_polling(self, monkeypatch):
        monkeypatch.setattr(api.time, "sleep", lambda s: None)
        resumed = {"n": 0}
        c = _client([{"status": "paused"}, {"status": "complete"}])
        def resume(app_id, aid): resumed["n"] += 1
        c.resume = resume
        calls = {"n": 0}
        real_poll = api.AscendAPI.poll_assessment
        def poll(self, app_id, aid, **kw):
            calls["n"] += 1
            if calls["n"] == 1: raise ConnectionError("dropped")
            return real_poll(self, app_id, aid, **kw)
        monkeypatch.setattr(api.AscendAPI, "poll_assessment", poll)
        out = c.run("aapp", "r", wait=True, interval=1, timeout=60)
        assert out["status"] == "complete" and resumed["n"] >= 2, "a drop that left it paused must be resumed"


class TestTheCommandRefusesToCallAnUnfinishedRunSuccess:
    def test_cmd_assess_run_exits_error_on_non_terminal_after_wait(self):
        m = re.search(r"^def cmd_assess_run\(args\):(.*?)(?=^def )", SRC, re.S | re.M)
        body = m.group(1)
        assert "not in api.TERMINAL_STATUSES" in body and "sys.exit(EXIT_ERROR)" in body, (
            "cmd_assess_run can still exit 0 with the run in progress")
        assert body.index("not in api.TERMINAL_STATUSES") > body.index("_out(res, args, human=human)"), (
            "the check must run after the result is emitted, so --json consumers still get the row")

    def test_the_message_names_the_follow_up_command(self):
        m = re.search(r"^def cmd_assess_run\(args\):(.*?)(?=^def )", SRC, re.S | re.M)
        assert "ascend assess watch" in m.group(1)
