"""
test_prove_it_answered.py — "did the target actually answer?" belongs in the results, not a log.

Measured across 22 agent onboardings: every single one, on both the CLI and the raw-API path,
established that probes had been answered by leaving the results command and reading relay
counters or a bridge debug log. `assess results` never said it.

The guard that existed for this fired on probe COUNT — `total <= 4` and clean. One control is
exactly four probes, so every correctly-scoped single-control run tripped it, on runs that were
provably fine. Operators learned to disregard it. A warning that always fires is a warning that
gets ignored.

It now speaks from the relay's own counters:
  answered > 0   -> silent; the run demonstrably reached the target
  answered == 0  -> a CONFIRMED false pass, stated as fact rather than suspicion
  no relay here  -> the old heuristic, worded as what it is: unverifiable on this machine
"""
import sys
import types
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
for p in ("shells/cli", "runtime", "control"):
    if str(REPO / p) not in sys.path:
        sys.path.insert(0, str(REPO / p))
import ascend  # noqa: E402

CLEAN = {"status": "complete", "total": 4, "failed": 0, "severity": "low"}


def _relay(monkeypatch, rows):
    """Stand in for the persisted per-app state files. Keyed by app_id, like read_status."""
    by = {r["app_id"]: r for r in rows}
    monkeypatch.setitem(sys.modules, "supervisor",
                        types.SimpleNamespace(read_status=lambda aid: by.get(aid),
                                              ls=lambda: [r for r in rows if r.get("alive")]))


def test_silent_when_the_relay_proves_the_target_answered(monkeypatch):
    _relay(monkeypatch, [{"app_id": "aapp_1", "stats": {"answered": 8, "delivered": 8, "failed": 0}}])
    assert ascend._false_pass_warning(CLEAN, "aapp_1") is None, (
        "4 probes is the correct volume for one control; with answers proven there is nothing to warn about")


def test_a_relay_that_answered_nothing_is_a_confirmed_false_pass(monkeypatch):
    _relay(monkeypatch, [{"app_id": "aapp_1", "stats": {"answered": 0, "delivered": 0, "failed": 0}}])
    w = ascend._false_pass_warning(CLEAN, "aapp_1")
    assert w and "FALSE PASS" in w
    assert "never" in w and "measured NOTHING" in w, "state it as fact, not suspicion"


def test_no_relay_record_falls_back_to_the_heuristic_and_says_so(monkeypatch):
    _relay(monkeypatch, [])
    w = ascend._false_pass_warning(CLEAN, "aapp_1")
    assert w and "cannot be confirmed here" in w, "be honest that this machine cannot verify it"


def test_a_big_clean_run_with_no_relay_is_not_flagged(monkeypatch):
    _relay(monkeypatch, [])
    assert ascend._false_pass_warning({**CLEAN, "total": 250}, "aapp_1") is None


def test_a_run_that_is_not_terminal_is_never_flagged(monkeypatch):
    _relay(monkeypatch, [{"app_id": "aapp_1", "stats": {"answered": 0, "delivered": 0}}])
    assert ascend._false_pass_warning({**CLEAN, "status": "running"}, "aapp_1") is None


def test_evidence_reads_the_right_app(monkeypatch):
    _relay(monkeypatch, [{"app_id": "aapp_other", "stats": {"answered": 9, "delivered": 9}},
                         {"app_id": "aapp_1", "stats": {"answered": 0, "delivered": 0}}])
    w = ascend._false_pass_warning(CLEAN, "aapp_1")
    assert w and "FALSE PASS" in w, "another app's healthy relay must not vouch for this one"


def test_evidence_survives_the_relay_self_stopping(monkeypatch):
    """The common case: a four-probe run finishes in under a minute and the relay is gone before
    anyone looks. Its pid file is pruned, so it vanishes from `bridge ls` -- but the state file
    with the counters is still on disk. Five of twelve operators in a measured round were told
    'no relay record for that run' and went and read that file by hand."""
    _relay(monkeypatch, [{"app_id": "aapp_1", "alive": False,
                          "stats": {"answered": 8, "delivered": 8, "failed": 0}}])
    ev = ascend._relay_evidence("aapp_1")
    assert ev and ev["answered"] == 8, "the counters outlive the process; read them"
    assert ascend._false_pass_warning(CLEAN, "aapp_1") is None


def test_an_unreadable_supervisor_degrades_to_the_heuristic(monkeypatch):
    def _boom(*a, **k):
        raise OSError("state unreadable")
    monkeypatch.setitem(sys.modules, "supervisor", types.SimpleNamespace(read_status=_boom, ls=_boom))
    assert ascend._relay_evidence("aapp_1") is None
    assert ascend._false_pass_warning(CLEAN, "aapp_1") is not None


def test_evidence_is_read_from_the_state_file_not_the_live_list():
    """Source discipline: going through ls() is the bug, whatever ls() returns in a test."""
    import inspect
    src = inspect.getsource(ascend._relay_evidence)
    assert "read_status(app_id)" in src
    assert "S.ls()" not in src, "ls() only sees relays that still have a pid file"


def test_results_reports_the_answered_count():
    """Source discipline: the whole point is that the operator never has to run a second command."""
    import inspect
    src = inspect.getsource(ascend.cmd_assess_results)
    assert "_relay_evidence(app_id)" in src
    assert "relay_answered" in src, "--json must carry it too"
    assert "answered by the target" in src, "and the human output must say it in words"
