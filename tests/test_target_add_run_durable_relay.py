"""
test_target_add_run_durable_relay.py — `target add --run` must not orphan the run it starts.

The path used to start a bridge as a daemon THREAD inside the command, start the assessment, and
then — under --json, so an agent could get its object and return — call client.stop() and exit.
That is an assessment deliberately left with nobody answering it: unanswered probes score as no
findings, so it completes looking clean having measured nothing. An operator in a live trial hit
exactly this ("the run was briefly unserved; fixed by running bridge start").

`assess run` already had the right answer: a supervised relay that outlives the process and
self-stops when the run ends. `--run` now uses the same one, so --json can return immediately AND
the run is served — the most common way an agent uses this command.
"""
import inspect
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
for p in ("shells/cli", "runtime", "control"):
    if str(REPO / p) not in sys.path:
        sys.path.insert(0, str(REPO / p))
import ascend  # noqa: E402


def _onboard_src():
    return inspect.getsource(ascend.cmd_onboard)


def test_run_uses_the_supervised_relay():
    src = _onboard_src()
    assert "_ensure_bridge(c, app_id, args=args)" in src


def test_run_no_longer_starts_an_in_process_thread_bridge():
    src = _onboard_src()
    assert "run_forever" not in src, "an in-process bridge dies with the command"
    assert "threading.Thread" not in src


def test_json_mode_never_stops_the_relay_it_just_started():
    src = _onboard_src()
    assert "client.stop()" not in src
    assert "not held open in --json mode" not in src


def test_the_relay_is_ensured_before_the_assessment_is_created():
    src = _onboard_src()
    assert src.index("_ensure_bridge(c, app_id, args=args)") < src.index("c.run(app_id,"), (
        "start the relay first, or the very first probes go unanswered")
