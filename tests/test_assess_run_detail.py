"""
test_assess_run_detail.py — the command that produces findings can also show them.

`assess run` waits for the run and prints the verdict, but did not accept `--detail`, so asking
the command that just produced the findings to show them exited 3 with
`unrecognized arguments: --detail` — and since the flag is rejected before anything happens, the
whole run had to be re-issued. Two independent operators hit this in consecutive trials; one of
them lost the run.

`assess results --detail` already existed, which is exactly what makes the omission a trap: the
flag is right, on the wrong verb.
"""
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
CLI = str(REPO / "shells" / "cli" / "ascend.py")


def _run(*args, env=None):
    return subprocess.run([sys.executable, CLI, *args], capture_output=True, text=True, timeout=120)


def test_assess_run_accepts_detail():
    r = _run("assess", "run", "--app", "X", "--name", "Y", "--detail", "--token", "")
    assert "unrecognized arguments" not in (r.stderr + r.stdout), r.stderr[:200]


def test_it_is_advertised_in_help():
    r = _run("assess", "run", "--help")
    assert "--detail" in r.stdout


def test_the_flag_reaches_the_verdict():
    """Parsing it and then ignoring it would be the same bug wearing a different hat."""
    import inspect
    for p in ("shells/cli", "runtime", "control"):
        if str(REPO / p) not in sys.path:
            sys.path.insert(0, str(REPO / p))
    import ascend
    src = inspect.getsource(ascend.cmd_assess_run)
    assert '_verdict(res, detail=getattr(args, "detail", False))' in src


def test_results_still_has_it():
    r = _run("assess", "results", "--help")
    assert "--detail" in r.stdout, "the sibling verb must keep the flag it always had"
