"""
test_command_matrix — every command group parses and fails cleanly (the "regression-test every
command" gate). No command may print a Python traceback on --help or on a missing/ bad argument;
each must exit with a stable, correct class. Runs the real CLI as a subprocess, offline.
"""
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]

def _all_groups():
    """Every group argparse actually knows, derived — not a hand-kept list.

    The hand-kept list silently fell five groups behind (`bridge`, `policy`, `reports`,
    `status`, `target` were never exercised). Root help is tiered now, so most groups are not
    listed at the top level and a broken one would be invisible until a user hit it. Deriving
    the list means adding a group automatically adds its coverage.
    """
    import importlib.util
    spec = importlib.util.spec_from_file_location("_acli_matrix", REPO / "shells/cli/ascend.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    import argparse
    for action in mod.build_parser()._actions:
        if isinstance(action, argparse._SubParsersAction):
            return sorted(action.choices)
    raise AssertionError("no subparsers found on the root parser")


GROUPS = _all_groups()


def run(*args, env=None):
    e = dict(os.environ)
    e["STRAIKER_PAT"] = "s6r_pat_dummy"   # FORCED: setdefault kept a real PAT from the shell
    if env:
        e.update(env)
    return subprocess.run([sys.executable, str(REPO / "shells/cli/ascend.py"), *args],
                          capture_output=True, text=True, env=e, cwd=str(REPO))


def test_top_level_help():
    r = run("--help")
    assert r.returncode == 0
    assert "Traceback" not in (r.stdout + r.stderr)


@pytest.mark.parametrize("group", GROUPS)
def test_group_help_never_tracebacks(group):
    r = run(group, "--help")
    assert r.returncode == 0, f"{group} --help exited {r.returncode}: {r.stderr[:200]}"
    assert "Traceback" not in (r.stdout + r.stderr)


@pytest.mark.parametrize("group", ["app", "controls", "assess", "adapter"])
def test_group_missing_subcommand_is_clean(group):
    # a group with required subcommands: argparse usage error (2), never a traceback
    r = run(group)
    assert "Traceback" not in (r.stdout + r.stderr)
    assert r.returncode in (2, 3)


@pytest.mark.parametrize("args", [
    ("adapter", "validate", "--config", "does-not-exist"),   # -> USAGE 3
    ("adapter", "show", "does-not-exist"),                    # -> USAGE 3
    ("export", "--file", "/no/such.json"),                    # bad file
    ("results", "/no/such.jsonl"),                            # bad file
    ("map", "--api", "http://169.254.169.254/x"),            # SSRF-blocked -> USAGE 3
])
def test_bad_input_no_traceback(args):
    r = run(*args)
    assert "Traceback" not in (r.stdout + r.stderr), f"{args} leaked a traceback"
    assert r.returncode != 0


def test_version_prints_and_exits_zero():
    r = run("version")
    assert r.returncode == 0
    assert r.stdout.strip()


# --- every SUBcommand parses too -----------------------------------------------------------
# Root help is tiered, so `app`, `adapter`, `keys` and the rest are no longer listed at the top
# level. Hiding a command from a menu must not be able to break it: the promise made when the
# help was tiered was that nothing was removed or renamed.
def _all_subcommands():
    import argparse
    import importlib.util
    spec = importlib.util.spec_from_file_location("_acli_subs", REPO / "shells/cli/ascend.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    out = []
    for action in mod.build_parser()._actions:
        if isinstance(action, argparse._SubParsersAction):
            for gname, gparser in action.choices.items():
                for sub in gparser._actions:
                    if isinstance(sub, argparse._SubParsersAction):
                        out += [(gname, s) for s in sorted(sub.choices)]
    return out


@pytest.mark.parametrize("group,verb", _all_subcommands())
def test_every_subcommand_help_parses(group, verb):
    r = run(group, verb, "--help")
    assert r.returncode == 0, f"{group} {verb} --help exited {r.returncode}: {r.stderr[:200]}"
    assert "Traceback" not in (r.stdout + r.stderr)
