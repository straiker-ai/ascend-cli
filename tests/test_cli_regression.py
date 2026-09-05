"""
test_cli_regression — the round-3 CLI correctness contract, exercised as a subprocess.

These pin the papercuts that burned real engagements:
  * a config reference is accepted EXACTLY as given — `x.json` never becomes `x.json.json`;
  * exit codes are a stable CI contract: OK=0, tool/target ERROR=1, gate FINDINGS=2, USAGE=3;
  * the same failure (missing/bad config) exits the same class no matter which command hit it.

Offline: every case here either fails before any network call, or targets a dead local port.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
ASCEND = REPO / "ascend"

EXIT_OK, EXIT_ERROR, EXIT_FINDINGS, EXIT_USAGE = 0, 1, 2, 3


def run(*args, env=None):
    e = dict(os.environ)
    e["STRAIKER_PAT"] = "s6r_pat_dummy"   # FORCED: setdefault kept a real PAT from the shell  # so "no token" never masks the code under test
    if env:
        e.update(env)
    return subprocess.run([sys.executable, str(REPO / "shells/cli/ascend.py"), *args],
                          capture_output=True, text=True, env=e, cwd=str(REPO))


def test_missing_config_message_never_doubles_json():
    r = run("adapter", "validate", "--config", "nope.json")
    assert r.returncode == EXIT_USAGE
    assert ".json.json" not in r.stderr          # the exact bug
    assert "config not found: nope.json" in r.stderr


def test_missing_config_exit_is_usage():
    assert run("adapter", "validate", "--config", "does-not-exist").returncode == EXIT_USAGE


def test_missing_file_exit_is_usage():
    assert run("adapter", "validate", "--file", "/no/such/file.json").returncode == EXIT_USAGE


def test_file_and_config_mutually_exclusive():
    r = run("adapter", "validate", "--config", "demo", "--file", "/x.json")
    assert r.returncode == EXIT_USAGE
    assert "either --file or --config" in r.stderr


def test_bad_json_file_is_usage(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{not json")
    r = run("adapter", "validate", "--file", str(p))
    assert r.returncode == EXIT_USAGE
    assert "not valid JSON" in r.stderr


def test_down_target_is_tool_error(tmp_path):
    cfg = tmp_path / "down.json"
    cfg.write_text(json.dumps({"adapter": "direct_api", "endpoint": "http://127.0.0.1:59999/x",
                               "method": "POST", "body": {"message": "{{PROMPT}}"},
                               "response_path": "r"}))
    # unreachable target -> ERROR(1), distinct from a content mismatch (2)
    assert run("adapter", "validate", "--file", str(cfg)).returncode == EXIT_ERROR


def test_runtime_start_missing_config_is_usage():
    r = run("runtime", "start", "--adapter", "direct_api", "--config", "does-not-exist",
            env={"STRAIKER_BRIDGE_API_KEY": "tc-dummy"})
    assert r.returncode == EXIT_USAGE          # same class as the CLI-resolved commands
    assert ".json.json" not in r.stderr


def test_assess_status_accepts_json_flag_after_group():
    # --json trailing must PARSE (argparse would exit 2 "unrecognized arguments" if not);
    # it then dies USAGE(3) on the dummy token, proving the flag was accepted.
    r = run("assess", "status", "--app", "X", "--assessment", "Y", "--json",
            env={"STRAIKER_PAT": ""})
    assert r.returncode != 2 or "unrecognized arguments" not in r.stderr
