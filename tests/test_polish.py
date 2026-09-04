"""test_polish.py — small things a first-time operator hits in the first five minutes."""
import json
import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
CLI = [sys.executable, str(REPO / "shells" / "cli" / "ascend.py")]


def _env_without_pat(tmp_path):
    env = {k: v for k, v in os.environ.items() if k not in ("STRAIKER_PAT", "STRAIKER_TOKEN")}
    env["HOME"] = str(tmp_path)                       # an empty key store
    env["ASCEND_NO_UPDATE_CHECK"] = "1"
    return env


def test_doctor_names_the_fix_for_a_missing_pat(tmp_path):
    r = subprocess.run(CLI + ["doctor"], capture_output=True, text=True, env=_env_without_pat(tmp_path))
    assert "[XX] PAT present" in r.stdout
    assert "fix: export STRAIKER_PAT=" in r.stdout, "a failed check that does not say what to do is a riddle"


def test_doctor_json_carries_the_fixes(tmp_path):
    r = subprocess.run(CLI + ["doctor", "--json"], capture_output=True, text=True, env=_env_without_pat(tmp_path))
    d = json.loads(r.stdout)
    assert d["checks"]["PAT present"] is False and "STRAIKER_PAT" in d["fixes"]["PAT present"]


def test_target_list_works_with_no_pat(tmp_path):
    """The list is local; the platform check is a bonus. It used to die on the token check."""
    r = subprocess.run(CLI + ["target", "list"], capture_output=True, text=True, env=_env_without_pat(tmp_path))
    assert r.returncode == 0, r.stderr
    assert "no token" not in r.stderr and "no targets yet" in r.stdout
    assert "not checked against the platform" in r.stderr


def test_usage_doc_matches_the_landed_behaviour():
    t = (REPO / "docs" / "USAGE.md").read_text()
    assert "latest finished run" in t and "--yes skips" in t and "bridge sync --app" in t
    assert "chat <target|config>" in t
