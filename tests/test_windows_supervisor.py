"""
test_windows_supervisor — the supervised relay says no on Windows, and says what works.

The detached relay is managed with setsid, os.kill and SIGTERM/SIGKILL. On Windows it was
spawned anyway and could never be seen or stopped. Pins: on nt the supervisor refuses BEFORE
spawning, names the foreground form and WSL; elsewhere nothing changes.
"""
import json
import os
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
for p in ("control", "runtime", "shells/cli"):
    sys.path.insert(0, str(REPO / p))
import supervisor  # noqa: E402


@pytest.fixture
def cfg(tmp_path, monkeypatch):
    d = tmp_path / "configs"; d.mkdir()
    (d / "c.json").write_text(json.dumps({"adapter": "direct_api", "endpoint": "http://127.0.0.1:9/chat"}))
    spawned = []
    monkeypatch.setattr(supervisor.subprocess, "Popen",
                        lambda *a, **k: spawned.append(a) or (_ for _ in ()).throw(AssertionError("spawned")))
    monkeypatch.setattr(supervisor, "relays_dir", lambda: tmp_path)
    return str(d / "c.json"), spawned


def test_windows_is_refused_before_anything_is_spawned(cfg, monkeypatch):
    path, spawned = cfg
    monkeypatch.setattr(supervisor.os, "name", "nt")
    r = supervisor.start("aapp_win", config=path, adapter=None, api_key="tc-x", self_reconcile=False)
    assert "error" in r and "macOS or Linux" in r["error"]
    assert "--foreground" in r["error"] and "WSL" in r["error"]
    assert not spawned


def test_posix_is_unchanged(cfg, monkeypatch):
    path, spawned = cfg
    monkeypatch.setattr(supervisor.os, "name", "posix")
    monkeypatch.setattr(supervisor, "_startup_grace_s", lambda: 0.0)

    class _Popen:
        def __init__(self, argv, **kw): spawned.append(argv); self.pid, self.returncode = 5, None
        def poll(self): return None
    monkeypatch.setattr(supervisor.subprocess, "Popen", _Popen)
    r = supervisor.start("aapp_posix", config=path, adapter=None, api_key="tc-x", self_reconcile=False)
    assert "error" not in r and spawned
    supervisor._clear("aapp_posix")
