"""
test_frozen_relay_spawn — the shipped binary must be able to start its own relay.

In a PyInstaller build `sys.executable` is the `ascend` binary. The supervisor spawned the relay
as `<binary> <bundle>/shells/cli/ascend.py runtime start …`, so the binary read the script path
as its <command> ("invalid choice"), exited 3, and every bridge-type assessment run from the
binary sat with no relay -- a false pass in waiting. Found by running the packaged binary from
outside the source tree; nothing in a source checkout can see it.
"""
import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
for p in ("control", "runtime", "shells/cli"):
    sys.path.insert(0, str(REPO / p))
import supervisor  # noqa: E402


class _FakePopen:
    last = None

    def __init__(self, argv, **kw):
        _FakePopen.last = argv
        self.pid, self.returncode = 4242, None

    def poll(self):
        return None


@pytest.fixture
def spawn(tmp_path, monkeypatch):
    d = tmp_path / "configs"; d.mkdir()
    (d / "c.json").write_text(json.dumps({"adapter": "direct_api", "endpoint": "http://127.0.0.1:9/chat",
                                          "method": "POST", "body": {"message": "{{PROMPT}}"}}))
    monkeypatch.setattr(supervisor.subprocess, "Popen", _FakePopen)
    monkeypatch.setattr(supervisor, "_startup_grace_s", lambda: 0.0)
    monkeypatch.setattr(supervisor, "relays_dir", lambda: tmp_path)
    return str(d / "c.json")


def test_a_frozen_binary_spawns_itself_with_no_script_path(spawn, monkeypatch):
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", "/opt/ascend/ascend")
    supervisor.start("aapp_frozen", config=spawn, adapter=None, api_key="tc-x", self_reconcile=False)
    argv = _FakePopen.last
    assert argv[0] == "/opt/ascend/ascend" and argv[1:3] == ["runtime", "start"], argv
    assert not any(a.endswith("ascend.py") for a in argv), argv
    supervisor._clear("aapp_frozen")


def test_a_source_checkout_still_runs_the_script(spawn, monkeypatch):
    monkeypatch.delattr(sys, "frozen", raising=False)
    supervisor.start("aapp_source", config=spawn, adapter=None, api_key="tc-x", self_reconcile=False)
    argv = _FakePopen.last
    assert argv[0] == sys.executable and argv[1].endswith("ascend.py") and argv[2:4] == ["runtime", "start"], argv
    supervisor._clear("aapp_source")
