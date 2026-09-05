"""
test_relay_config_cwd — the relay must be handed a config it can actually open.

The relay child is spawned with `cwd=REPO` so its own relative paths stay put, while
`configs.config_dirs()` searches `Path.cwd()/configs` FIRST. A bare config name therefore
resolved to a real file for every foreground command (which runs in the operator's shell) and
to nothing for the relay. `target add --save-as x` writes to ./configs whenever that directory
exists, so this is the ordinary case for anyone who keeps a configs/ directory beside their
work -- not a corner. It presented as `relay exited at startup (code 3)` quoting a path in
~/.ascend/configs the operator never chose, the platform pausing the run, and the CLI warning
that probes would go unanswered: a false pass in waiting.

Pins: the child gets an ABSOLUTE path that exists; an unresolvable config is refused BEFORE a
process is spawned, with a message that names where the CLI looked.
"""
import os
import sys
import json
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
for p in ("control", "runtime", "shells/cli"):
    sys.path.insert(0, str(REPO / p))

import supervisor  # noqa: E402

CFG = {"adapter": "direct_api", "endpoint": "http://127.0.0.1:9/chat", "method": "POST",
       "message_body": {"message": "{{PROMPT}}"}, "response_path": "reply"}


class _FakePopen:
    """Captures argv instead of spawning. The real thing would be a detached relay."""
    instances = []

    def __init__(self, argv, **kw):
        self.argv, self.kw, self.pid, self.returncode = argv, kw, 999_999, None
        _FakePopen.instances.append(self)

    def poll(self):
        return None


@pytest.fixture
def sandbox(tmp_path, monkeypatch):
    """An operator working directory that holds its own configs/, like any real one."""
    work = tmp_path / "work"
    (work / "configs").mkdir(parents=True)
    (work / "configs" / "mybot.json").write_text(json.dumps(CFG))
    home = tmp_path / "home"
    (home / ".ascend" / "configs").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.chdir(work)
    _FakePopen.instances.clear()
    monkeypatch.setattr(supervisor.subprocess, "Popen", _FakePopen)
    monkeypatch.setattr(supervisor, "_startup_grace_s", lambda: 0.0)
    yield work
    supervisor._clear("aapp_cfg_cwd_test")


def _config_arg(argv):
    return argv[argv.index("--config") + 1]


class TestTheRelayCanOpenWhatItIsGiven:
    def test_child_is_handed_an_absolute_path_that_exists(self, sandbox):
        """The operator types a bare name; the relay must still find the file.

        This is the most common case -- `target add --save-as mybot` from a directory that has a
        configs/ dir -- so it is the one the test pins.
        """
        r = supervisor.start("aapp_cfg_cwd_test", config="mybot", adapter=None,
                             api_key="tc-test", self_reconcile=False)
        assert "error" not in r, r
        passed = _config_arg(_FakePopen.instances[0].argv)
        assert os.path.isabs(passed), f"relay got a cwd-relative reference: {passed!r}"
        assert Path(passed).is_file()
        assert Path(passed).resolve() == (sandbox / "configs" / "mybot.json").resolve()

    def test_the_path_resolves_from_the_childs_own_cwd(self, sandbox, monkeypatch):
        """Re-resolve from where the child will actually stand: cwd=REPO."""
        import configs as configs_mod
        supervisor.start("aapp_cfg_cwd_test", config="mybot", adapter=None,
                         api_key="tc-test", self_reconcile=False)
        passed = _config_arg(_FakePopen.instances[0].argv)
        assert _FakePopen.instances[0].kw.get("cwd") == str(supervisor.REPO)
        monkeypatch.chdir(supervisor.REPO)
        assert configs_mod.resolve_config_path(passed) is not None, \
            "the relay still cannot resolve its own --config from cwd=REPO"

    def test_missing_config_is_refused_before_anything_is_spawned(self, sandbox):
        """No doomed child, and the error says where the CLI looked."""
        r = supervisor.start("aapp_cfg_cwd_test", config="not-a-real-config", adapter=None,
                             api_key="tc-test", self_reconcile=False)
        assert "error" in r
        assert "not-a-real-config" in r["error"] and "Looked in" in r["error"]
        assert not _FakePopen.instances, "a process was spawned for a config that does not exist"
