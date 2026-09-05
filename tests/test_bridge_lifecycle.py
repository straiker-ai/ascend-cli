"""
test_bridge_lifecycle — supervisor liveness + spawn safety + the lease-client idle signal.

Pins:
  * is_serving() is heartbeat-aware (fresh=serving, stale=not, dead=not) — stricter than a bare
    pid check, so the auto-lifecycle never "reuses" a bridge that stopped answering (a false pass);
  * start() puts the assessment id / idle-timeout on argv but the control token and bridge key ONLY
    in the child ENV (argv is world-readable via `ps`);
  * last_probe_ts advances on a real probe (the input to the 30-min idle-timeout).
"""
import os
import sys
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
for p in ("control", "runtime", "shells/cli"):
    sys.path.insert(0, str(REPO / p))


@pytest.fixture()
def sup(tmp_path, monkeypatch):
    """Isolate the relay state dir, then hand back a fresh supervisor module."""
    monkeypatch.setenv("ASCEND_HOME", str(tmp_path / "ascend"))
    monkeypatch.setenv("ASCEND_STATE_DIR", str(tmp_path / "state"))
    for mod in ("tenant", "creds", "supervisor"):
        sys.modules.pop(mod, None)
    import supervisor
    return supervisor


def test_is_serving_fresh_heartbeat(sup):
    sup._write_pid("aapp_x", os.getpid())
    sup.write_status("aapp_x", {"app_id": "aapp_x", "ts": time.time(),
                                "started_at": time.time()})
    assert sup.is_serving("aapp_x") is True


def test_is_serving_stale_heartbeat_is_not_serving(sup):
    sup._write_pid("aapp_x", os.getpid())          # alive pid...
    sup.write_status("aapp_x", {"app_id": "aapp_x", "ts": time.time() - 10_000})  # ...but stale
    assert sup.is_serving("aapp_x") is False


def test_is_serving_dead_pid_is_not_serving(sup):
    sup._write_pid("aapp_x", 2_000_000)            # not a live pid
    sup.write_status("aapp_x", {"app_id": "aapp_x", "ts": time.time()})
    assert sup.is_serving("aapp_x") is False


def _real_cfg(tmp_path, name="cfg"):
    """A config that exists on disk. start() refuses to spawn a relay for one that does not:
    the child runs from the CLI's own directory and could never have opened it."""
    import json as _json
    d = Path(tmp_path) / "cfgs"
    d.mkdir(parents=True, exist_ok=True)
    f = d / f"{name}.json"
    f.write_text(_json.dumps({"adapter": "direct_api", "endpoint": "http://127.0.0.1:9/chat",
                              "method": "POST", "message_body": {"message": "{{PROMPT}}"},
                              "response_path": "reply"}))
    return str(f)


def test_start_keeps_secrets_off_argv_but_in_env(sup, monkeypatch, tmp_path):
    captured = {}

    class FakePopen:
        def __init__(self, argv, **kw):
            captured["argv"] = argv
            captured["env"] = kw.get("env", {})
            self.pid = 4321
    monkeypatch.setattr(sup.subprocess, "Popen", FakePopen)

    sup.start("aapp_x", config=_real_cfg(tmp_path), adapter=None, api_key="tc-secret",
              assessment_id="asmt_1", control_token="s6r_pat_secret",
              control_base="https://ctrl.example", idle_timeout_s=1800)

    argv = captured["argv"]
    # non-secret run parameters DO go on argv
    assert "--assessment-id" in argv and "asmt_1" in argv
    assert "--idle-timeout" in argv and "1800" in argv
    # secrets NEVER on argv (ps is world-readable)
    joined = " ".join(argv)
    assert "s6r_pat_secret" not in joined
    assert "tc-secret" not in joined
    # ...they live in the child ENV instead
    env = captured["env"]
    assert env["STRAIKER_PAT"] == "s6r_pat_secret"
    assert env["STRAIKER_BRIDGE_API_KEY"] == "tc-secret"
    assert env["ASCEND_CONTROL_BASE"] == "https://ctrl.example"
    # and the status record tracks the assessment
    assert sup.read_status("aapp_x").get("assessment_id") == "asmt_1"


def test_no_self_reconcile_flag_on_argv(sup, monkeypatch, tmp_path):
    captured = {}

    class FakePopen:
        def __init__(self, argv, **kw):
            captured["argv"] = argv
            self.pid = 55
    monkeypatch.setattr(sup.subprocess, "Popen", FakePopen)
    sup.start("aapp_y", config=_real_cfg(tmp_path), adapter=None, api_key="tc-x",
              self_reconcile=False)
    assert "--no-self-reconcile" in captured["argv"]


def test_last_probe_ts_advances_on_real_probe(monkeypatch):
    import lease_client
    c = lease_client.LeaseClient(api_key="tc", handler=lambda m: (200, {"response": "ok"}))
    assert c.last_probe_ts == 0.0
    monkeypatch.setattr(c, "_submit", lambda *a, **k: {})   # no network
    c._process({"request_id": "r1", "msg_id": "m1", "message": {"payload": "hi"}})
    assert c.last_probe_ts > 0.0
    assert c.stats["answered"] == 1


@pytest.fixture(autouse=True)
def _no_startup_grace(monkeypatch):
    """These tests are about pid/status bookkeeping and argv hygiene; their children are stand-ins
    (or die at once on a bogus config). supervisor.start() now watches a fresh child for its first
    heartbeat or its death, which would turn every start() here into a 3 s wait or a reported
    death. The real-child startup-death behaviour has its own test in test_p1_consistency.py."""
    monkeypatch.setenv("ASCEND_STARTUP_GRACE_S", "0")
