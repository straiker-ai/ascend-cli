"""
test_stale_relay_reclaim.py — a relay that is alive but not answering is replaced, not protected;
a run the platform paused during a relay outage is resumed once the relay is back; a run with no
relay startable fails fast instead of polling to its timeout; `watch --all --once` returns.

Seen live: a second `assess run` on an app whose relay had wedged printed "a relay is already
running for this app" on every tick for ten minutes while the run sat paused. `is_serving()` (pid
alive AND heartbeat fresh) said no; `start()` (pid alive) refused; nothing in between reclaimed it.
"""
import inspect
import sys
import types
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
for p in ("shells/cli", "runtime", "control"):
    if str(REPO / p) not in sys.path:
        sys.path.insert(0, str(REPO / p))
import ascend  # noqa: E402

APP = {"id": "aapp_test", "name": "T", "api_type": "bridge"}


class _FakeSup:
    """The supervisor calls _ensure_bridge makes, with the order recorded."""

    def __init__(self, *, running, serving, status=None):
        self.running, self.serving, self.status = running, serving, dict(status or {})
        self.calls = []

    def is_serving(self, app_id):
        return self.serving

    def is_running(self, app_id):
        return self.running

    def read_pid(self, app_id):
        return 777 if self.running else None

    def read_status(self, app_id):
        return dict(self.status)

    def stop(self, app_id, grace_s=8.0):
        self.calls.append("stop")
        self.running = False
        return {"app_id": app_id, "stopped": True, "pid": 777}

    def start(self, app_id, **kw):
        self.calls.append("start")
        if self.running:
            return {"app_id": app_id, "error": "a relay is already running for this app", "pid": 777}
        return {"app_id": app_id, "pid": 4242, "log": "x.log"}


@pytest.fixture
def wired(monkeypatch):
    def _wire(sup):
        monkeypatch.setitem(sys.modules, "supervisor", sup)
        monkeypatch.setattr(ascend, "needs_bridge", lambda app: True)
        monkeypatch.setattr(ascend, "_target_for",
                            lambda app_id: {"config": "c.json", "key": "k", "adapter": None, "app_name": "T"})
        return sup
    return _wire


class TestReclaim:
    def test_alive_but_stale_relay_is_stopped_then_replaced(self, wired):
        sup = wired(_FakeSup(running=True, serving=False))
        r = ascend._ensure_bridge(None, APP)
        assert r.get("started") and r.get("pid") == 4242, r
        assert r.get("reclaimed") == 777
        assert sup.calls == ["stop", "start"]

    def test_nothing_running_means_nothing_stopped(self, wired):
        sup = wired(_FakeSup(running=False, serving=False))
        r = ascend._ensure_bridge(None, APP)
        assert r.get("started") and "reclaimed" not in r
        assert sup.calls == ["start"]

    def test_a_serving_relay_is_reused_untouched(self, wired):
        sup = wired(_FakeSup(running=True, serving=True))
        r = ascend._ensure_bridge(None, APP)
        assert r.get("reused") and sup.calls == []

    def test_a_fatal_relay_is_surfaced_not_churned(self, wired):
        sup = wired(_FakeSup(running=True, serving=False,
                             status={"state": "fatal", "fatal_error": "lease service returned 401"}))
        r = ascend._ensure_bridge(None, APP)
        assert not r.get("ensured")
        assert "fatal" in r["error"] and "401" in r["error"] and "bridge start" in r["error"]
        assert sup.calls == [], "a relay that will fail again must not be restarted into the same wall"

    def test_the_notes_name_the_replaced_pid(self):
        n = ascend._ensure_note({"started": True, "pid": 1, "reclaimed": 777})
        assert "777" in n and "replaced" in n
        n2 = ascend._ensure_note({"started": True, "pid": 1})
        assert "replaced" not in n2

    def test_reclaim_happens_before_start(self):
        src = inspect.getsource(ascend._ensure_bridge)
        assert src.index("_reclaim_wedged_relay(") < src.index("S.start(")


class _Client:
    def __init__(self, fail=False):
        self.resumed, self.fail = [], fail

    def resume(self, app_id, aid):
        if self.fail:
            raise RuntimeError("409 not paused")
        self.resumed.append(aid)


@pytest.fixture
def guard_env(monkeypatch):
    state = {"serving": True}
    monkeypatch.setitem(sys.modules, "supervisor",
                        types.SimpleNamespace(is_serving=lambda app_id: state["serving"]))
    return state


A = {"id": "asmt_1"}


class TestPauseGuard:
    def test_paused_with_no_relay_fails_after_three_polls(self, guard_env):
        guard_env["serving"] = False
        g = ascend._PauseGuard(_Client(), "aapp_x", bridged=True)
        for _ in range(ascend.PAUSED_NO_BRIDGE_TICKS - 1):
            assert g.tick("paused", A, outage_note="! bridge down and could not be restarted: no key") is None
        with pytest.raises(ascend._BridgeUnavailable) as ei:
            g.tick("paused", A, outage_note="! bridge down and could not be restarted: no key")
        assert ei.value.assessment_id == "asmt_1"
        assert "consecutive" in str(ei.value) and "no key" in str(ei.value)

    def test_a_pause_after_an_outage_is_resumed_once_the_relay_is_back(self, guard_env):
        c = _Client()
        g = ascend._PauseGuard(c, "aapp_x", bridged=True)
        guard_env["serving"] = False
        assert g.tick("running", A) is None                      # the outage
        guard_env["serving"] = True
        note = g.tick("paused", A, outage_note="bridge went down mid-run — restarted (pid 9)")
        assert c.resumed == ["asmt_1"] and "resumed" in note
        # The platform reports "paused" for a poll or two after a resume: no second resume, and no
        # "somebody paused this" hint for a pause we just lifted.
        for _ in range(ascend.RESUME_SETTLE_TICKS):
            assert g.tick("paused", A) is None
        assert c.resumed == ["asmt_1"], "one outage, one resume"

    def test_an_operator_pause_is_left_alone_and_said_once(self, guard_env):
        c = _Client()
        g = ascend._PauseGuard(c, "aapp_x", bridged=True)
        g.tick("running", A); g.tick("running", A)
        hint = g.tick("paused", A)
        assert c.resumed == [] and hint and "assess resume" in hint
        assert g.tick("paused", A) is None

    def test_a_native_app_is_never_touched(self, guard_env):
        guard_env["serving"] = False
        c = _Client()
        g = ascend._PauseGuard(c, "aapp_x", bridged=False)
        for _ in range(10):
            assert g.tick("paused", A, outage_note="! down") is None
        assert c.resumed == []

    def test_a_bridge_elsewhere_only_gets_a_hint(self, guard_env):
        guard_env["serving"] = False
        c = _Client()
        g = ascend._PauseGuard(c, "aapp_x", bridged=True, local=False)
        notes = [g.tick("paused", A) for _ in range(10)]
        assert c.resumed == [] and sum(1 for n in notes if n) == 1
        assert "elsewhere" in notes[0]

    def test_auto_resume_is_capped(self, guard_env):
        c = _Client()
        g = ascend._PauseGuard(c, "aapp_x", bridged=True)
        for _ in range(6):
            guard_env["serving"] = False; g.tick("running", A)
            guard_env["serving"] = True; g.tick("paused", A)
        assert len(c.resumed) == ascend.AUTO_RESUME_MAX

    def test_a_healthy_stretch_forgets_an_old_outage(self, guard_env):
        c = _Client()
        g = ascend._PauseGuard(c, "aapp_x", bridged=True)
        guard_env["serving"] = False; g.tick("running", A)
        guard_env["serving"] = True
        for _ in range(ascend.HEALTHY_TICKS_TO_FORGET):
            g.tick("running", A)
        g.tick("paused", A)
        assert c.resumed == [], "a pause long after the outage is not the outage's pause"

    def test_a_failed_resume_is_reported_not_raised(self, guard_env):
        g = ascend._PauseGuard(_Client(fail=True), "aapp_x", bridged=True)
        guard_env["serving"] = False; g.tick("running", A)
        guard_env["serving"] = True
        note = g.tick("paused", A)
        assert note.startswith("!") and "409" in note

    def test_the_run_loop_consults_the_guard_and_fails_fast(self):
        src = inspect.getsource(ascend.cmd_assess_run)
        assert "guard.tick(" in src
        # A start that FAILED is this machine's problem: the guard must be armed, not hinting.
        assert 'ensure.get("error")' in src.split("_PauseGuard(")[1].split(")")[0] + src.split("_PauseGuard(")[1][:200]
        assert "except _BridgeUnavailable" in src
        assert "sys.exit(EXIT_ERROR)" in src.split("except _BridgeUnavailable")[1]


class TestWatchOnce:
    def test_watch_all_once_returns_without_sleeping(self, monkeypatch, capsys):
        c = types.SimpleNamespace(list_apps=lambda: [dict(APP)])
        monkeypatch.setattr(ascend, "_assessments_for",
                            lambda c, appid: [{"id": "asmt_1", "status": "running", "progress": 0.4}])
        monkeypatch.setattr(ascend.time, "sleep",
                            lambda s: (_ for _ in ()).throw(AssertionError("slept: --once ignored")))
        args = types.SimpleNamespace(app=None, all=True, json=True, include_done=False, interval=3,
                                     once=True)
        ascend._watch_many(args, c)
        assert "asmt_1" in capsys.readouterr().out


class TestHeartbeatGuarded:
    def test_the_beat_loop_cannot_die_silently(self):
        src = inspect.getsource(ascend.cmd_runtime_start) if hasattr(ascend, "cmd_runtime_start") else \
            (REPO / "shells" / "cli" / "ascend.py").read_text()
        beat = src.split("def _beat():", 1)[1].split("threading.Thread(target=_beat", 1)[0]
        lines = [l.strip() for l in beat.split("\n")]
        w = lines.index("while True:")
        assert lines[w + 1] == "try:", "the beat loop body is not guarded"
        assert "heartbeat error" in beat
