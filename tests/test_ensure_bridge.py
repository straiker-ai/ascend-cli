"""
test_ensure_bridge — the invariant enforcer that `assess run`/`resume` call to guarantee a bridge
is up before probes are scheduled.

Pins the four branches: native apps skip cleanly (no false alarm), an already-serving bridge is
reused (never double-started), a missing key/config is a soft skip (not a crash), and an eligible
app is started with the control token/base and idle-timeout plumbed through.

Note: `_ensure_bridge` does `import supervisor as S` at call time, and other tests pop/reload the
`supervisor` module — so each test imports it locally to patch the SAME object the code will see.
"""
import importlib
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
for p in ("control", "runtime", "shells/cli"):
    sys.path.insert(0, str(REPO / p))
import ascend            # noqa: E402


def _supervisor():
    return importlib.import_module("supervisor")


class FakeClient:
    token = "s6r_pat_secret"


class Args:
    base = "https://api.example/api/v3"
    qpm = None
    wait_ms = None


def test_native_app_skips_cleanly(monkeypatch):
    supervisor = _supervisor()

    def boom(*a, **k):
        raise AssertionError("native app must never start a bridge")
    monkeypatch.setattr(supervisor, "start", boom)
    r = ascend._ensure_bridge(FakeClient(), {"id": "aapp_1", "api_type": "api"}, args=Args())
    assert r["ensured"] is False
    assert "native" in r["reason"]


def test_reuses_serving_bridge(monkeypatch):
    supervisor = _supervisor()
    monkeypatch.setattr(supervisor, "is_serving", lambda app_id: True)

    def boom(*a, **k):
        raise AssertionError("must not double-start a serving bridge")
    monkeypatch.setattr(supervisor, "start", boom)
    r = ascend._ensure_bridge(FakeClient(), {"id": "aapp_1", "api_type": "thin"}, args=Args())
    assert r["ensured"] is True
    assert r.get("reused") is True


def test_skips_when_no_key(monkeypatch):
    supervisor = _supervisor()
    monkeypatch.setattr(supervisor, "is_serving", lambda app_id: False)
    monkeypatch.setattr(ascend, "_target_for",
                        lambda app_id: {"app_id": app_id, "skip": "no stored bridge key"})

    def boom(*a, **k):
        raise AssertionError("must not start without a resolved target")
    monkeypatch.setattr(supervisor, "start", boom)
    r = ascend._ensure_bridge(FakeClient(), {"id": "aapp_1", "api_type": "thin"}, args=Args())
    assert r["ensured"] is False
    assert "no stored bridge key" in r["skip"]


def test_starts_and_plumbs_control_token(monkeypatch):
    supervisor = _supervisor()
    monkeypatch.setattr(supervisor, "is_serving", lambda app_id: False)
    monkeypatch.setattr(ascend, "_target_for", lambda app_id: {
        "app_id": app_id, "app_name": "Bot", "config": "cfg", "adapter": None, "key": "tc-abc"})
    captured = {}

    def fake_start(app_id, **kw):
        captured.update(kw)
        captured["app_id"] = app_id
        return {"app_id": app_id, "pid": 4242}
    monkeypatch.setattr(supervisor, "start", fake_start)

    r = ascend._ensure_bridge(FakeClient(), {"id": "aapp_1", "api_type": "thin"},
                              args=Args(), assessment_id="asmt_9")
    assert r["ensured"] is True and r.get("started") is True and r["pid"] == 4242
    # the child must be able to reach the control plane to self-reconcile
    assert captured["control_token"] == "s6r_pat_secret"
    assert captured["control_base"] == "https://api.example/api/v3"
    assert captured["idle_timeout_s"] == 0        # idle-kill off by default: stop only on terminal
    assert captured["assessment_id"] == "asmt_9"
    assert captured["api_key"] == "tc-abc"


def test_ensure_never_raises_on_start_error(monkeypatch):
    supervisor = _supervisor()
    monkeypatch.setattr(supervisor, "is_serving", lambda app_id: False)
    monkeypatch.setattr(ascend, "_target_for", lambda app_id: {
        "app_id": app_id, "app_name": "Bot", "config": "cfg", "adapter": None, "key": "tc-abc"})
    monkeypatch.setattr(supervisor, "start",
                        lambda *a, **k: {"app_id": "aapp_1", "error": "already running"})
    r = ascend._ensure_bridge(FakeClient(), {"id": "aapp_1", "api_type": "thin"}, args=Args())
    assert r["ensured"] is False
    assert "already running" in r["error"]
