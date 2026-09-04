"""
test_multi_target_ux.py — with several targets on one machine, the names a person reads in
`target list` must work everywhere a target can be named.

`chat` took a config name, a config path or a URL — never the target's own name — so the name
just read in `target list` was refused with "no config named …". The lookup below maps a target
(app name or aapp_ id) to its bound config through the keys store, and only when no config of
that name exists, so a config really called that still wins.
"""
import sys
import types
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
for p in ("shells/cli", "runtime", "control"):
    if str(REPO / p) not in sys.path:
        sys.path.insert(0, str(REPO / p))
import ascend  # noqa: E402

STORE = {"aapp_1": {"app_name": "Multi A", "config": "multi-a", "thin_api_key": "k"},
         "aapp_2": {"app_name": "Multi B", "config": "127-0-0-1-8921", "thin_api_key": "k"},
         "aapp_3": {"app_name": "Twin", "config": "twin-1", "thin_api_key": "k"},
         "aapp_4": {"app_name": "Twin", "config": "twin-2", "thin_api_key": "k"}}


@pytest.fixture
def store(monkeypatch):
    monkeypatch.setitem(sys.modules, "creds", types.SimpleNamespace(load_all=lambda: dict(STORE)))
    monkeypatch.setattr(ascend, "resolve_config_path", lambda n: Path(f"/c/{n}.json") if n in ("multi-a", "twin-1") else None)


class TestConfigForTarget:
    def test_a_target_name_maps_to_its_bound_config(self, store):
        assert ascend._config_for_target("Multi B") == "127-0-0-1-8921"

    def test_an_app_id_maps_too(self, store):
        assert ascend._config_for_target("aapp_2") == "127-0-0-1-8921"

    def test_a_real_config_name_wins(self, store):
        assert ascend._config_for_target("multi-a") is None, "resolves as a config; no lookup"

    def test_urls_and_paths_are_left_alone(self, store):
        assert ascend._config_for_target("https://h/chat") is None
        assert ascend._config_for_target("./x.json") is None

    def test_two_targets_with_one_name_resolve_to_nothing(self, store):
        assert ascend._config_for_target("Twin") is None, "guessing between two would chat with the wrong one"

    def test_chat_resolution_uses_it(self, store, monkeypatch, capsys):
        monkeypatch.setattr(ascend, "_load_named_config", lambda n: {"adapter": "direct_api", "url": n})
        cfg, adapter, name = ascend._resolve_chat_target(types.SimpleNamespace(target="Multi B", config=None, file=None, adapter=None))
        assert cfg["url"] == "127-0-0-1-8921" and adapter == "direct_api"
        assert "-> config" in capsys.readouterr().err


import inspect  # noqa: E402
import json  # noqa: E402


def ns(**kw):
    base = dict(json=False, no_wait=False, timeout=60, interval=1, name="wave", controls=None, force=False,
                qpm=None, wait_ms=None, base=None, yes=True, keep_key=False, detail=False, app=None)
    base.update(kw)
    return types.SimpleNamespace(**base)


class TestDuplicateNameRefused:
    def test_a_name_that_exists_is_refused_with_the_adopt_hint(self, capsys):
        c = types.SimpleNamespace(list_apps=lambda: [{"id": "aapp_old", "name": "Multi A"}])
        with pytest.raises(SystemExit) as ei:
            ascend._refuse_duplicate_app_name(c, "Multi A", "multi-dup")
        err = capsys.readouterr().err
        assert ei.value.code == ascend.EXIT_USAGE
        assert "aapp_old" in err and "--app 'Multi A'" in err and "multi-dup" in err

    def test_a_new_name_passes(self):
        c = types.SimpleNamespace(list_apps=lambda: [{"id": "aapp_old", "name": "Multi A"}])
        assert ascend._refuse_duplicate_app_name(c, "Multi B", "multi-b") is None

    def test_registration_checks_before_it_creates(self):
        src = inspect.getsource(ascend.cmd_onboard)
        assert src.index("_refuse_duplicate_app_name(") < src.index("c.create_app(api.build_thin_spec(")


class TestTargetListDuplicates:
    def test_same_named_targets_are_flagged_with_their_ids(self, monkeypatch, capsys):
        store = {"aapp_1": {"app_name": "Twin", "config": "twin-1", "thin_api_key": "k"},
                 "aapp_2": {"app_name": "Twin", "config": "twin-2", "thin_api_key": "k"},
                 "aapp_3": {"app_name": "Solo", "config": "solo", "thin_api_key": "k"}}
        monkeypatch.setitem(sys.modules, "creds", types.SimpleNamespace(load_all=lambda: store))
        monkeypatch.setitem(sys.modules, "supervisor", types.SimpleNamespace(ls=lambda: []))
        monkeypatch.setattr(ascend, "_client", lambda a: types.SimpleNamespace(
            list_apps=lambda: [{"id": i} for i in store]))
        monkeypatch.setattr(ascend, "_adapter_for", lambda r: "direct_api", raising=False)
        ascend.cmd_target_list(ns())
        out = capsys.readouterr().out
        assert "2 targets are named 'Twin'" in out and "aapp_1" in out and "aapp_2" in out
        assert "Solo" in out and "named 'Solo'" not in out


class _FleetClient:
    """Two apps; each run reports running once, then complete."""
    def __init__(self):
        self.polls = {}
        self.token = "t"

    def list_apps(self):
        return [{"id": "aapp_a", "name": "A", "api_type": "api"}, {"id": "aapp_b", "name": "B", "api_type": "api"}]

    def run(self, appid, name, wait=False, **kw):
        return {"assessment_id": f"asmt_{appid}", "status": "running"}

    def get_assessment(self, appid, aid):
        n = self.polls[appid] = self.polls.get(appid, 0) + 1
        if n < 2:
            return {"id": aid, "status": "running", "progress": 0.5}
        return {"id": aid, "status": "complete", "progress": 1, "severity": "low", "total": 4,
                "category_summary": [{"failed": 1}]}


@pytest.fixture
def fleet(monkeypatch):
    c = _FleetClient()
    monkeypatch.setattr(ascend, "_resolve_app", lambda c, r: {"A": "aapp_a", "B": "aapp_b"}[r])
    monkeypatch.setattr(ascend, "_scope_run_controls", lambda *a, **k: None)
    monkeypatch.setattr(ascend, "_ensure_bridge", lambda c, appid, args=None: {"app_id": appid, "ensured": False, "reason": "native"})
    monkeypatch.setattr(ascend, "needs_bridge", lambda a: False)
    monkeypatch.setattr(ascend, "_supervise_bridge", lambda *a, **k: None)
    monkeypatch.setattr(ascend, "_bind_assessment", lambda *a, **k: None)
    monkeypatch.setattr(ascend, "_release_bridge", lambda *a, **k: None)
    monkeypatch.setattr(ascend.time, "sleep", lambda s: None)
    return c


class TestFleetWaits:
    def test_the_fleet_form_waits_and_summarises(self, fleet, capsys):
        ascend._assess_run_many(ns(), fleet, ["A", "B"])          # no SystemExit: both complete
        out = capsys.readouterr().out
        assert "APP" in out and "complete" in out and "asmt_aapp_a" in out and "asmt_aapp_b" in out
        assert "1/4" in out, "failed/total from probe_counts"
        assert "watch them" not in out, "a waited fleet has nothing to watch afterwards"

    def test_no_wait_keeps_the_fire_and_forget_form(self, fleet, capsys):
        ascend._assess_run_many(ns(no_wait=True), fleet, ["A", "B"])
        out = capsys.readouterr().out
        assert "watch them" in out and "APP" not in out
        assert fleet.polls == {}, "--no-wait must not poll"

    def test_json_is_one_document_with_results(self, fleet, capsys):
        ascend._assess_run_many(ns(json=True), fleet, ["A", "B"])
        d = json.loads(capsys.readouterr().out)                    # exactly one JSON document
        assert {r["status"] for r in d["results"]} == {"complete"} and len(d["started"]) == 2

    def test_an_unfinished_run_exits_1(self, fleet, monkeypatch, capsys):
        monkeypatch.setattr(fleet, "get_assessment", lambda appid, aid: {"id": aid, "status": "running", "progress": 0.1})
        monkeypatch.setattr(ascend.time, "time", (lambda t0=[ascend.time.time()]: (lambda: t0.__setitem__(0, t0[0] + 40) or t0[0]))())
        with pytest.raises(SystemExit) as ei:
            ascend._assess_run_many(ns(timeout=60), fleet, ["A", "B"])
        assert ei.value.code == ascend.EXIT_ERROR
        assert "did not finish" in capsys.readouterr().out


class TestResultsOnARunningRun:
    def test_says_so_instead_of_question_marks(self, monkeypatch, capsys):
        c = types.SimpleNamespace(get_assessment=lambda appid, aid: {"id": aid, "status": "running", "progress": 0.4})
        monkeypatch.setattr(ascend, "_client", lambda a: c)
        monkeypatch.setattr(ascend, "_resolve_app", lambda c, r: "aapp_1")
        monkeypatch.setattr(ascend, "_resolve_assessment", lambda c, appid, args, verb="": "asmt_9")
        ascend.cmd_assess_results(ns(app="A", assessment=None))
        out = capsys.readouterr().out
        assert "still running (40%)" in out and "assess watch" in out and "?" not in out


class TestRetireForgetsTheRelay:
    def test_retire_forgets_state_and_counts_live_runs(self, monkeypatch):
        calls = []
        monkeypatch.setitem(sys.modules, "supervisor", types.SimpleNamespace(
            is_running=lambda i: False, stop=lambda i: None, forget=lambda i: calls.append(("forget", i)) or True))
        monkeypatch.setitem(sys.modules, "creds", types.SimpleNamespace(remove=lambda i: True))
        monkeypatch.setattr(ascend, "_assessments_for", lambda c, i: [{"status": "running"}, {"status": "complete"}])
        c = types.SimpleNamespace(delete_app=lambda i: {"ok": True})
        r = ascend._retire_app(c, "aapp_1")
        assert calls == [("forget", "aapp_1")] and r["live_runs_cancelled"] == 1

    def test_supervisor_forget_is_real_and_refuses_a_live_relay(self, tmp_path, monkeypatch):
        import supervisor as S
        monkeypatch.setattr(S, "relays_dir", lambda: tmp_path)
        for k, pth in S.paths_for("aapp_z").items():
            pth.write_text("x")
        monkeypatch.setattr(S, "is_running", lambda i: True)
        assert S.forget("aapp_z") is False and all(p.exists() for p in S.paths_for("aapp_z").values())
        monkeypatch.setattr(S, "is_running", lambda i: False)
        assert S.forget("aapp_z") is True and not any(p.exists() for p in S.paths_for("aapp_z").values())
