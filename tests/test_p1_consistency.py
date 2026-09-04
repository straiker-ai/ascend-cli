"""
test_p1_consistency.py — exit codes and --json shapes a pipeline can rely on.

Each test pins a contract that was broken in the enterprise-readiness sweep:
  * argparse usage errors exited 2 — the same code as EXIT_FINDINGS — with plain text under --json
  * `bridge start --json` / `bridge sync --json` returned before their failure exits
  * `bridge sync` exited 1 on every shared-tenant run this machine holds no key for
  * `assess watch --json` printed the final row twice
  * `--scaffold` was treated as a competing source for the positional
  * four copies of the --controls rule with three policies
  * `assess results` demanded --assessment although a resolver for "latest finished" existed
  * `bridge start --foreground` crashed on `wait_ms=None / 1000`
"""
import inspect
import json
import re
import subprocess
import sys
import types
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
for p in ("shells/cli", "runtime", "control"):
    if str(REPO / p) not in sys.path:
        sys.path.insert(0, str(REPO / p))
import ascend  # noqa: E402

CLI = [sys.executable, str(REPO / "shells" / "cli" / "ascend.py")]


def ns(**kw):
    base = dict(json=False, detail=False, once=False, interval=0, follow=False, out=None)
    base.update(kw)
    return types.SimpleNamespace(**base)


class TestUsageErrors:
    def test_the_parser_is_ours_all_the_way_down(self):
        p = ascend.build_parser() if hasattr(ascend, "build_parser") else None
        if p is None:
            pytest.skip("no build_parser export")
        assert isinstance(p, ascend._Parser)
        subs = [a for a in p._actions if isinstance(a, argparse_action_type())]
        assert subs and all(isinstance(sp, ascend._Parser) for sp in subs[0].choices.values())

    def test_an_unknown_command_exits_usage_not_findings(self):
        r = subprocess.run(CLI + ["not-a-command"], capture_output=True, text=True)
        assert r.returncode == ascend.EXIT_USAGE, (r.returncode, r.stderr)
        assert r.returncode != ascend.EXIT_FINDINGS
        assert "usage:" in r.stderr and "error:" in r.stderr

    def test_a_bad_flag_under_json_is_one_object(self):
        r = subprocess.run(CLI + ["--json", "assess", "results", "--app", "x", "--bogus"],
                           capture_output=True, text=True)
        assert r.returncode == ascend.EXIT_USAGE
        d = json.loads(r.stdout)                      # exactly one object, nothing else on stdout
        assert d["ok"] is False and d["error"]["code"] == "usage"
        assert "usage:" not in r.stdout


def argparse_action_type():
    import argparse
    return argparse._SubParsersAction


class TestBridgeStartJson:
    def test_none_started_exits_1_under_json_with_one_list(self, monkeypatch, capsys):
        monkeypatch.setattr(ascend, "_client", lambda a: types.SimpleNamespace(token="t"))
        monkeypatch.setattr(ascend, "_fleet_targets",
                            lambda a, c: [{"app_id": "aapp_1", "app_name": "A", "skip": "no stored bridge key"}])
        with pytest.raises(SystemExit) as ei:
            ascend.cmd_relay_start(ns(json=True, app=["A"], all_running=False, qpm=None, qpm_total=None,
                                      max_workers=None, wait_ms=None, foreground=False, bridge_base=None,
                                      idle_timeout=None, base=None))
        assert ei.value.code == ascend.EXIT_ERROR
        out = capsys.readouterr().out
        rows = json.loads(out)
        assert isinstance(rows, list) and rows[0]["started"] is False


@pytest.fixture
def sync_env(monkeypatch):
    apps = [{"id": "aapp_1", "name": "Mine", "api_type": "thin"},
            {"id": "aapp_2", "name": "Theirs", "api_type": "thin"}]
    c = types.SimpleNamespace(list_apps=lambda: apps, token="t")
    monkeypatch.setattr(ascend, "_client", lambda a: c)
    monkeypatch.setattr(ascend, "_assessments_for",
                        lambda c, appid: [{"id": "asmt", "status": "running"}])
    monkeypatch.setattr(ascend, "needs_bridge", lambda a: True)
    monkeypatch.setitem(sys.modules, "supervisor",
                        types.SimpleNamespace(is_serving=lambda i: False, stop=lambda i: None))
    ensure = {"aapp_1": {"started": True, "pid": 1}, "aapp_2": {"skip": "no stored bridge key for it"}}
    monkeypatch.setattr(ascend, "_ensure_bridge", lambda c, a, args=None: dict(ensure[a["id"]]))
    return ensure


class TestBridgeSync:
    def test_unscoped_a_key_this_machine_lacks_is_reported_not_failed(self, sync_env, capsys):
        ascend.cmd_bridge_sync(ns(json=True, app=None, no_stop=False))
        d = json.loads(capsys.readouterr().out)
        assert d["started"] == ["Mine"] and d["unserved"][0]["app"] == "Theirs" and d["failed"] == []
        assert d["skipped"], "the pre-1.1.3 key stays for existing consumers"

    def test_scoped_to_an_app_it_cannot_serve_is_a_failure(self, sync_env, monkeypatch, capsys):
        monkeypatch.setattr(ascend, "_resolve_app", lambda c, r: "aapp_2")
        with pytest.raises(SystemExit) as ei:
            ascend.cmd_bridge_sync(ns(json=True, app=["Theirs"], no_stop=False))
        assert ei.value.code == ascend.EXIT_ERROR
        assert json.loads(capsys.readouterr().out)["failed"][0]["app"] == "Theirs"

    def test_a_start_that_failed_is_a_failure_even_unscoped(self, sync_env, capsys):
        sync_env["aapp_2"] = {"error": "spawn failed"}
        with pytest.raises(SystemExit):
            ascend.cmd_bridge_sync(ns(json=True, app=None, no_stop=False))
        assert json.loads(capsys.readouterr().out)["failed"][0]["reason"] == "spawn failed"

    def test_human_output_exits_0_with_unserved_apps(self, sync_env, capsys):
        ascend.cmd_bridge_sync(ns(json=False, app=None, no_stop=False))
        out = capsys.readouterr().out
        assert "not served from here" in out and "Theirs" in out


class TestWatchJson:
    def test_a_finished_run_is_printed_once(self, monkeypatch, capsys):
        row = {"id": "asmt_1", "status": "complete", "progress": 1, "category_summary": []}
        c = types.SimpleNamespace(get_assessment=lambda appid, aid: dict(row))
        monkeypatch.setattr(ascend, "_client", lambda a: c)
        monkeypatch.setattr(ascend, "_app_refs", lambda a: ["A"])
        monkeypatch.setattr(ascend, "_resolve_app", lambda c, r: "aapp_1")
        monkeypatch.setattr(sys.stdout, "isatty", lambda: False)
        ascend.cmd_assess_watch(ns(json=True, app="A", assessment="asmt_1", all=False))
        lines = [l for l in capsys.readouterr().out.splitlines() if l.strip()]
        assert len(lines) == 1 and json.loads(lines[0])["id"] == "asmt_1"


class TestScaffoldPositional:
    def test_scaffold_is_not_a_competing_source(self):
        src = inspect.getsource(ascend.cmd_target_add)
        conflict = src[: src.index("not both")]
        conflict = conflict[conflict.rindex("if any("):]
        assert "scaffold" not in conflict, "a positional URL plus --scaffold is the documented shape"
        nothing = src[src.index("nothing to onboard") - 400: src.index("nothing to onboard")]
        assert "scaffold" in nothing, "a scaffold-only invocation must still count as something to do"


class _CV:
    def __init__(self, unknown=(), valid=("a",), warnings=()):
        self.v = {"unknown": list(unknown), "valid": list(valid), "warnings": list(warnings)}

    def validate_controls(self, ids):
        return dict(self.v)


class TestControlsRule:
    def test_unknown_is_refused_unless_forced(self, capsys):
        with pytest.raises(SystemExit) as ei:
            ascend._validated_control_ids(_CV(unknown=["zzz"]), ["a", "zzz"])
        assert ei.value.code == ascend.EXIT_USAGE and "zzz" in capsys.readouterr().err
        assert ascend._validated_control_ids(_CV(unknown=["zzz"]), ["a", "zzz"], force=True) == ["a"]

    def test_nothing_scorable_is_refused_unless_forced(self):
        with pytest.raises(SystemExit):
            ascend._validated_control_ids(_CV(valid=[]), ["dep"])
        assert ascend._validated_control_ids(_CV(valid=[]), ["dep"], force=True) == ["dep"]

    def test_warnings_go_through_the_given_printer(self):
        got = []
        ascend._validated_control_ids(_CV(warnings=["old id"]), ["a"], say=got.append)
        assert got == ["warning: old id"]

    @pytest.mark.parametrize("fn", ["cmd_app_create", "cmd_app_update", "cmd_assess_run", "cmd_onboard"])
    def test_every_controls_site_uses_the_one_rule(self, fn):
        src = inspect.getsource(getattr(ascend, fn))
        assert "_validated_control_ids(" in src
        assert "validate_controls(" not in src, f"{fn} still validates on its own"


class TestResultsDefault:
    def test_no_assessment_means_the_latest_finished_run(self, monkeypatch, capsys):
        seen = {}
        c = types.SimpleNamespace(get_assessment=lambda appid, aid: {"id": aid, "status": "complete",
                                                                     "category_summary": [], "total": 4})
        monkeypatch.setattr(ascend, "_client", lambda a: c)
        monkeypatch.setattr(ascend, "_resolve_app", lambda c, r: "aapp_1")
        monkeypatch.setattr(ascend, "_resolve_assessment",
                            lambda c, appid, args, verb="": seen.setdefault("called", True) and "asmt_latest")
        monkeypatch.setattr(ascend, "_false_pass_warning", lambda a: "WARN: measured nothing")
        ascend.cmd_assess_results(ns(json=True, app="A", assessment=None))
        d = json.loads(capsys.readouterr().out)
        assert seen["called"] and d["id"] == "asmt_latest"
        assert d["false_pass_suspect"] is True and "measured nothing" in d["false_pass_warning"]

    def test_the_flag_is_optional_in_the_parser(self):
        r = subprocess.run(CLI + ["assess", "results", "--help"], capture_output=True, text=True)
        assert "latest finished" in r.stdout


class TestJsonShapes:
    def test_app_resolve_json(self, monkeypatch, capsys):
        monkeypatch.setattr(ascend, "_client", lambda a: None)
        monkeypatch.setattr(ascend, "_resolve_app", lambda c, r: "aapp_9")
        ascend.cmd_app_resolve(ns(json=True, name="Demo"))
        assert json.loads(capsys.readouterr().out)["app_id"] == "aapp_9"

    def test_bridge_logs_json(self, monkeypatch, capsys, tmp_path):
        log = tmp_path / "x.log"; log.write_text("hello relay\n")
        monkeypatch.setitem(sys.modules, "supervisor", types.SimpleNamespace(paths_for=lambda i: {"log": log}))
        ascend.cmd_relay_logs(ns(json=True, app="aapp_1", follow=False))
        d = json.loads(capsys.readouterr().out)
        assert d["tail"] == "hello relay\n" and d["log"].endswith("x.log")

    def test_export_out_keeps_stdout_empty(self):
        src = inspect.getsource(ascend.cmd_export)
        assert re.search(r'print\(f"wrote \{args\.out\}", file=sys\.stderr\)', src)


class TestForeground:
    def test_namespace_is_completed_from_the_runtime_parser(self, monkeypatch):
        got = {}
        monkeypatch.setattr(ascend, "cmd_runtime_start", lambda a: got.update(vars(a)))
        monkeypatch.setattr(ascend, "_client", lambda a: None)
        monkeypatch.setattr(ascend, "_resolve_app", lambda c, r: "aapp_77")
        ascend._bridge_start_foreground(ns(app=["A"], config="c", foreground=True, wait_ms=None, qpm=None,
                                           max_workers=None, idle_timeout=None, bridge_base=None))
        assert got["wait_ms"] == 25000, "the runtime default, not None (which crashed on /1000)"
        assert "status_file" in got
        # Registered under the app ID with the fleet's consumer scheme — a relay known only by a
        # name is invisible to is_serving(), and assess run then starts a second one.
        assert got["app"] == "aapp_77" and got["consumer"] == "abv2-aapp_77"

    def test_the_runtime_parser_and_the_helper_are_one(self):
        src = (REPO / "shells" / "cli" / "ascend.py").read_text()
        assert src.count('"--wait-ms"') == 2, "runtime start's flags must be defined once, in the helper (+ the fleet's own)"


class TestStartupDeath:
    def test_an_explicit_config_that_does_not_exist_is_a_skip_not_a_spawn(self, monkeypatch):
        monkeypatch.setattr(ascend, "resolve_config_path", lambda n: None)
        store = {"aapp_1": {"thin_api_key": "tc-k", "config": "real", "app_name": "A"}}
        r = ascend._target_for("aapp_1", store=store, config_override="no-such-config")
        assert "not found" in r.get("skip", "")
        monkeypatch.setattr(ascend, "resolve_config_path", lambda n: Path("/x/real.json"))
        assert "skip" not in ascend._target_for("aapp_1", store=store, config_override="real")

    def test_a_relay_that_dies_at_startup_is_an_error_not_a_pid(self, tmp_path, monkeypatch):
        """Real child process, real death: the config does not exist, so `runtime start` exits."""
        import supervisor as S
        monkeypatch.setattr(S, "relays_dir", lambda: tmp_path)
        r = S.start("aapp_startup_death", config="no-such-config-xyz", adapter=None, api_key="tc-test",
                    self_reconcile=False)
        assert "error" in r and "exited at startup" in r["error"], r
        assert S.read_pid("aapp_startup_death") is None, "a dead child must not leave a pidfile"
