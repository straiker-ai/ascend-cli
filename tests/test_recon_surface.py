"""
test_recon_surface.py — reconnaissance as a first-class step, the way the Console models it.

In the Console, recon (capability enumeration) is started separately from an assessment. The CLI
gives that one noun: `ascend recon run|list|show|results|controls`, and `ascend assess run
--with-recon` / `--recon-only`. The public v3 API does not serve recon yet, so every call goes
through one seam that turns a 404 into a single honest line — a tenant that gains the endpoint
needs no CLI change.
"""
import inspect
import json
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
import api  # noqa: E402

CLI = [sys.executable, str(REPO / "shells" / "cli" / "ascend.py")]


def ns(**kw):
    base = dict(json=False, app="Demo Bot", name=None, controls=None, recon_controls=None, no_wait=False,
                interval=1, timeout=30, recon=None, category=None)
    base.update(kw)
    return types.SimpleNamespace(**base)


class _NotYet:
    """A tenant whose API has no recon paths: every recon call is a 404."""
    def __getattr__(self, name):
        if name.startswith("recon_"):
            def _missing(*a, **k):
                raise api.AscendAPIError(f"GET /ascend/recon/x -> 404: {{\"detail\":\"Not Found\"}}")
            return _missing
        raise AttributeError(name)

    def list_apps(self):
        return [{"id": "aapp_1", "name": "Demo Bot"}]


DETAIL = {"id": "rq_1", "status": "complete", "total_tasks": 3, "completed_tasks": 3, "matched_tasks": 2,
          "control_summaries": [
              {"category": "Tool Reconnaissance", "control": "database_tools", "goal_matched": True, "total_turns": 4},
              {"category": "Tool Reconnaissance", "control": "code_interpreter", "goal_matched": False, "total_turns": 6},
              {"category": "Architecture", "control": "rag_sources", "goal_matched": True, "total_turns": 3}],
          "category_summaries": {"Tool Reconnaissance": {"summarized_recon_structured": "SQL tool confirmed."}}}


class _Ready:
    """A tenant that serves recon: start -> running once -> complete."""
    def __init__(self):
        self.calls = []
        self.polls = 0

    def list_apps(self):
        return [{"id": "aapp_1", "name": "Demo Bot"}]

    def recon_controls(self):
        self.calls.append("controls")
        return {"categories": [{"id": "tools", "name": "Tool Reconnaissance", "description": "which tools exist",
                                "controls": [{"id": "database_tools", "name": "Database tools", "max_turn": 6}]}]}

    def recon_start(self, app_id, *, name=None, controls=None):
        self.calls.append(("start", app_id, name, controls))
        return {"id": "rq_1", "status": "running"}

    def recon_get(self, app_id, rid):
        self.polls += 1
        return {**DETAIL, "status": "running" if self.polls < 2 else "complete"}

    def recon_list(self, app_id):
        return {"recon_requests": [{"id": "rq_1", "status": "complete", "created_at": "2026-09-04T10:00:00Z", "controls": []}]}

    def recon_results(self, app_id, *, category=None):
        return {"controls": DETAIL["control_summaries"], "matched_controls": 2, "category_summaries": {}}


@pytest.fixture(autouse=True)
def _fast(monkeypatch):
    monkeypatch.setattr(ascend.time, "sleep", lambda s: None)


class TestNotExposedYet:
    def test_every_recon_verb_says_so_in_one_line(self, monkeypatch, capsys):
        monkeypatch.setattr(ascend, "_client", lambda a: _NotYet())
        for fn, a in ((ascend.cmd_recon_controls, ns()), (ascend.cmd_recon_run, ns()),
                      (ascend.cmd_recon_list, ns()), (ascend.cmd_recon_results, ns())):
            with pytest.raises(SystemExit) as ei:
                fn(a)
            assert ei.value.code == ascend.EXIT_ERROR
            assert "not exposed by the Ascend API on this tenant yet" in capsys.readouterr().err

    def test_json_carries_a_stable_code(self, monkeypatch, capsys):
        monkeypatch.setattr(ascend, "_client", lambda a: _NotYet())
        monkeypatch.setattr(ascend, "_wants_json", lambda: True)
        with pytest.raises(SystemExit):
            ascend.cmd_recon_controls(ns(json=True))
        d = json.loads(capsys.readouterr().out)
        assert d["ok"] is False and d["error"]["code"] == "recon_unavailable"

    def test_other_api_errors_are_not_swallowed(self):
        def boom():
            raise api.AscendAPIError("GET /x -> 500: server on fire")
        with pytest.raises(api.AscendAPIError):
            ascend._recon_call(boom)


class TestWhenTheTenantServesRecon:
    def test_run_follows_to_completion_and_summarises(self, monkeypatch, capsys):
        c = _Ready()
        monkeypatch.setattr(ascend, "_client", lambda a: c)
        ascend.cmd_recon_run(ns(name="r1", controls="database_tools,rag_sources"))
        out = capsys.readouterr().out
        assert ("start", "aapp_1", "r1", ["database_tools", "rag_sources"]) in c.calls
        assert "2/3 capabilities found" in out and "database_tools" in out and "SQL tool confirmed" in out

    def test_controls_catalog_renders(self, monkeypatch, capsys):
        monkeypatch.setattr(ascend, "_client", lambda a: _Ready())
        ascend.cmd_recon_controls(ns())
        out = capsys.readouterr().out
        assert "Tool Reconnaissance" in out and "database_tools" in out and "1 recon control(s)" in out

    def test_show_defaults_to_the_latest_run(self, monkeypatch, capsys):
        monkeypatch.setattr(ascend, "_client", lambda a: _Ready())
        ascend.cmd_recon_show(ns())
        assert "rq_1" in capsys.readouterr().err


class TestAssessRunIntegration:
    def test_recon_only_delegates_to_recon_run(self):
        src = inspect.getsource(ascend.cmd_assess_run)
        assert 'getattr(args, "recon_only", False)' in src and "return cmd_recon_run(args)" in src

    def test_with_recon_runs_recon_before_the_assessment(self):
        src = inspect.getsource(ascend.cmd_assess_run)
        i = src.index("_run_recon_before_assessment(c, appid, refs[0], args)")
        j = src.index("ensure = _ensure_bridge(c, appid, args=args)")
        assert i < j, "recon must complete before the relay and the attack run start"

    def test_the_flags_exist(self):
        r = subprocess.run(CLI + ["assess", "run", "--help"], capture_output=True, text=True)
        assert "--with-recon" in r.stdout and "--recon-only" in r.stdout and "--recon-controls" in r.stdout
        r = subprocess.run(CLI + ["recon", "--help"], capture_output=True, text=True)
        assert r.returncode == 0 and all(v in r.stdout for v in ("controls", "run", "list", "show", "results"))
