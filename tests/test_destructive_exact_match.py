"""
test_destructive_exact_match.py — a command that changes or destroys an app takes the exact name.

`_resolve_app` falls back from an exact name to a case-insensitive substring match, which is a
convenience for `assess results --app bot` and a hazard for `target rm bot`: with one app whose
name contains "bot", the fallback deleted it. Every mutating command now passes `exact=True`, the
three deletes confirm on a terminal (never in a pipeline, `--yes` to skip), and they share one
retire helper that drops the stored bridge key only AFTER the platform delete succeeded — the old
`target rm` dropped the key first and exited 0 when the delete then failed.
"""
import inspect
import re
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

APPS = [{"id": "aapp_1", "name": "Demo Bot"}, {"id": "aapp_2", "name": "Robot Lab"},
        {"id": "aapp_3", "name": "Payroll"}]


class _C:
    def __init__(self, apps=APPS, fail_delete=None, log=None):
        self.apps, self.fail_delete, self.deleted = list(apps), fail_delete, []
        self.log = log if log is not None else []

    def list_apps(self):
        return list(self.apps)

    def get_app(self, app_id):
        return next((a for a in self.apps if a["id"] == app_id), None)

    def delete_app(self, app_id):
        if self.fail_delete:
            raise self.fail_delete
        self.log.append("delete")
        self.deleted.append(app_id)
        return {"ok": True}


def ns(**kw):
    base = dict(json=False, yes=False, keep_key=False, delete_app=False)
    base.update(kw)
    return types.SimpleNamespace(**base)


class TestExactResolution:
    def test_a_substring_is_refused_with_the_candidates(self, capsys):
        with pytest.raises(SystemExit) as ei:
            ascend._resolve_app(_C(), "bot", exact=True)
        err = capsys.readouterr().err
        assert "exactly" in err and "Demo Bot" in err and "Robot Lab" in err and "aapp_1" in err
        assert ei.value.code == ascend.EXIT_USAGE

    def test_the_default_keeps_the_substring_convenience(self):
        assert ascend._resolve_app(_C(), "payr") == "aapp_3"

    def test_an_exact_name_resolves(self):
        assert ascend._resolve_app(_C(), "Demo Bot", exact=True) == "aapp_1"

    def test_an_id_passes_through(self):
        assert ascend._resolve_app(_C(), "aapp_9", exact=True) == "aapp_9"

    def test_an_ambiguous_default_still_dies(self, capsys):
        with pytest.raises(SystemExit):
            ascend._resolve_app(_C(), "bot")
        assert "matches 2 apps" in capsys.readouterr().err


MUTATING = ["cmd_app_delete", "cmd_target_rm", "cmd_keys_rm", "cmd_app_update", "cmd_relay_stop",
            "cmd_assess_pause", "cmd_assess_resume", "cmd_policy_push", "cmd_keys_add"]


def _resolve_calls(src):
    """The argument text of every _resolve_app(...) call, nested parentheses included."""
    out = []
    for m in re.finditer(r"_resolve_app\(", src):
        depth, k = 1, m.end()
        while k < len(src) and depth:
            depth += {"(": 1, ")": -1}.get(src[k], 0)
            k += 1
        out.append(src[m.end():k - 1])
    return out


@pytest.mark.parametrize("fn", MUTATING)
def test_every_mutating_command_resolves_exactly(fn):
    src = inspect.getsource(getattr(ascend, fn))
    calls = _resolve_calls(src)
    assert calls, f"{fn} no longer resolves an app by name?"
    assert all("exact=True" in c for c in calls), f"{fn} still resolves fuzzily: {calls}"


@pytest.fixture
def tty(monkeypatch):
    monkeypatch.setattr(ascend, "_stdio_is_tty", lambda: True)


class TestConfirm:
    def test_the_tty_check_needs_both_ends(self, monkeypatch):
        monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
        monkeypatch.setattr(sys.stdout, "isatty", lambda: False)
        assert ascend._stdio_is_tty() is False

    def test_yes_skips_the_prompt(self, monkeypatch, tty):
        monkeypatch.setattr("builtins.input", lambda *_: pytest.fail("prompted despite --yes"))
        assert ascend._confirm_destroy(ns(yes=True), "x") is None

    def test_json_never_prompts(self, monkeypatch, tty):
        monkeypatch.setattr("builtins.input", lambda *_: pytest.fail("prompted under --json"))
        assert ascend._confirm_destroy(ns(json=True), "x") is None

    def test_a_pipeline_never_prompts(self, monkeypatch):
        monkeypatch.setattr(ascend, "_stdio_is_tty", lambda: False)
        monkeypatch.setattr("builtins.input", lambda *_: pytest.fail("prompted with no terminal"))
        assert ascend._confirm_destroy(ns(), "x") is None

    def test_no_aborts_with_exit_1_and_changes_nothing(self, monkeypatch, tty, capsys):
        monkeypatch.setattr("builtins.input", lambda *_: "n")
        with pytest.raises(SystemExit) as ei:
            ascend._confirm_destroy(ns(), "delete app X?")
        assert ei.value.code == ascend.EXIT_ERROR
        assert "aborted" in capsys.readouterr().err

    def test_enter_alone_aborts(self, monkeypatch, tty):
        monkeypatch.setattr("builtins.input", lambda *_: "")
        with pytest.raises(SystemExit):
            ascend._confirm_destroy(ns(), "x")

    def test_eof_aborts(self, monkeypatch, tty):
        def _eof(*_):
            raise EOFError
        monkeypatch.setattr("builtins.input", _eof)
        with pytest.raises(SystemExit):
            ascend._confirm_destroy(ns(), "x")

    def test_yes_answer_proceeds(self, monkeypatch, tty):
        monkeypatch.setattr("builtins.input", lambda *_: "y")
        assert ascend._confirm_destroy(ns(), "x") is None


@pytest.fixture
def stores(monkeypatch):
    log = []
    creds = types.SimpleNamespace(removed=[], remove=lambda app_id: (log.append("key"),
                                                                       creds.removed.append(app_id), True)[2])
    sup = types.SimpleNamespace(running=False,
                                is_running=lambda app_id: sup.running,
                                stop=lambda app_id, grace_s=8.0: (log.append("stop"), {"stopped": True})[1])
    monkeypatch.setitem(sys.modules, "creds", creds)
    monkeypatch.setitem(sys.modules, "supervisor", sup)
    return log, creds, sup


class TestRetireOrder:
    def test_the_key_is_kept_when_the_delete_fails(self, stores):
        log, creds, _ = stores
        c = _C(fail_delete=api.AscendAPIError("500 server error"), log=log)
        with pytest.raises(api.AscendAPIError):
            ascend._retire_app(c, "aapp_1")
        assert creds.removed == [], "a key dropped before a failed delete strands an unserviceable app"

    def test_the_key_goes_only_after_the_delete(self, stores):
        log, creds, sup = stores
        sup.running = True
        c = _C(log=log)
        r = ascend._retire_app(c, "aapp_1")
        assert log == ["stop", "delete", "key"]
        assert r["key_removed"] and r["bridge_stopped"] and c.deleted == ["aapp_1"]

    def test_keep_key(self, stores):
        log, creds, _ = stores
        r = ascend._retire_app(_C(log=log), "aapp_1", keep_key=True)
        assert creds.removed == [] and r["key_removed"] is False


class TestTheThreeDeletesShareIt:
    @pytest.mark.parametrize("fn", ["cmd_app_delete", "cmd_target_rm", "cmd_keys_rm"])
    def test_confirm_and_retire_are_the_shared_helpers(self, fn):
        src = inspect.getsource(getattr(ascend, fn))
        assert "_confirm_destroy(" in src and "_retire_app(" in src
        assert "delete_app(" not in src, f"{fn} deletes on its own instead of through _retire_app"

    def test_target_rm_exits_non_zero_and_keeps_the_key_when_the_delete_fails(self, stores, monkeypatch, capsys):
        log, creds, _ = stores
        c = _C(fail_delete=api.AscendAPIError("404 not found"), log=log)
        monkeypatch.setattr(ascend, "_client", lambda args: c)
        with pytest.raises(SystemExit) as ei:
            ascend.cmd_target_rm(ns(target="aapp_1", yes=True))
        assert ei.value.code == ascend.EXIT_ERROR
        assert creds.removed == []
        assert "keys prune" in capsys.readouterr().out

    def test_target_rm_json_carries_the_error(self, stores, monkeypatch, capsys):
        log, creds, _ = stores
        c = _C(fail_delete=api.AscendAPIError("500"), log=log)
        monkeypatch.setattr(ascend, "_client", lambda args: c)
        with pytest.raises(SystemExit):
            ascend.cmd_target_rm(ns(target="aapp_1", json=True))
        out = capsys.readouterr().out
        assert '"app_deleted": false' in out and '"error"' in out
