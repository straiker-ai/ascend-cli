"""
test_ambiguous_app_name.py — a name ambiguous on the tenant is resolved by THIS machine's binding.

Shared tenants accumulate same-named apps: demo apps re-registered over months, two engineers
onboarding the same bot, a teardown that failed. The demo tenant carries four such clusters, one
of them five apps deep. `_resolve_app` died on any of them, which produced a split-brain CLI:

    ascend target check 'Demo Bot'   -> worked   (reads the local binding)
    ascend assess run --app 'Demo Bot' -> error  (searched the tenant by name and gave up)

Same name, same machine, same second. `target add` writes down which app it registered, so the
answer was already on disk; resolution just did not look. It looks now, and says which app it
picked. With no binding — or more than one — it still refuses, because then the machine genuinely
does not know which app is meant.
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

DUPES = [{"id": "aapp_dupe1", "name": "Demo Bot"},
         {"id": "aapp_dupe2", "name": "Demo Bot"},
         {"id": "aapp_dupe3", "name": "Demo Bot"},
         {"id": "aapp_other", "name": "Payroll"}]


class _C:
    def list_apps(self):
        return list(DUPES)


def _bind(monkeypatch, mapping):
    """Stand in for the key store: {app_id: {"app_name": ...}}."""
    fake = types.SimpleNamespace(load_all=lambda: mapping)
    monkeypatch.setitem(sys.modules, "creds", fake)


def test_binding_resolves_a_name_the_tenant_duplicates(monkeypatch, capsys):
    _bind(monkeypatch, {"aapp_dupe2": {"app_name": "Demo Bot"},
                        "aapp_other": {"app_name": "Payroll"}})
    assert ascend._resolve_app(_C(), "Demo Bot") == "aapp_dupe2"
    err = capsys.readouterr().err
    assert "3 apps" in err and "aapp_dupe2" in err, "it must say which app it picked"
    assert "--app <aapp_id>" in err, "and how to pick a different one"


def test_the_binding_also_settles_a_destructive_command(monkeypatch):
    """exact=True is about refusing a SUBSTRING match, not about refusing a known app id."""
    _bind(monkeypatch, {"aapp_dupe3": {"app_name": "Demo Bot"}})
    assert ascend._resolve_app(_C(), "Demo Bot", exact=True) == "aapp_dupe3"


def test_no_local_binding_still_refuses(monkeypatch):
    _bind(monkeypatch, {"aapp_other": {"app_name": "Payroll"}})
    with pytest.raises(SystemExit):
        ascend._resolve_app(_C(), "Demo Bot")


def test_two_local_bindings_refuse_rather_than_guess(monkeypatch):
    """Two targets on this machine share the name: the machine does not know either."""
    _bind(monkeypatch, {"aapp_dupe1": {"app_name": "Demo Bot"},
                        "aapp_dupe2": {"app_name": "Demo Bot"}})
    with pytest.raises(SystemExit):
        ascend._resolve_app(_C(), "Demo Bot", exact=True)


def test_a_binding_to_an_app_that_no_longer_exists_is_ignored(monkeypatch):
    """A stale local record must not resolve to an app the tenant does not list."""
    _bind(monkeypatch, {"aapp_deleted": {"app_name": "Demo Bot"}})
    with pytest.raises(SystemExit):
        ascend._resolve_app(_C(), "Demo Bot")


def test_an_unambiguous_name_does_not_consult_the_store(monkeypatch):
    """The common path must not depend on the key store being readable."""
    def _boom():
        raise OSError("key store unreadable")
    monkeypatch.setitem(sys.modules, "creds", types.SimpleNamespace(load_all=_boom))
    assert ascend._resolve_app(_C(), "Payroll") == "aapp_other"


def test_an_unreadable_store_degrades_to_the_old_refusal(monkeypatch):
    def _boom():
        raise OSError("key store unreadable")
    monkeypatch.setitem(sys.modules, "creds", types.SimpleNamespace(load_all=_boom))
    with pytest.raises(SystemExit):
        ascend._resolve_app(_C(), "Demo Bot")


def test_the_note_fits_a_narrow_terminal(monkeypatch, capsys):
    """An aapp_ id is 27 characters. As one sentence the note wrapped MID-ID, so the id could not
    be copied by eye or by double-click — in a terminal, and in the docs tour video."""
    long_id = "aapp_dupe2"
    _bind(monkeypatch, {long_id: {"app_name": "Demo Bot"}})
    ascend._resolve_app(_C(), "Demo Bot")
    lines = capsys.readouterr().err.rstrip("\n").split("\n")
    assert len(lines) == 3, "three short lines, not one long one"
    for line in lines:
        assert len(line) <= 80, f"{len(line)} columns: {line!r}"
