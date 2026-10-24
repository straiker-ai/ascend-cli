"""
test_self_authenticating — the `self_authenticating` marker `ascend target inspect` emits, and that
it can never disagree with the transport choice.

A public target whose login the hosted adaptor completes end to end — the engine mints or echoes
the credential every turn — has NOTHING for the operator to supply. `ascend connect` keys its
no-throwaway-bearer path on an inspect marker, and this is the CLI half that sets it.

`_self_authenticating(adapter, cfg)` is the SINGLE predicate behind both the marker and the
`not static_auth` adaptor branch of `_choose_transport` (which calls it). These tests pin the marker
across the four cases the task names — a public machine-login contract (set), and a human-login /
static-auth / private one (absent) — and assert, case by case, that the predicate and the live
transport decision agree, so the marker and `target add --via auto` can never diverge.
"""
from __future__ import annotations

import json
import sys
import types
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
for _p in (REPO / "shells" / "cli", REPO / "runtime", REPO / "control", REPO):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))
import ascend  # noqa: E402
from runtime.discovery import profiles  # noqa: E402

PUBLIC = "https://8.8.8.8/c"          # an IP literal: globally routable, no DNS lookup
PRIVATE = "http://127.0.0.1:1/c"
MACHINE_KINDS = ["oauth2", "csrf", "derived_multihop"]     # machine-completable logins
HUMAN_GRANTS = ["authorization_code", "device_code", "implicit"]   # a person in the loop


def _args(url, **kw):
    return types.SimpleNamespace(**{"via": "auto", "source": url, "insecure": False,
                                    "header": None, "bearer": None, "json": False, **kw})


# ------------------------------------------------------------------ the predicate
class TestTheSelfAuthenticatingPredicate:
    @pytest.mark.parametrize("kind", MACHINE_KINDS)
    def test_a_public_machine_login_is_self_authenticating(self, kind):
        assert ascend._self_authenticating("direct_api", {"endpoint": PUBLIC, "auth": {"type": kind}}) is True

    @pytest.mark.parametrize("grant", HUMAN_GRANTS)
    def test_a_human_login_is_not(self, grant):
        # A person has to complete it, so the operator (and the engine) cannot: not self-authenticating.
        cfg = {"endpoint": PUBLIC, "auth": {"type": "oauth2", "grant": grant}}
        assert ascend._self_authenticating("direct_api", cfg) is False

    @pytest.mark.parametrize("auth", [{"type": "static"}, None])
    def test_static_or_no_auth_is_not(self, auth):
        # The operator carries the key (or there is none to mint): a plain adaptor, not a login one.
        cfg = {"endpoint": PUBLIC}
        if auth is not None:
            cfg["auth"] = auth
        assert ascend._self_authenticating("direct_api", cfg) is False

    @pytest.mark.parametrize("kind", MACHINE_KINDS)
    def test_a_private_target_is_not_even_with_a_machine_login(self, kind):
        # The engine cannot dial it, so no hosted adaptor could run — and the predicate must NOT
        # raise (unlike `_choose_transport`, which _die()s): inspect has to stay read-only.
        assert ascend._self_authenticating("direct_api", {"endpoint": PRIVATE, "auth": {"type": kind}}) is False

    @pytest.mark.parametrize("adapter", list(ascend.LOCAL_ONLY_ADAPTERS))
    def test_a_local_only_adapter_is_not(self, adapter):
        assert ascend._self_authenticating(adapter, {"endpoint": PUBLIC, "auth": {"type": "oauth2"}}) is False

    def test_a_routed_target_is_not(self):
        cfg = {"endpoint": "https://demo.tun.straiker.ai/c", "auth": {"type": "oauth2"}}
        assert ascend._self_authenticating("direct_api", cfg) is False


# ------------------------------------------------------------------ never disagrees with the transport
class TestTheMarkerTracksTheTransportChoice:
    """For every contract, the marker is True exactly when `target add --via auto` would route it to
    the hosted LOGIN adaptor (transport == adaptor AND the reason names the handshake). One predicate
    decides both, so this can only ever hold."""

    def _routes_to_login_adaptor(self, adapter, cfg):
        try:
            via, why = ascend._choose_transport(_args(cfg.get("endpoint") or ""), adapter, cfg)
        except SystemExit:
            return False               # a private target is refused: not a hosted adaptor
        kind = ascend._auth_type(cfg)
        return via == "adaptor" and kind in ascend.DYNAMIC_AUTH_KINDS and str(kind) in why

    @pytest.mark.parametrize("adapter,cfg", [
        ("direct_api", {"endpoint": PUBLIC, "auth": {"type": "oauth2"}}),                      # machine login -> True
        ("direct_api", {"endpoint": PUBLIC, "auth": {"type": "csrf"}}),
        ("direct_api", {"endpoint": PUBLIC, "auth": {"type": "derived_multihop"}}),
        ("direct_api", {"endpoint": PUBLIC, "auth": {"type": "oauth2", "grant": "authorization_code"}}),  # human -> False
        ("direct_api", {"endpoint": PUBLIC, "auth": {"type": "static"}}),                      # static -> False
        ("direct_api", {"endpoint": PUBLIC}),                                                  # no auth -> False
        ("direct_api", {"endpoint": PRIVATE, "auth": {"type": "oauth2"}}),                     # private -> False
        ("custom", {"endpoint": PUBLIC, "auth": {"type": "oauth2"}}),                          # local-only -> False
    ])
    def test_marker_equals_login_adaptor_routing(self, adapter, cfg):
        assert ascend._self_authenticating(adapter, cfg) is self._routes_to_login_adaptor(adapter, cfg)


# ------------------------------------------------------------------ `ascend target inspect` emits it
class _Console:
    def _rows(self, v):
        return v.get("data", []) if isinstance(v, dict) else (v or [])

    def list_apps(self):
        return {"data": []}


def _fake_profile(auth, endpoint=PUBLIC, adapter="direct_api"):
    class _FakeProfile:
        name = "fake"
        label = "Fake agent"

        @staticmethod
        def inspect(origin, headers, verify=True):
            out = {"profile": "fake", "label": "Fake agent", "origin": origin,
                   "endpoint": endpoint, "adapter": adapter, "needs": [], "workspaces": []}
            if auth is not None:
                out["auth"] = auth
            return out
    return _FakeProfile


class TestInspectEmitsTheMarker:
    @pytest.fixture(autouse=True)
    def wired(self, monkeypatch):
        monkeypatch.delenv("ASCEND_TARGET_AUTH_FILE", raising=False)
        monkeypatch.setattr(ascend, "_client", lambda args: _Console())

    def _inspect_json(self, monkeypatch, capsys, *, auth, endpoint=PUBLIC):
        monkeypatch.setattr(profiles, "detect", lambda url, verify=True: _fake_profile(auth, endpoint))
        ascend.cmd_target_inspect(_args(endpoint, json=True))
        return json.loads(capsys.readouterr().out)

    @pytest.mark.parametrize("kind", MACHINE_KINDS)
    def test_a_public_machine_login_inspect_sets_the_marker(self, kind, monkeypatch, capsys):
        out = self._inspect_json(monkeypatch, capsys, auth={"type": kind})
        assert out.get("self_authenticating") is True

    @pytest.mark.parametrize("auth,endpoint", [
        ({"type": "oauth2", "grant": "authorization_code"}, PUBLIC),   # human login
        ({"type": "static"}, PUBLIC),                                  # static auth
        (None, PUBLIC),                                                # no auth
        ({"type": "oauth2"}, PRIVATE),                                 # private
    ])
    def test_everything_else_leaves_the_marker_absent(self, auth, endpoint, monkeypatch, capsys):
        out = self._inspect_json(monkeypatch, capsys, auth=auth, endpoint=endpoint)
        assert "self_authenticating" not in out
