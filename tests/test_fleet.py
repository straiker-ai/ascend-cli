"""
test_fleet — the round-4 fleet contract: single-tenant lock, the tc- key store, and the relay
supervisor. All offline; the supervisor is exercised with a real but harmless child process.

These pin the three properties that keep multi-engagement work safe:
  1. the CLI refuses a credential from a different tenant (crossing customers is the worst mistake);
  2. a key store you can look up by app, that prunes dead apps and never un-prunes them;
  3. relay liveness that can tell serving from dead — because a dead relay silently produces a
     FALSE PASS (unanswered probes are not findings).
"""
import base64
import json
import os
import sys
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "runtime"))


@pytest.fixture()
def home(tmp_path, monkeypatch):
    """Isolate ~/.ascend and the tenant state dir for every test."""
    monkeypatch.setenv("ASCEND_HOME", str(tmp_path / "ascend"))
    monkeypatch.delenv("ASCEND_STATE_DIR", raising=False)
    for mod in ("tenant", "creds", "supervisor"):
        sys.modules.pop(mod, None)
    import tenant
    monkeypatch.setattr(tenant, "ASCEND_HOME", tmp_path / "ascend")
    monkeypatch.setattr(tenant, "TENANT_FILE", tmp_path / "ascend" / "tenant.json")
    import creds
    monkeypatch.setattr(creds, "LEGACY_FILE", tmp_path / "ascend" / "creds")
    return tmp_path


def _jwt(straiker_id="6", email="me@acme.com", iss="https://pool/us-east-1_X"):
    hdr = base64.urlsafe_b64encode(b'{"alg":"none"}').decode().rstrip("=")
    body = base64.urlsafe_b64encode(json.dumps(
        {"iss": iss, "straikerId": straiker_id, "email": email, "role": "admin"}).encode()
    ).decode().rstrip("=")
    return f"{hdr}.{body}.sig"


# --------------------------------------------------------------------------- tenant lock
def test_pins_on_first_use_then_matches(home):
    import tenant
    first = tenant.check(_jwt())
    assert first["status"] == "pinned"
    again = tenant.check(_jwt())
    assert again["status"] == "ok"


def test_refuses_a_different_tenant(home):
    import tenant
    tenant.check(_jwt(straiker_id="6", email="me@acme.com"))
    with pytest.raises(tenant.TenantMismatch) as e:
        tenant.check(_jwt(straiker_id="99", email="them@other.com"))
    msg = str(e.value)
    assert "locked to tenant" in msg and "ascend tenant switch" in msg


def test_fingerprint_is_a_hash_not_the_raw_id(home):
    import tenant
    rec = tenant.check(_jwt(straiker_id="6"))
    stored = json.loads((home / "ascend" / "tenant.json").read_text())
    assert len(stored["fingerprint"]) == 64          # sha256 hex
    assert "straikerId" not in stored and "6" != stored["fingerprint"]
    assert rec["fingerprint"] == stored["fingerprint"]


def test_state_root_is_tenant_scoped(home):
    import tenant
    tenant.check(_jwt(straiker_id="6"))
    a = tenant.state_root()
    tenant.clear()
    tenant.check(_jwt(straiker_id="7"))
    assert tenant.state_root() != a                  # a switch can't reuse the other tenant's dir


def test_unknown_identity_does_not_pin(home):
    import tenant
    assert tenant.check("not-a-jwt")["status"] == "unknown"
    assert tenant.load() is None


# --------------------------------------------------------------------------- key store
def test_save_get_and_mask(home):
    import creds
    creds.save("aapp_1", "tc-abcdefgh-1234-zz", app_name="Bot", config="bot", adapter="direct_api")
    assert creds.key_for("aapp_1") == "tc-abcdefgh-1234-zz"
    rec = creds.get("aapp_1")
    assert rec["config"] == "bot" and rec["adapter"] == "direct_api"
    m = creds.mask("tc-abcdefgh-1234-zz")
    assert m.startswith("tc-") and m.endswith("zz") and "abcdefgh-1234" not in m


def test_legacy_jsonl_is_migrated_then_retired(home):
    import creds
    legacy = home / "ascend" / "creds"
    legacy.parent.mkdir(parents=True, exist_ok=True)
    legacy.write_text(
        json.dumps({"app_id": "aapp_old", "name": "Old", "thin_api_key": "tc-old"}) + "\n"
        + json.dumps({"app_id": "aapp_dup", "name": "Dup", "thin_api_key": "tc-1"}) + "\n"
        + json.dumps({"app_id": "aapp_dup", "name": "Dup", "thin_api_key": "tc-2"}) + "\n")
    recs = creds.load_all()
    assert recs["aapp_old"]["thin_api_key"] == "tc-old"
    assert recs["aapp_dup"]["thin_api_key"] == "tc-2"        # last line wins
    assert not legacy.exists() and legacy.with_name("creds.migrated").exists()


def test_prune_is_permanent(home):
    """The bug this guards: load_all() used to re-merge the legacy file, so pruned keys came back."""
    import creds
    legacy = home / "ascend" / "creds"
    legacy.parent.mkdir(parents=True, exist_ok=True)
    legacy.write_text(json.dumps({"app_id": "aapp_dead", "name": "Dead",
                                  "thin_api_key": "tc-dead"}) + "\n")
    creds.save("aapp_live", "tc-live", app_name="Live")
    assert set(creds.load_all()) == {"aapp_dead", "aapp_live"}
    assert creds.prune({"aapp_live"}) == ["aapp_dead"]
    assert set(creds.load_all()) == {"aapp_live"}            # and STAYS pruned
    assert set(creds.load_all()) == {"aapp_live"}


def test_remove_and_archive(home):
    import creds
    creds.save("aapp_1", "tc-1")
    creds.save("aapp_2", "tc-2")
    assert creds.remove("aapp_1") is True
    assert creds.get("aapp_1") is None
    assert creds.archive_all() == 1
    assert creds.load_all() == {}


# --------------------------------------------------------------------------- supervisor
def test_start_stop_and_liveness(home, monkeypatch):
    import tenant, supervisor as S
    tenant.check(_jwt())
    # a harmless long-lived child instead of a real relay
    monkeypatch.setattr(S, "REPO", REPO)
    r = S.start("aapp_x", config="c", adapter="direct_api", api_key="tc-test",
                python=sys.executable)
    # the spawned child is the real CLI; it will exit fast on a bad key/config, which is fine —
    # what we assert is the supervisor's own bookkeeping.
    assert r.get("pid") and S.read_pid("aapp_x") == r["pid"]
    assert S.paths_for("aapp_x")["log"].exists()
    dup = S.start("aapp_x", config="c", adapter="direct_api", api_key="tc-test")
    assert "already running" in str(dup.get("error", "")) or dup.get("pid") == r["pid"]
    out = S.stop("aapp_x")
    assert out["app_id"] == "aapp_x"
    assert S.read_pid("aapp_x") is None                       # pidfile cleaned up


def test_key_never_appears_in_child_argv(home, monkeypatch):
    """A tc- key on argv is readable by every local user via `ps`. It must go in the env."""
    import tenant, supervisor as S
    tenant.check(_jwt())
    seen = {}

    class FakeProc:
        pid = 4242

    def fake_popen(argv, **kw):
        seen["argv"] = argv
        seen["env"] = kw.get("env") or {}
        seen["new_session"] = kw.get("start_new_session")
        return FakeProc()

    monkeypatch.setattr(S.subprocess, "Popen", fake_popen)
    S.start("aapp_secret", config="c", adapter="direct_api", api_key="tc-SUPER-SECRET")
    assert "tc-SUPER-SECRET" not in " ".join(seen["argv"])
    assert seen["env"]["STRAIKER_BRIDGE_API_KEY"] == "tc-SUPER-SECRET"
    assert seen["new_session"] is True                        # detached: survives the terminal
    assert "--consumer" in seen["argv"]                       # parallel relays must differ


def test_ls_reports_dead_and_stale(home, monkeypatch):
    import tenant, supervisor as S
    tenant.check(_jwt())
    S.write_status("aapp_d", {"app_id": "aapp_d", "app_name": "D", "config": "c",
                              "pid": 999999, "ts": time.time(), "stats": {"answered": 3}})
    S.paths_for("aapp_d")["pid"].write_text("999999")         # a pid that isn't alive
    rows = {r["app_id"]: r for r in S.ls()}
    assert rows["aapp_d"]["state"] == "dead"
    # alive but no recent heartbeat => stale
    S.write_status("aapp_s", {"app_id": "aapp_s", "pid": os.getpid(),
                              "ts": time.time() - (S.HEARTBEAT_STALE_S + 60), "stats": {}})
    S.paths_for("aapp_s")["pid"].write_text(str(os.getpid()))
    rows = {r["app_id"]: r for r in S.ls()}
    assert rows["aapp_s"]["state"] == "stale"


def test_stale_pidfile_is_reaped(home):
    import tenant, supervisor as S
    tenant.check(_jwt())
    S.paths_for("aapp_z")["pid"].parent.mkdir(parents=True, exist_ok=True)
    S.paths_for("aapp_z")["pid"].write_text("999999")
    assert S.is_running("aapp_z") is False
    assert S.read_pid("aapp_z") is None


@pytest.fixture(autouse=True)
def _no_startup_grace(monkeypatch):
    """These tests are about pid/status bookkeeping and argv hygiene; their children are stand-ins
    (or die at once on a bogus config). supervisor.start() now watches a fresh child for its first
    heartbeat or its death, which would turn every start() here into a 3 s wait or a reported
    death. The real-child startup-death behaviour has its own test in test_p1_consistency.py."""
    monkeypatch.setenv("ASCEND_STARTUP_GRACE_S", "0")
