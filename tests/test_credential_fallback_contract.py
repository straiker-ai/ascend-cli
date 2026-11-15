"""Names-only fallback exclusions, using authored local stores and no network."""
import json
from pathlib import Path
import subprocess
import sys
import zipfile

import pytest
import target_secrets as secrets
from layers.auth import AuthError, AuthProvider, resolve_secret_ref

ENV = "_ASCEND_AGENT_WITHHELD_NAMES"
ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def stores(tmp_path, monkeypatch):
    paths = [tmp_path / "pinned.json", tmp_path / "unpinned.json"]
    for path in paths:
        path.write_text(json.dumps({"BLOCKED": {"value": "synthetic-stale-secret"},
                                    "OTHER": {"value": "synthetic-other-secret"}}))
        path.chmod(0o600)
    monkeypatch.setattr(secrets, "_paths", lambda: paths)
    for name in (ENV, "BLOCKED", "OTHER"):
        monkeypatch.delenv(name, raising=False)
    return paths


def test_excluded_name_never_reads_either_fallback(stores, monkeypatch):
    monkeypatch.setenv(ENV, '["BLOCKED"]')
    monkeypatch.setattr(secrets, "_paths", lambda: pytest.fail("excluded get read a store"))
    assert secrets.get("BLOCKED") is None
    with pytest.raises(AuthError) as error:
        resolve_secret_ref("env:BLOCKED")
    assert "BLOCKED" in str(error.value) and "synthetic-stale-secret" not in str(error.value)


def test_bulk_excludes_both_stores_without_mutating_them(stores, monkeypatch):
    before = [path.read_bytes() for path in stores]
    monkeypatch.setenv(ENV, '["BLOCKED"]')
    assert set(secrets.load_all()) == {"OTHER"}
    assert secrets.get("OTHER") == "synthetic-other-secret"
    assert [path.read_bytes() for path in stores] == before


@pytest.mark.parametrize("metadata", [None, "", "[]"])
def test_no_exclusions_preserve_existing_lookup(stores, monkeypatch, metadata):
    if metadata is not None:
        monkeypatch.setenv(ENV, metadata)
    assert secrets.get("BLOCKED") == "synthetic-stale-secret"
    assert set(secrets.load_all()) == {"BLOCKED", "OTHER"}


def test_fresh_environment_wins_and_exclusions_are_not_cached(stores, monkeypatch):
    monkeypatch.setenv(ENV, '["BLOCKED"]')
    monkeypatch.setenv("BLOCKED", "synthetic-corrected-secret")
    assert secrets.get("BLOCKED") == resolve_secret_ref("env:BLOCKED") == "synthetic-corrected-secret"
    monkeypatch.delenv("BLOCKED")
    assert secrets.get("BLOCKED") is None
    monkeypatch.setenv(ENV, "[]")
    assert secrets.get("BLOCKED") == "synthetic-stale-secret"


def test_public_auth_builder_never_materializes_a_withheld_stale_header(stores, monkeypatch):
    monkeypatch.setenv(ENV, '["BLOCKED"]')
    config = {"endpoint": "https://synthetic.example.test/chat",
              "auth": {"type": "static", "mode": "bearer", "value_ref": "env:BLOCKED"}}
    provider = AuthProvider.from_config(config)
    assert provider.needs_network is False
    with pytest.raises(AuthError):
        provider.materialize()
    assert provider.token is None
    monkeypatch.setenv("BLOCKED", "synthetic-corrected-secret")
    material = provider.materialize()
    assert material.headers == {"Authorization": "Bearer synthetic-corrected-secret"}
    assert config["endpoint"] == "https://synthetic.example.test/chat"
    assert config["auth"]["value_ref"] == "env:BLOCKED"


@pytest.mark.parametrize("metadata", ['{', '{}', '[null]', '["BAD-NAME"]'])
def test_malformed_metadata_never_restores_store_fallback(stores, monkeypatch, metadata):
    monkeypatch.setenv(ENV, metadata)
    assert secrets.get("BLOCKED") is None
    assert secrets.load_all() == {}
    monkeypatch.setenv("OTHER", "synthetic-explicit-secret")
    assert secrets.get("OTHER") == "synthetic-explicit-secret"


def test_nested_metadata_at_default_process_recursion_limit(stores, monkeypatch):
    monkeypatch.setenv(ENV, '[' * 1100 + ']' * 1100)
    previous = sys.getrecursionlimit()
    try:
        sys.setrecursionlimit(1000)  # pytest raises this; normal fresh processes use 1000.
        assert secrets.get("BLOCKED") is None
        assert secrets.load_all() == {}
    finally:
        sys.setrecursionlimit(previous)


@pytest.mark.parametrize("metadata", ['["BLOCKED"]', '{'])
def test_native_resolver_child_does_not_leak_or_contact_a_host(tmp_path, metadata):
    home, state = tmp_path / "home", tmp_path / "state"
    home.mkdir(); state.mkdir()
    value = "synthetic-native-stale-secret"
    store = state / "target_secrets.json"
    store.write_text(json.dumps({"BLOCKED": {"value": value}})); store.chmod(0o600)
    probe = tmp_path / "resolver_probe.py"
    probe.write_text('''import json, socket
def forbidden(*args, **kwargs):
    raise AssertionError("network unavailable in resolver fixture")
socket.socket.connect = forbidden
socket.getaddrinfo = forbidden
import target_secrets
from layers.auth import resolve_secret_ref, AuthError
assert target_secrets.get("BLOCKED") is None
assert "BLOCKED" not in target_secrets.load_all()
try:
    resolve_secret_ref("env:BLOCKED")
except AuthError as error:
    assert error.__cause__ is None and error.__context__ is None
    print(json.dumps({"unavailable": True, "error": str(error)}))
else:
    raise AssertionError("stale fallback was restored")
''')
    environment = {"HOME": str(home), "ASCEND_STATE_DIR": str(state),
                   "PYTHONPATH": str(ROOT / "runtime"), ENV: metadata}
    argv = [sys.executable, str(probe)]
    result = subprocess.run(argv, env=environment, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["unavailable"] is True
    assert value not in result.stdout + result.stderr + repr(argv)
    assert json.loads(store.read_text())["BLOCKED"]["value"] == value


def test_capability_marker_is_shipped_in_the_actual_wheel(tmp_path):
    destination = tmp_path / "wheel"
    destination.mkdir()
    result = subprocess.run([sys.executable, "-c",
        "from setuptools.build_meta import build_wheel; import sys; build_wheel(sys.argv[1])", str(destination)],
        cwd=ROOT, capture_output=True, text=True, timeout=45)
    assert result.returncode == 0, result.stderr
    wheel, = destination.glob("*.whl")
    with zipfile.ZipFile(wheel) as package:
        marker = json.loads(package.read("runtime/credential_contract.json"))
    assert marker == {"version": 1, "store_exclusion_environment": ENV}
