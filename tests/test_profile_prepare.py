"""Synthetic producer contracts: no sockets, stores, platform clients or execution."""
from copy import deepcopy
import base64
import hashlib
import json
import socket
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
import requests

from runtime.discovery import profile_prepare as prepare
from runtime.discovery import profiles
from shells.cli import ascend as cli

ORIGIN = "https://profile.example.test"
ACCESS = "synthetic-access-credential-001"
KEY = "synthetic-scoring-credential-002"
SHARE = "synthetic-workspace-credential-003"
ENV = {"ACCESS": ACCESS, "KEY": KEY, "SHARE": SHARE}
SLOTS = [{"origin": ORIGIN, "in": kind, "field": name, "reference": "env:" + ref}
         for kind, name, ref in (("header", "x-demo-key", "ACCESS"),
                                 ("body", "apiKey", "KEY"), ("body", "workspace", "SHARE"))]
WORKSPACE = {"slug": "chosen", "name": "Synthetic target", "share_id": SHARE,
             "llm": {"provider": "bedrock"}, "tool_specs": [],
             "system_prompt": "Private configuration using " + ACCESS}


def forbidden(*args, **kwargs):
    pytest.fail("Unexpected transport, credential store, mutation or discovery")


class Response:
    def __init__(self, url, data=None, status=200, content=None):
        self.url, self.status_code = url, status
        self.content = json.dumps(data).encode() if content is None else content
        self.closed = False

    def iter_content(self, **kwargs):
        for start in range(0, len(self.content), 4096):
            yield self.content[start:start + 4096]

    def close(self):
        self.closed = True


class Cookies:
    def clear(self):
        pass


class Transport:
    def __init__(self):
        self.calls, self.responses = [], []
        self.closed = False
        self.cookies = Cookies()
        self.trust_env = True
        self.config = {"app_name": "Doppelganger", "public": {"complete": [1, True, None]}}
        self.workspace = deepcopy(WORKSPACE)
        self.error = None
        self.override = None

    def get(self, url, **kwargs):
        assert self.trust_env is False
        assert kwargs["verify"] is True and kwargs["allow_redirects"] is False
        assert kwargs["stream"] is True and set(kwargs) == {
            "headers", "verify", "allow_redirects", "stream", "timeout"}
        self.calls.append((url, deepcopy(kwargs)))
        if self.error:
            raise self.error
        if self.override:
            response = self.override(url)
        elif url == ORIGIN + "/api/config":
            response = Response(url, self.config)
            assert "x-demo-key" not in kwargs["headers"]
        else:
            assert url == ORIGIN + "/api/workspaces/chosen"
            assert kwargs["headers"]["x-demo-key"] == ACCESS
            response = Response(url, self.workspace)
        self.responses.append(response)
        return response

    def close(self):
        self.closed = True


@pytest.fixture(autouse=True)
def offline(monkeypatch, tmp_path):
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(profiles, "detect", forbidden)
    monkeypatch.setattr(profiles, "_get", forbidden)
    monkeypatch.setattr(cli, "_client", forbidden)
    monkeypatch.setattr(prepare.target_secrets, "get", forbidden)
    monkeypatch.setattr(prepare.target_secrets, "record", forbidden)
    monkeypatch.setattr(requests.Session, "get", forbidden)
    monkeypatch.setenv("ASCEND_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("ASCEND_CONFIG_DIR", str(tmp_path / "configs"))


@pytest.fixture
def transport():
    return Transport()


def run(transport, **kwargs):
    args = dict(expected_profile="doppelganger", workspace="chosen", credential_slots=deepcopy(SLOTS),
                environ=ENV, session_factory=lambda: transport)
    args.update(kwargs)
    return prepare.prepare(ORIGIN + "/api/chat", **args)


def test_prepared_contract_is_complete_symbolic_and_read_only(transport):
    out = run(transport)
    assert out["ok"] and out["version"] == 1 and out["outcome"] == "prepared"
    assert out["producer_revision"] == prepare.PRODUCER_REVISION
    assert out["source_kind"] == "published_profile" and out["profile_version"] == 1
    assert out["origin"] == ORIGIN and out["selected_workspace"] == "chosen"
    assert out["credential_slots"] == SLOTS
    step, = out["contract"]["steps"]
    assert step == {"method": "POST", "url": ORIGIN + "/api/chat", "redirect": "manual",
                    "headers": {"x-demo-key": "env:ACCESS", "Content-Type": "application/json"},
                    "body": {"message": "{{PROMPT}}", "apiKey": "env:KEY", "workspace": "env:SHARE",
                             "userName": "ascend", "activeConnectors": [], "connectorCredentials": {},
                             "llmProvider": "bedrock", "llmKey": None, "systemPrompt": None,
                             "ragContent": None}}
    assert out["contract"]["reply"] == {"kind": "json", "path": "message"}
    assert len(transport.calls) == 2, "the build reuses the complete captured workspace"
    assert not out["remote_attested"] and not any(out["facts"][k] for k in (
        "local_verified", "engine_tested", "stored_verified"))
    assert transport.closed and all(r.closed for r in transport.responses)
    assert all(value not in json.dumps(out) for value in ENV.values())


def test_captures_are_complete_and_have_two_distinct_honest_hashes(transport):
    out = run(transport)
    assert len(out["read_observations"]) == 2
    for observation, response in zip(out["read_observations"], transport.responses):
        assert observation["raw_response_bytes_sha256"] == hashlib.sha256(response.content).hexdigest()
        capture = prepare._json_bytes(observation["sanitized_data"])
        assert observation["sanitized_capture_sha256"] == hashlib.sha256(capture).hexdigest()
        assert observation["raw_response_bytes"] == len(response.content)
        assert observation["remote_attested"] is False
        assert observation["method"] == "GET" and observation["status"] == 200
    expected = deepcopy(WORKSPACE)
    expected.update(share_id="env:SHARE", system_prompt="Private configuration using env:ACCESS")
    assert out["read_observations"][1]["sanitized_data"] == expected
    assert out["read_observations"][1]["raw_response_bytes_sha256"] != out["read_observations"][1]["sanitized_capture_sha256"]


@pytest.mark.parametrize("failure", [requests.Timeout(), requests.ConnectionError()])
def test_outage_after_prior_recognition_never_redetects_or_falls_back(transport, failure):
    transport.error = failure
    out = run(transport)
    assert out["outcome"] == "unavailable" and not out["ok"] and "contract" not in out
    assert len(transport.calls) == 1 and transport.closed


@pytest.mark.parametrize("status,outcome", [(301, "unavailable"), (403, "inputs_required"),
                                             (404, "conflicting_source"), (503, "unavailable")])
def test_known_get_refusals_remain_distinct_and_never_follow_redirects(transport, status, outcome):
    transport.override = lambda url: Response(url, {}, status=status)
    out = run(transport)
    assert out["outcome"] == outcome and "contract" not in out
    assert len(transport.calls) == 1


@pytest.mark.parametrize("change", ["profile", "workspace"])
def test_changed_profile_or_selected_workspace_is_not_a_new_route(transport, change):
    if change == "profile":
        transport.config["app_name"] = "Changed"
    else:
        transport.workspace["slug"] = "other"
    out = run(transport)
    assert out["outcome"] == "conflicting_source" and "contract" not in out


def test_changed_expected_origin_refuses_before_reading_inputs_or_network(transport):
    out = run(transport, expected_origin="https://other.example.test", environ=None)
    assert out["error"]["code"] == "expected_origin_changed" and not transport.calls


@pytest.mark.parametrize("change", ["origin", "duplicate", "literal", "missing", "unused", "ambiguous"])
def test_scoped_complete_credential_bindings_are_unambiguous(transport, change):
    slots, env = deepcopy(SLOTS), dict(ENV)
    if change == "origin":
        slots[0]["origin"] = "https://other.example.test"
    elif change == "duplicate":
        slots.append({**slots[0], "field": "X-Demo-Key"})
    elif change == "literal":
        slots[0]["reference"] = ACCESS
    elif change == "missing":
        env.pop("ACCESS")
    elif change == "unused":
        transport.workspace.pop("share_id")
    else:
        env["SHARE"] = ACCESS
    out = run(transport, credential_slots=slots, environ=env)
    assert not out["ok"] and "contract" not in out
    assert all(value not in json.dumps(out) for value in ENV.values())


def test_missing_slot_and_missing_selection_are_structured(transport):
    out = run(transport, credential_slots=[])
    assert out["outcome"] == "inputs_required" and "contract" not in out
    assert out["required_slot"] == {"origin": ORIGIN, "in": "header", "field": "x-demo-key"}
    out = run(transport, credential_slots=SLOTS[:2])
    assert out["error"]["code"] == "private_output_required"
    assert SHARE not in json.dumps(out)
    out = run(transport, workspace=None)
    assert out["outcome"] == "selection_required" and "contract" not in out


@pytest.mark.parametrize("value", ["not-supplied-private-value", {"password": "not-supplied-private-value"}])
def test_unsymbolizable_source_credentials_hold_without_leaking_partial_capture(transport, value):
    transport.workspace["extra_secret"] = value
    out = run(transport)
    assert not out["ok"] and "contract" not in out
    assert "not-supplied-private-value" not in json.dumps(out)
    assert len(out["read_observations"]) == 1


@pytest.mark.parametrize("body", [b'{"x":1,"x":2}', b'{"x":NaN}', b'not json', b'\xff',
                                  b'"' + b'a' * prepare.MAX_BYTES + b'"'])
def test_invalid_or_unbounded_capture_holds(transport, body):
    transport.override = lambda url: Response(url, content=body)
    out = run(transport)
    assert not out["ok"] and "contract" not in out and out["read_observations"] == []


def test_source_markers_cannot_inject_ambient_credentials_or_template_variables(transport):
    transport.workspace["llm"]["provider"] = "env:UNDECLARED"
    out = run(transport)
    assert out["error"]["code"] == "unsafe_source_template" and "contract" not in out


def test_known_profile_without_safe_read_only_contract_is_explicitly_unsupported(transport):
    out = run(transport, expected_profile="copilot_studio")
    assert out["outcome"] == "unsupported" and not transport.calls


def test_total_get_allowance_is_checked_while_reading(transport, monkeypatch):
    ticks = iter([0.0, 0.0, 21.0])
    monkeypatch.setattr(prepare.time, "monotonic", lambda: next(ticks))
    out = run(transport)
    assert out["outcome"] == "unavailable" and out["error"]["code"] == "read_budget_exhausted"


@pytest.mark.parametrize("timeout", [0, -1, 21, float("inf"), float("nan"), True])
def test_invalid_deadline_never_opens_a_request(transport, timeout):
    out = run(transport, timeout=timeout)
    assert out["error"]["code"] == "invalid_read_budget" and not transport.calls


@pytest.mark.parametrize("workspace", ["../other", "chosen?token=private", "chosen/other"])
def test_workspace_selection_cannot_change_get_scope(transport, workspace):
    out = run(transport, workspace=workspace)
    assert out["error"]["code"] == "invalid_workspace_selection" and not transport.calls


def test_returned_response_url_cannot_change_origin(transport):
    transport.override = lambda url: Response("https://other.example.test/api/config", {})
    out = run(transport)
    assert out["error"]["code"] == "read_scope_changed" and "contract" not in out


def test_capability_discovery_does_not_read_a_target_or_credential_store(capsys):
    cli.main(["--json", "target", "prepare", "--capabilities"])
    data = json.loads(capsys.readouterr().out)
    assert data["version"] == 1 and data["command"] == "target prepare"
    assert data["profiles"]["doppelganger"] == {
        "version": 1, "profile_version": 1, "command": "target prepare"}
    assert "copilot_studio" not in data["profiles"]


def test_actual_cli_parser_dispatch_emits_plan_and_nonzero_holds(transport, monkeypatch, capsys):
    monkeypatch.setattr(prepare.requests, "Session", lambda: transport)
    for name, value in ENV.items():
        monkeypatch.setenv(name, value)
    args = ["--json", "target", "prepare", ORIGIN, "--expected-profile", "doppelganger",
            "--workspace", "chosen", "--credential-slots", json.dumps(SLOTS)]
    cli.main(args)
    assert json.loads(capsys.readouterr().out)["outcome"] == "prepared"
    transport.error = requests.Timeout("must never be echoed: " + ACCESS)
    with pytest.raises(SystemExit) as error:
        cli.main(args)
    assert error.value.code == cli.EXIT_ERROR
    shown = capsys.readouterr().out
    assert json.loads(shown)["outcome"] == "unavailable" and ACCESS not in shown


def test_inspect_advertises_prepare_only_for_supported_recognized_profile(monkeypatch, capsys):
    monkeypatch.setattr(profiles, "detect", lambda *a, **kw: profiles.Doppelganger)
    monkeypatch.setattr(profiles.Doppelganger, "inspect", lambda *a, **kw: {
        "profile": "doppelganger", "origin": ORIGIN})
    monkeypatch.setattr(cli, "_target_auth", lambda *a: ({}, {}))
    monkeypatch.setattr(cli, "_is_public_host", lambda *a: True)
    monkeypatch.setattr(cli, "_client", lambda *a: SimpleNamespace(list_apps=lambda: [], _rows=lambda rows: rows))
    cli.main(["--json", "target", "inspect", ORIGIN])
    assert json.loads(capsys.readouterr().out)["prepare_capability"]["version"] == 1
    monkeypatch.setattr(profiles, "detect", lambda *a, **kw: None)
    cli.main(["--json", "target", "inspect", ORIGIN])
    assert "prepare_capability" not in json.loads(capsys.readouterr().out)


def test_installed_entrypoint_capability_probe_is_offline_and_old_cli_has_no_capability():
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run([sys.executable, str(root / "shells/cli/ascend.py"), "--json",
                             "target", "prepare", "--capabilities"],
                            capture_output=True, text=True, timeout=5,
                            env={"PATH": "/usr/bin:/bin", "NO_COLOR": "1"})
    assert result.returncode == 0 and json.loads(result.stdout)["version"] == 1
    old = subprocess.run(["git", "show", "d9c185a:shells/cli/ascend.py"], cwd=root,
                         capture_output=True, text=True, timeout=5)
    assert old.returncode == 0 and "prepare_capability" not in old.stdout


def test_generic_producer_uses_profile_owned_contract_not_target_specific_global_rules(transport, monkeypatch):
    class Synthetic:
        name = "synthetic"
        prepare_version = 1
        prepare_shape = ("/published", "kind", "synthetic")
        prepare_secret_fields = frozenset()
        prepare_slots = frozenset({("header", "x-access")})

        @staticmethod
        def prepare_config(origin, workspace, inputs, fetch):
            reference = inputs.required("header", "x-access")
            fetch(origin + "/manifest", headers={"X-Access": reference})
            return {"adapter": "direct_api", "method": "POST", "endpoint": origin + "/conversation",
                    "headers": {"X-Access": reference}, "body": {"question": "{{PROMPT}}"},
                    "response_path": "answer.text"}, {}, {}

    monkeypatch.setattr(profiles, "PROFILES", [Synthetic])
    transport.override = lambda url: Response(url, {"kind": "synthetic", "complete": True})
    slots = [{"origin": ORIGIN, "in": "header", "field": "x-access", "reference": "env:ACCESS"}]
    out = run(transport, expected_profile="synthetic", credential_slots=slots)
    assert out["ok"] and out["contract"]["reply"]["path"] == "answer.text"
    assert [url for url, _ in transport.calls] == [ORIGIN + "/published", ORIGIN + "/manifest"]


def test_private_native_observed_input_needs_no_preexisting_workspace_credential(transport, tmp_path):
    path = tmp_path / "native-plan.json"
    out = run(transport, credential_slots=SLOTS[:2], private_output=str(path))
    assert out["ok"] and out["observed_input_count"] == 1
    assert "read_observations" not in out and "contract" not in out and "facts" not in out
    assert all(value not in json.dumps(out) for value in ENV.values())
    raw = path.read_bytes()
    assert path.stat().st_mode & 0o777 == 0o600
    assert hashlib.sha256(raw).hexdigest() == out["private_output"]["sha256"]
    assert len(raw) == out["private_output"]["bytes"]
    bundle = json.loads(raw)
    entry, = bundle["observed_inputs"]
    assert entry == {"id": "profile_workspace", "origin": ORIGIN, "in": "body", "field": "workspace",
                     "value": SHARE, "reference": "input:profile_workspace", "source_observation": 1,
                     "source_url": ORIGIN + "/api/workspaces/chosen", "source_pointer": "/share_id"}
    assert bundle["contract"]["steps"][0]["body"]["workspace"] == "input:profile_workspace"
    observation = bundle["read_observations"][1]
    captured = base64.b64decode(observation["raw_response_bytes_base64"], validate=True)
    assert hashlib.sha256(captured).hexdigest() == observation["raw_response_bytes_sha256"]
    assert json.loads(captured)["share_id"] == SHARE
    assert observation["sanitized_data"]["share_id"] == "input:profile_workspace"
    assert SHARE not in json.dumps(observation["sanitized_data"])


def test_later_observed_input_resanitizes_every_original_capture(transport, tmp_path):
    transport.config["public_note"] = "Earlier " + ACCESS + " and " + SHARE
    path = tmp_path / "native-plan.json"
    out = run(transport, credential_slots=SLOTS[:2], private_output=str(path))
    assert out["ok"] and SHARE not in json.dumps(out)
    bundle = json.loads(path.read_bytes())
    assert bundle["observed_inputs"][0]["value"] == SHARE
    assert bundle["read_observations"][0]["sanitized_data"]["public_note"] == (
        "Earlier env:ACCESS and input:profile_workspace")
    for observation, response in zip(bundle["read_observations"], transport.responses):
        assert observation["raw_response_bytes_sha256"] == hashlib.sha256(response.content).hexdigest()
        assert base64.b64decode(observation["raw_response_bytes_base64"], validate=True) == response.content
        sanitized = observation["sanitized_data"]
        assert all(value not in json.dumps(sanitized) for value in ENV.values())
        assert observation["sanitized_capture_sha256"] == hashlib.sha256(
            prepare._json_bytes(sanitized)).hexdigest()


def test_later_observed_input_in_earlier_property_name_refuses_publication(transport, tmp_path):
    observed = "opaque-observed-value-003"
    transport.config[observed] = "earlier property"
    transport.workspace["share_id"] = observed
    path = tmp_path / "native-plan.json"
    out = run(transport, credential_slots=SLOTS[:2], private_output=str(path))
    assert not out["ok"] and out["error"]["code"] == "credential_in_property_name"
    assert observed not in json.dumps(out) and "private_output" not in out and not path.exists()


@pytest.mark.parametrize("missing", ["absent", None, "", False, 0])
def test_missing_exact_slot_cannot_hide_behind_a_shared_reference(transport, missing):
    if missing == "absent":
        transport.workspace.pop("share_id")
    else:
        transport.workspace["share_id"] = missing
    slots = deepcopy(SLOTS)
    slots[2]["reference"] = "env:ACCESS"
    out = run(transport, credential_slots=slots)
    assert not out["ok"] and out["error"]["code"] == "unused_credential_slot"
    assert "contract" not in out


@pytest.mark.parametrize("header", ["x-demo-key", "X-Demo-Key"])
def test_shared_reference_remains_valid_in_every_exact_declared_slot(transport, header):
    transport.workspace["share_id"] = ACCESS
    slots = deepcopy(SLOTS)
    slots[0]["field"] = header
    slots[2]["reference"] = "env:ACCESS"
    out = run(transport, credential_slots=slots)
    assert out["ok"]
    step, = out["contract"]["steps"]
    assert step["headers"]["x-demo-key"] == step["body"]["workspace"] == "env:ACCESS"


def test_observed_facts_keep_native_profile_mechanics_and_exact_source_locations(transport):
    transport.workspace.update(description="Synthetic purpose", tool_specs=[{"name": "lookup"}])
    out = run(transport)
    facts = out["facts"]
    assert facts["system_prompt"] == "Private configuration using env:ACCESS"
    assert facts["purpose"] == "Synthetic purpose" and facts["tools"] == ["lookup"]
    assert facts["agentic"] is True and facts["name"] == "Doppelganger \u00b7 Synthetic target"
    assert facts["sources"]["purpose"] == {"url": ORIGIN + "/api/workspaces/chosen",
        "pointer": "/description", "transform": "native_profile"}
    transport.workspace.pop("description")
    out = run(transport)
    assert "purpose" not in out["facts"] and "purpose" not in out["facts"]["sources"]


@pytest.mark.parametrize("mode", ["existing", "symlink", "unsafe_parent", "relative"])
def test_private_output_refuses_unsafe_destination_without_get_or_overwrite(transport, tmp_path, monkeypatch, mode):
    path = tmp_path / "plan.json"
    sentinel = tmp_path / "untouched"
    sentinel.write_text("unchanged")
    if mode == "existing":
        path.write_text("existing")
    elif mode == "symlink":
        path.symlink_to(sentinel)
    elif mode == "unsafe_parent":
        tmp_path.chmod(0o755)
    else:
        monkeypatch.chdir(tmp_path)
        path = Path("plan.json")
    try:
        out = run(transport, private_output=str(path))
        assert not out["ok"] and out["error"]["code"] == "private_output_unavailable"
        assert not transport.calls and sentinel.read_text() == "unchanged"
        if mode == "existing":
            assert path.read_text() == "existing"
    finally:
        tmp_path.chmod(0o700)


def test_failed_private_prepare_removes_only_its_unpublished_artifact(transport, tmp_path):
    path = tmp_path / "plan.json"
    transport.error = requests.Timeout()
    out = run(transport, private_output=str(path), credential_slots=SLOTS[:2])
    assert not out["ok"] and not path.exists()
    assert "read_observations" not in out and "observed_inputs" not in out


def test_existing_observed_credential_conflict_never_rotates_or_publishes(transport, tmp_path):
    transport.workspace["share_id"] = "new-unapproved-credential-value"
    path = tmp_path / "plan.json"
    out = run(transport, private_output=str(path))
    assert not out["ok"] and out["error"]["code"] == "observed_credential_conflict"
    assert "new-unapproved" not in json.dumps(out) and not path.exists()


def test_contract_does_not_repurpose_reference_into_an_undeclared_slot(transport):
    transport.workspace["llm"]["provider"] = KEY
    out = run(transport)
    assert not out["ok"] and out["error"]["code"] == "undeclared_credential_placement"


def test_observed_input_cannot_come_from_an_unselected_source(transport, tmp_path):
    transport.config["share_id"] = "not-from-selected-workspace"
    path = tmp_path / "plan.json"
    out = run(transport, private_output=str(path), credential_slots=SLOTS[:2])
    assert not out["ok"] and "not-from-selected" not in json.dumps(out)
    assert not path.exists()


def test_actual_cli_private_output_prints_only_metadata(transport, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(prepare.requests, "Session", lambda: transport)
    monkeypatch.setenv("ACCESS", ACCESS)
    monkeypatch.setenv("KEY", KEY)
    path = tmp_path / "native.json"
    cli.main(["--json", "target", "prepare", ORIGIN, "--expected-profile", "doppelganger",
              "--workspace", "chosen", "--credential-slots", json.dumps(SLOTS[:2]),
              "--private-output", str(path)])
    shown = capsys.readouterr().out
    out = json.loads(shown)
    assert out["ok"] and out["observed_input_count"] == 1
    assert all(value not in shown for value in ENV.values())
    assert all(field not in out for field in ("contract", "facts", "read_observations", "observed_inputs"))
    assert json.loads(path.read_bytes())["observed_inputs"][0]["value"] == SHARE
