"""Actual CLI/API offline route correlation; engine payloads remain untouched."""
from copy import deepcopy
import ast
import inspect
import json

import pytest

from conftest import FakeResponse, install_fake_requests
from test_adaptor_cli import APP, UUID, TURN_OK, Recorder, api, cli, js, run
from test_console_ids import flat_listing


OTHER_UUID = "11111111-2222-4333-8444-555555555555"


@pytest.mark.parametrize("command", [cli.cmd_adaptor_test, cli.cmd_adaptor_verify])
def test_both_execution_commands_use_shared_resolution_and_envelope(command):
    tree = ast.parse(inspect.getsource(command))
    calls = [node.func.id for node in ast.walk(tree)
             if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)]
    assert calls.count("_adaptor_engine_ref_and_app") == 1
    assert calls.count("_adaptor_run_envelope") == 1
    assert "_adaptor_engine_ref" not in calls and "_run_envelope" not in calls


def argv(verb, source, ref=APP["id"], override=False):
    return ["adaptor", verb, *([source] if verb == "test" else []), "--app", ref,
            *(["--console-id", UUID] if override else [])]


@pytest.mark.parametrize("verb", ["test", "verify"])
@pytest.mark.parametrize("ref", [APP["id"], APP["name"]])
@pytest.mark.parametrize("listing_case", [
    "matched", "default_port", "nondefault_port", "url_conflict", "path_case", "ambiguous", "denied"])
def test_authenticated_lookup_and_engine_response_emit_operational_identity(
        monkeypatch, capsys, js, verb, ref, listing_case):
    """Use real API auth, get_app, Console decoding/matcher, and CLI command code."""
    payload = {"app_id": UUID, "ok": True, "turns": [deepcopy(TURN_OK)],
               "digest": "opaque-engine-digest", "endpoint": APP["url"]}
    rows = [{"irisId": UUID, "name": APP["name"], "url": APP["url"]}]
    if listing_case == "url_conflict":
        rows[0]["url"] = "https://another.example/v1"
    elif listing_case == "path_case":
        rows[0]["url"] = APP["url"].replace("/v1", "/V1")
    elif listing_case == "ambiguous":
        rows.append(dict(rows[0], irisId=OTHER_UUID))
    elif listing_case in ("default_port", "nondefault_port"):
        port = 443 if listing_case == "default_port" else 8443
        rows[0]["url"] = APP["url"].replace("/v1", f":{port}/v1")
    resolved = listing_case in ("matched", "default_port")
    route = UUID if resolved else APP["id"]
    observed = []
    def handler(method, url, kwargs):
        observed.append((method, url, kwargs))
        if url.endswith("/auth/token"):
            return FakeResponse(200, {"access_token": "synthetic-jwt"})
        if "/listApplications?payload=" in url:
            assert kwargs["headers"]["Cookie"] == "auth-id-token=synthetic-jwt"
            if listing_case == "denied":
                return FakeResponse(403, {"type": "error"})
            return FakeResponse(200, {"type": "result", "data": flat_listing(rows)})
        assert kwargs["headers"]["Authorization"] == "Bearer synthetic-jwt"
        if url.endswith("/ascend/applications?limit=100"):
            return FakeResponse(200, {"data": [deepcopy(APP)]})
        if url.endswith("/ascend/applications/" + APP["id"]):
            return FakeResponse(200, dict(deepcopy(APP), headers={"Authorization": "synthetic-private-value"}))
        if url.endswith("/ascend/adapters/test"):
            assert kwargs["json"]["appId"] == route
            return FakeResponse(200, deepcopy(payload))
        if url.endswith("/ascend/applications/" + route + "/adapter/verify"):
            return FakeResponse(200, deepcopy(payload))
        pytest.fail(f"Unexpected synthetic route: {method} {url}")
    install_fake_requests(monkeypatch, handler)
    client = api.AscendAPI(token="s6r_pat_synthetic")
    run(monkeypatch, client, *argv(verb, js, ref), json_mode=True)
    envelope = json.loads(capsys.readouterr().out)
    assert envelope["ok"] and envelope["verdict"]["ok"]
    if resolved:
        assert envelope["app_id"] == APP["id"] and envelope["console_id"] == UUID
        assert envelope["identity_scope"] == "operational_route"
        assert "identity_unresolved" not in envelope
    else:
        assert "app_id" not in envelope and "console_id" not in envelope
        assert "identity_unresolved" in envelope
    assert envelope["data"] == payload
    assert "synthetic-private-value" not in json.dumps(envelope)
    assert sum("/listApplications?" in url for _, url, _ in observed) == 1
    assert sum(url.endswith("/ascend/applications/" + APP["id"]) for _, url, _ in observed) == 1
    assert sum(method == "POST" and not url.endswith("/auth/token") for method, url, _ in observed) == 1


@pytest.mark.parametrize("verb", ["test", "verify"])
@pytest.mark.parametrize("case", [
    "direct_uuid", "console_override", "missing_lookup", "wrong_public_record", "failed_lookup",
    "missing_url", "console_failure", "returned_uuid_conflict", "returned_uuid_absent",
    "returned_console_conflict", "returned_public_conflict", "returned_unresolved", "failed_execution",
])
def test_unconfirmed_resolution_never_mints_public_identity(monkeypatch, capsys, js, verb, case):
    payload = {"app_id": UUID, "turns": [deepcopy(TURN_OK)]}
    rec = Recorder(console_uuid=UUID)
    ref, override = APP["id"], False
    if case == "direct_uuid":
        ref = UUID
    elif case == "console_override":
        override = True
    elif case == "missing_lookup":
        rec.app = None
    elif case == "wrong_public_record":
        rec.app["id"] = "aapp_other"
    elif case == "failed_lookup":
        def failed(app_id):
            raise api.AscendAPIError("synthetic denied")
        rec.get_app = failed
    elif case == "missing_url":
        rec.app.pop("url")
    elif case == "console_failure":
        rec.console_uuid = None
    elif case == "returned_uuid_conflict":
        payload["app_id"] = OTHER_UUID
    elif case == "returned_uuid_absent":
        payload.pop("app_id")
    elif case == "returned_console_conflict":
        payload["console_id"] = OTHER_UUID
    elif case == "returned_public_conflict":
        payload["app"] = {"id": "aapp_other"}
    elif case == "returned_unresolved":
        payload["identity_unresolved"] = True
    elif case == "failed_execution":
        payload["turns"][0]["status_code"] = 403
    rec.test_out = rec.verify_out = payload
    if case == "failed_execution":
        with pytest.raises(SystemExit) as exc:
            run(monkeypatch, rec, *argv(verb, js, ref, override), json_mode=True)
        assert exc.value.code == 1
    else:
        run(monkeypatch, rec, *argv(verb, js, ref, override), json_mode=True)
    envelope = json.loads(capsys.readouterr().out)
    assert "identity_unresolved" in envelope
    assert "app_id" not in envelope and "console_id" not in envelope
    assert "identity_scope" not in envelope
    assert envelope["data"] == payload
    assert len(rec.tested if verb == "test" else rec.verified) == 1
    if case in ("direct_uuid", "console_override"):
        assert not rec.console_asked and rec.listed == 0
