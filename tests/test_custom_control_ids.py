"""
test_custom_control_ids.py — a custom control id is checked, never waved through or silently dropped.

Custom controls (`custom-<n>`) are not in `/ascend/controls`, which is the built-in catalog; the
organization's custom controls have their own list, `/ascend/custom-controls`. Two places need it:

  * `--controls custom-50` must validate against that list, so a real custom control runs without
    --force and a deleted or mistyped one is refused like any unknown id.
  * `assess run` without --controls runs the app's registered set. A custom control deleted after
    the app was set up is skipped by the platform without a word and scores clean, so the run is
    refused before it starts.
"""
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "shells" / "cli"))
sys.path.insert(0, str(REPO / "runtime"))
sys.path.insert(0, str(REPO / "control"))
import ascend  # noqa: E402
from api import AscendAPI, AscendAPIError  # noqa: E402

CATALOG = {"controls": [{"id": "sys_prompt_leak"}, {"id": "old_control", "deprecated": True}]}


def _client(monkeypatch, custom=("custom-50",), custom_error=None):
    client = AscendAPI(token="s6r_pat_x")
    calls = []
    monkeypatch.setattr(client, "list_controls", lambda: CATALOG)

    def req(method, path, **_):
        calls.append((method, path))
        if path == "/ascend/custom-controls":
            if custom_error:
                raise AscendAPIError(custom_error)
            return {"object": "list", "data": [{"id": i, "object": "ascend.custom_control"} for i in custom]}
        raise AssertionError(f"unexpected call {method} {path}")

    monkeypatch.setattr(client, "_req", req)
    return client, calls


class TestValidateControls:
    def test_an_existing_custom_control_is_valid(self, monkeypatch):
        c, _ = _client(monkeypatch)
        r = c.validate_controls(["sys_prompt_leak", "custom-50"])
        assert r["valid"] == ["sys_prompt_leak", "custom-50"]
        assert r["unknown"] == []

    def test_a_deleted_custom_control_is_unknown(self, monkeypatch):
        c, _ = _client(monkeypatch)
        r = c.validate_controls(["custom-50", "custom-51"])
        assert r["valid"] == ["custom-50"]
        assert r["unknown"] == ["custom-51"]

    def test_the_custom_list_is_only_fetched_for_custom_ids(self, monkeypatch):
        """An invocation without custom ids makes exactly the calls it made before."""
        c, calls = _client(monkeypatch)
        c.validate_controls(["sys_prompt_leak"])
        assert calls == []

    def test_a_platform_without_the_list_says_so(self, monkeypatch):
        c, _ = _client(monkeypatch, custom_error="GET /ascend/custom-controls -> 404: not found")
        r = c.validate_controls(["custom-50"])
        assert r["unknown"] == ["custom-50"]
        assert any("does not list custom controls" in w for w in r["warnings"])

    def test_other_errors_are_not_mistaken_for_a_missing_list(self, monkeypatch):
        c, _ = _client(monkeypatch, custom_error="GET /ascend/custom-controls -> 502: bad gateway")
        with pytest.raises(AscendAPIError):
            c.validate_controls(["custom-50"])


class _App:
    """A client whose app has a given registered control set."""

    def __init__(self, control_type, control_ids, custom=("custom-50",)):
        self._app = {"control_type": control_type, "control_ids": list(control_ids)}
        self._custom = None if custom is None else set(custom)

    def get_app(self, _app_id):
        return self._app

    def custom_control_ids(self):
        return self._custom


class TestDeletedCustomControls:
    def test_a_deleted_custom_control_in_the_registered_set_is_reported(self):
        c = _App("custom", ["sys_prompt_leak", "custom-50", "custom-51"])
        assert ascend._deleted_custom_controls(c, "aapp_x") == ["custom-51"]

    def test_an_empty_control_type_runs_the_ids_as_given_so_it_is_checked(self):
        assert ascend._deleted_custom_controls(_App("", ["custom-51"]), "aapp_x") == ["custom-51"]

    @pytest.mark.parametrize("control_type", ["all", "compliance-3"])
    def test_types_that_ignore_control_ids_are_not_checked(self, control_type):
        assert ascend._deleted_custom_controls(_App(control_type, ["custom-51"]), "aapp_x") == []

    def test_nothing_to_check_against_is_not_an_error(self):
        assert ascend._deleted_custom_controls(_App("custom", ["custom-51"], custom=None), "aapp_x") == []

    def test_the_message_names_the_controls_and_the_fix(self):
        msg = ascend._deleted_custom_controls_msg(["custom-51"])
        assert "custom-51" in msg and "app update" in msg and "--force" in msg
