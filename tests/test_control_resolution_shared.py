"""
test_control_resolution_shared.py — `target add` must not send a payload the platform refuses.

The platform accepts exactly ONE shape for the control selection: `control_type: "custom"` plus
an explicit id list. `control_type: "all"` is rejected with a bare 400 ("the request was rejected
by the upstream service"), and so is omitting the field. So "test everything" has to be spelled
out client-side by resolving the catalog.

`cmd_app_create` did that. `cmd_onboard` did not — it had `if controls:` with nothing in the
else, so with no `--controls` it fell through to `control_type: "all"` and failed **100% of the
time**. That is the default invocation of `ascend target add`, the command 1.1.2 makes the
primary path, and it was found only when a docs recording captured the failure on screen:

    [3/5] registering the application with Ascend
    error: POST /ascend/applications -> 400: {"error":{"code":"invalid_request",
           "message":"the request was rejected by the upstream service"}}

Two copies of one rule is how that happens. There is now one copy (`_resolve_all_controls`) and
two callers, and the source-discipline test below is the part that keeps it that way — a unit
test on the helper alone would have passed against the bug, because the helper was never the
broken half.
"""
import re
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "shells" / "cli"))
sys.path.insert(0, str(REPO / "runtime"))
sys.path.insert(0, str(REPO / "control"))
import ascend  # noqa: E402

SRC = (REPO / "shells" / "cli" / "ascend.py").read_text()


class _Args:
    json = False
    verbose = False


class _Client:
    def __init__(self, catalog):
        self._catalog = catalog

    def list_controls(self):
        return self._catalog


class TestTheHelperResolvesTheCatalog:
    def test_an_empty_selection_becomes_every_non_deprecated_control(self):
        c = _Client({"controls": [{"id": "sys_prompt_leak"}, {"id": "pii_leak"},
                                  {"id": "legacy_thing", "deprecated": True}]})
        got = ascend._resolve_all_controls(c, _Args(), [])
        assert got == ["sys_prompt_leak", "pii_leak"], \
            "a deprecated control generates zero probes, so it must not be selected"

    def test_an_explicit_selection_is_passed_through_untouched(self):
        c = _Client({"controls": [{"id": "everything_else"}]})
        assert ascend._resolve_all_controls(c, _Args(), ["pii_leak"]) == ["pii_leak"]

    def test_a_bare_list_catalog_shape_also_works(self):
        """The catalog has been seen both as {"controls": [...]} and as a bare list."""
        c = _Client([{"id": "a"}, {"id": "b"}])
        assert ascend._resolve_all_controls(c, _Args(), []) == ["a", "b"]

    def test_an_unreadable_catalog_fails_loudly(self):
        """Refusing beats sending control_type 'all' and getting an unexplained 400."""
        class Broken:
            def list_controls(self):
                raise RuntimeError("network down")
        with pytest.raises(SystemExit):
            ascend._resolve_all_controls(Broken(), _Args(), [])

    def test_an_empty_catalog_fails_loudly(self):
        with pytest.raises(SystemExit):
            ascend._resolve_all_controls(_Client({"controls": []}), _Args(), [])


class TestBothCallSitesUseTheOneCopy:
    """The drift guard. This is the test that would have caught the original bug.

    A unit test on the helper passes against the bug, because the helper was fine — the defect
    was that one of the two registration paths never called it.
    """

    def _body(self, fn_name):
        m = re.search(rf"^def {fn_name}\(args\):(.*?)(?=^def )", SRC, re.S | re.M)
        assert m, f"could not find {fn_name} in ascend.py"
        return m.group(1)

    @pytest.mark.parametrize("fn", ["cmd_app_create", "cmd_onboard"])
    def test_the_registration_path_calls_the_helper(self, fn):
        assert "_resolve_all_controls(" in self._body(fn), (
            f"{fn} registers an application without resolving the control catalog — with no "
            f"--controls it will send control_type 'all' and the platform will refuse it 400")

    @pytest.mark.parametrize("fn", ["cmd_app_create", "cmd_onboard"])
    def test_no_call_site_carries_its_own_copy(self, fn):
        """A second inline `list_controls()` resolution is the drift starting over."""
        body = self._body(fn)
        assert "list_controls()" not in body, (
            f"{fn} resolves the catalog inline again — that is exactly the duplication that let "
            f"cmd_onboard and cmd_app_create disagree in the first place")


class TestTheApiStillDefaultsToTheRejectedShape:
    """Documents WHY the client-side resolution is mandatory, so nobody removes it as redundant.

    `control/api.py` sends `control_type: "all"` when it is handed no control_ids. That is the
    payload the platform refuses, so every caller must resolve first. If the platform ever starts
    accepting "all", this test is the breadcrumb explaining what the resolution was for.
    """

    def test_api_sends_all_when_given_no_ids(self):
        api_src = (REPO / "control" / "api.py").read_text()
        assert '"control_type": "custom" if control_ids else "all"' in api_src, (
            "control/api.py no longer defaults to the rejected 'all' shape — re-check whether "
            "_resolve_all_controls is still required before deleting it")
