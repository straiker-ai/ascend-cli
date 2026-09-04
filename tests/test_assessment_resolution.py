"""
test_assessment_resolution.py — every command with an optional --assessment must resolve one.

`args.assessment` defaults to None, and several commands passed it straight into the URL. Omitting
the flag therefore requested the literal string:

    GET /ascend/applications/aapp_.../assessments/None -> 404 assessment_not_found
      not found — check the app id/name with `ascend app list`

and the advice named the one thing that HAD resolved correctly, sending the reader to look at the
wrong half.

THIS FILE EXISTS BECAUSE THE FIRST FIX WAS INCOMPLETE. `ci` was repaired on its own, inline, and
`export` was left with the identical defect — found only by re-running the audit against a clean
clone afterwards. `export` is how a report reaches a customer, so it was the worse one to leave
broken.

Scope was checked rather than assumed: `assess results` LOOKS like a third instance and is not —
its `--assessment` is `required=True`, so argparse rejects the call before any URL is built. It
is excluded here. An earlier draft of this file included it and asserted it had "the identical
defect", which was simply false; a test that states something untrue about the code is worse than
no test, because it is read as documentation.

That is the same failure as every other one this release: a shared rule fixed at one call site and
not the others. A unit test on the resolver would have passed against it, because the resolver was
never the broken part. So the tests that matter here are the source-discipline ones at the bottom,
which check that each command actually calls the shared helper.

`assess pause`, `assess resume` and `assess results` are excluded for the same reason: they
REQUIRE `--assessment`, so the value can never be None. For the two destructive verbs that is also
the right design — defaulting a pause or a resume to "whatever ran last" would be worse than the
error it replaces. `assess watch` is optional but already resolves its own default (the RUNNING
assessment, which is the correct default for a live view rather than the latest finished one), so
it is left alone.
"""
import re
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
for p in ("shells/cli", "runtime", "control"):
    sys.path.insert(0, str(REPO / p))
import ascend  # noqa: E402

SRC = (REPO / "shells" / "cli" / "ascend.py").read_text()

# Commands whose --assessment is optional and which therefore must resolve a default.
OPTIONAL = ["cmd_ci", "cmd_export", "cmd_assess_results"]


class _Args:
    json = False
    verbose = False
    app = "Demo Bot"
    assessment = None


class _Client:
    def __init__(self, latest=None):
        self._latest = latest
        self.asked = 0

    def latest_assessment(self, app_id, **kw):
        self.asked += 1
        return self._latest


class TestTheResolver:
    def test_an_explicit_id_is_used_untouched(self):
        a = _Args()
        a.assessment = "asmt_explicit"
        c = _Client()
        assert ascend._resolve_assessment(c, "aapp_x", a) == "asmt_explicit"
        assert c.asked == 0, "an explicit id must not cost a lookup"

    def test_it_defaults_to_the_latest_run(self):
        c = _Client({"id": "asmt_latest", "status": "complete"})
        assert ascend._resolve_assessment(c, "aapp_x", _Args()) == "asmt_latest"

    def test_the_alternate_id_field_is_accepted(self):
        """The API has returned this as both `id` and `assessment_id`."""
        c = _Client({"assessment_id": "asmt_alt", "status": "complete"})
        assert ascend._resolve_assessment(c, "aapp_x", _Args()) == "asmt_alt"

    def test_an_app_with_no_runs_says_so_instead_of_404ing(self):
        with pytest.raises(SystemExit):
            ascend._resolve_assessment(_Client(None), "aapp_x", _Args())

    def test_the_no_runs_message_names_how_to_make_one(self):
        import io
        import contextlib
        err = io.StringIO()
        with contextlib.redirect_stderr(err), pytest.raises(SystemExit):
            ascend._resolve_assessment(_Client(None), "aapp_x", _Args())
        assert "assess run" in err.getvalue()

    def test_it_never_returns_the_string_none(self):
        """The literal defect: `None` reaching the URL as a path segment."""
        c = _Client({"id": "asmt_x", "status": "complete"})
        assert ascend._resolve_assessment(c, "aapp_x", _Args()) != "None"


class TestEveryOptionalCommandResolves:
    """The drift guard — the test that would have caught the incomplete first fix."""

    def _body(self, fn):
        m = re.search(rf"^def {fn}\(args\):(.*?)(?=^def )", SRC, re.S | re.M)
        assert m, f"{fn} not found"
        return m.group(1)

    @pytest.mark.parametrize("fn", OPTIONAL)
    def test_it_calls_the_shared_resolver(self, fn):
        assert "_resolve_assessment(" in self._body(fn), (
            f"{fn} takes an optional --assessment and does not resolve a default — omitting the "
            f"flag will put the literal string 'None' in the URL and 404")

    @pytest.mark.parametrize("fn", OPTIONAL)
    def test_it_does_not_pass_the_raw_flag_to_the_api(self, fn):
        body = self._body(fn)
        assert not re.search(r"get_assessment\([^)]*args\.assessment", body), (
            f"{fn} still hands args.assessment straight to get_assessment")

    @pytest.mark.parametrize("fn", OPTIONAL)
    def test_no_command_carries_its_own_copy_of_the_rule(self, fn):
        """A second inline `latest_assessment()` is the duplication starting over."""
        code = "\n".join(re.sub(r"#.*$", "", l) for l in self._body(fn).splitlines())
        assert "latest_assessment(" not in code, (
            f"{fn} resolves the latest run inline instead of calling the shared helper")

    def test_the_helper_is_defined_once(self):
        assert len(re.findall(r"^def _resolve_assessment\(", SRC, re.M)) == 1


class TestCommandsThatRequireItAreLeftAlone:
    """These are excluded from OPTIONAL because argparse already blocks the None case.

    If any of them is ever made optional, it acquires the exact defect this file exists for and
    must be added to OPTIONAL in the same change — that is what this test is here to force.
    `assess results` made that move in 1.1.3 (it defaults to the latest finished run); the two
    verbs left here act on a run, and naming it explicitly is the right design on its own terms.
    """

    @pytest.mark.parametrize("verbs", [("assess", "pause"), ("assess", "resume")])
    def test_the_flag_is_still_required(self, verbs):
        p = ascend.build_parser()
        node = [a for a in p._actions if getattr(a, "choices", None)][0].choices[verbs[0]]
        node = [a for a in node._actions if getattr(a, "choices", None)][0].choices[verbs[1]]
        flag = next(a for a in node._actions if "--assessment" in (a.option_strings or []))
        assert flag.required, (
            f"{' '.join(verbs)} no longer requires --assessment; it must not silently act on "
            f"whatever ran most recently")
