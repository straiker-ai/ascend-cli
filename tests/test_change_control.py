"""
test_change_control.py — the gates must stay wired up.

A CI file is itself a thing that can rot. Someone comments out a slow job, a script gets renamed,
a workflow gets replaced wholesale by a generated template — and the gate is gone without any
visible failure, which is exactly the state this repo was already in: `.github/` held only
`dependabot.yml`, so the test suite, both output corpora and the command-map check ran only when
somebody remembered.

Everything that shipped broken this release shipped green. These tests are cheap insurance that
the gates listed in `docs/CHANGE_CONTROL.md` are actually invoked by CI, and that the scripts they
invoke still exist under those names.
"""
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
WF = REPO / ".github" / "workflows" / "ci.yml"
DOC = REPO / "docs" / "CHANGE_CONTROL.md"

# Each gate: the script that runs it, and the command CI must invoke.
GATES = {
    "back-compat": ("scripts/back_compat.py", "scripts/back_compat.py --check"),
    "golden output": ("scripts/golden_output.py", "scripts/golden_output.py --check"),
    "command map": ("scripts/gen_command_map.py", "scripts/gen_command_map.py --check"),
}


class TestCiExists:
    def test_a_workflow_is_present(self):
        assert WF.is_file(), (
            "there is no CI workflow — every gate in this repo then runs only when somebody "
            "remembers, which is the state that let this release ship green and broken")

    def test_it_is_valid_yaml(self):
        yaml = pytest.importorskip("yaml")
        assert yaml.safe_load(WF.read_text()), "the workflow is empty or unparseable"

    def test_it_runs_on_pull_requests(self):
        yaml = pytest.importorskip("yaml")
        # PyYAML parses the bare key `on:` as the boolean True — a real trap when asserting on
        # workflow files, and the reason this looks for either spelling.
        wf = yaml.safe_load(WF.read_text())
        triggers = wf.get("on", wf.get(True)) or {}
        assert "pull_request" in triggers, "CI that does not run on a PR gates nothing"

    def test_it_also_runs_on_main(self):
        """A push run tests the MERGE RESULT. A PR run tests the branch."""
        yaml = pytest.importorskip("yaml")
        wf = yaml.safe_load(WF.read_text())
        triggers = wf.get("on", wf.get(True)) or {}
        assert "push" in triggers


class TestEveryGateIsInvoked:
    @pytest.mark.parametrize("name", sorted(GATES))
    def test_the_script_still_exists(self, name):
        script, _ = GATES[name]
        assert (REPO / script).is_file(), f"{script} is gone; CI invokes it by name"

    @pytest.mark.parametrize("name", sorted(GATES))
    def test_ci_invokes_it(self, name):
        _, cmd = GATES[name]
        assert cmd in WF.read_text(), (
            f"CI no longer runs `{cmd}` — that gate is now unenforced and nothing will say so")

    def test_ci_runs_the_whole_suite_in_one_process(self):
        """Per-file invocation is what hid an order-dependent failure across 14 tests."""
        assert re.search(r"pytest\s+tests/", WF.read_text()), (
            "CI does not run the suite as a whole; running files separately hides tests that "
            "pass alone and fail together")

    def test_ci_tests_the_declared_python_floor(self):
        """A `requires-python` nothing runs on is a claim, not a fact."""
        floor = re.search(r'requires-python\s*=\s*">=([\d.]+)"',
                          (REPO / "pyproject.toml").read_text())
        assert floor, "pyproject.toml declares no python floor"
        assert floor.group(1) in WF.read_text(), (
            f"pyproject declares >={floor.group(1)} and CI never runs it")

    def test_ci_installs_and_runs_the_built_package(self):
        """Runs the INSTALLED entry point — the check that catches an uncommitted local fix."""
        t = WF.read_text()
        assert "pip install ." in t and "ascend version" in t


class TestTheDocMatchesReality:
    def test_the_doc_exists(self):
        assert DOC.is_file()

    @pytest.mark.parametrize("name", sorted(GATES))
    def test_every_gate_is_documented(self, name):
        script, _ = GATES[name]
        assert script in DOC.read_text(), f"{script} runs in CI but is not in CHANGE_CONTROL.md"

    def test_the_live_matrix_is_named_as_a_release_step(self):
        """It cannot run on a fork PR — it needs a real PAT. Saying so prevents a false sense
        that CI proves an adapter can reach a target; the offline suite mocks all transport."""
        t = DOC.read_text()
        assert "live_matrix.py" in t
        assert (REPO / "scripts" / "live_matrix.py").is_file()
        # the auth gates are the other thing CI cannot prove: a target behind a login, live
        assert "live_auth_matrix.py" in t
        assert (REPO / "scripts" / "live_auth_matrix.py").is_file()

    def test_it_is_not_run_by_ci(self):
        assert "live_matrix.py" not in WF.read_text().split("# Deliberately NOT here")[-1].split(
            "name: ci")[0] or "live_matrix" not in re.sub(r"#.*", "", WF.read_text()), (
            "live_matrix.py runs real probes against a real tenant with a real PAT — a fork PR "
            "would hand that token to untrusted code")

    def test_the_changelog_exists_and_has_an_unreleased_section(self):
        cl = (REPO / "CHANGELOG.md")
        assert cl.is_file()
        assert "[Unreleased]" in cl.read_text()
