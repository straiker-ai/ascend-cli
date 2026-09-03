"""
test_corpus_normalize.py — one normalizer for both corpora, and it must be interpreter-proof.

`golden_output.py` and `back_compat.py` each carried their own `_normalize`, copied character for
character — and they had already drifted: an argparse fix landed in one and not the other, so the
same CLI output compared equal in one gate and unequal in the other. That is the exact
duplicate-logic defect that caused most of the bugs this release, sitting inside the two scripts
whose entire job is to catch drift.

WHY THE INTERPRETER MATTERS HERE

The corpora capture argparse output, and argparse's own wording changes between CPython releases —
including between PATCH releases:

    optional arguments:                          Python 3.9
    options:                                     Python 3.10+
    (choose from 'app', 'controls')              Python 3.12.7
    (choose from app, controls)                  Python 3.12.14

Both of those shipped as CI failures on this repo within an hour of each other. The first attempt
at a fix pinned the corpus to one minor version and skipped elsewhere; that was wrong twice over —
it gave up cross-version coverage, and it did not even work, because the second difference is
across PATCH versions and a CI runner updates its Python underneath you.

Normalizing CPython's rendering is the fix that holds. Nothing real is lost: which commands exist,
and every flag on them, are asserted by `gen_command_map.py --check`, which diffs the whole parser
tree. These rules drop CPython's phrasing, not our surface.
"""
import re
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))
from corpus_normalize import normalize  # noqa: E402


class TestInterpreterWordingIsNormalized:
    @pytest.mark.parametrize("a,b", [
        # 3.9 vs 3.10+ section header
        ("optional arguments:\n  -h, --help", "options:\n  -h, --help"),
        # 3.12.7 vs 3.12.14 invalid-choice rendering
        ("invalid choice: 'x' (choose from 'app', 'controls')",
         "invalid choice: 'x' (choose from app, controls)"),
    ])
    def test_two_cpython_renderings_compare_equal(self, a, b):
        assert normalize(a) == normalize(b), (
            "a corpus recorded on one CPython will fail on another for a difference this project "
            "did not make — which gets re-recorded, burying whatever it was protecting")

    def test_the_invalid_choice_list_is_collapsed(self):
        out = normalize("invalid choice: 'x' (choose from 'a', 'b', 'c')")
        assert "<COMMANDS>" in out and "'a'" not in out

    def test_the_bad_value_itself_is_preserved(self):
        """Collapsing the list must not collapse the thing the case is asserting."""
        assert "'not-a-command'" in normalize(
            "invalid choice: 'not-a-command' (choose from 'a')")

    def test_a_multiline_body_keeps_everything_else(self):
        t = "usage: ascend ...\noptions:\n  --json  machine-readable\n"
        assert "--json  machine-readable" in normalize(t)


class TestMachineSpecificsAreStripped:
    def test_the_repo_path_is_replaced(self):
        assert "<REPO>" in normalize(f"wrote {REPO}/configs/x.json")

    def test_the_home_path_is_replaced(self):
        import os
        assert "<HOME>" in normalize(f"stored at {os.path.expanduser('~')}/.ascend/keys.json")

    def test_macos_private_tmp_matches_tmp(self):
        assert normalize("/private/tmp/x") == normalize("/tmp/x")


class TestBothScriptsUseTheOneCopy:
    """The drift guard. A unit test on the normalizer passes against the original bug, because
    the normalizer was never the broken half — one of its two COPIES was."""

    @pytest.mark.parametrize("name", ["golden_output.py", "back_compat.py"])
    def test_it_imports_the_shared_normalizer(self, name):
        src = (REPO / "scripts" / name).read_text()
        assert "from corpus_normalize import normalize" in src, (
            f"{name} does not use the shared normalizer; a second copy is how these two gates "
            f"came to disagree about identical CLI output")

    @pytest.mark.parametrize("name", ["golden_output.py", "back_compat.py"])
    def test_it_does_not_reimplement_the_rules(self, name):
        """Grep code, not comments — the docstrings legitimately quote these strings."""
        src = (REPO / "scripts" / name).read_text()
        code = "\n".join(l for l in src.splitlines() if not l.strip().startswith("#"))
        code = re.sub(r'""".*?"""', "", code, flags=re.S)
        for rule in ('replace("/private/tmp"', "choose from [^)]*", 'replace("optional arguments:'):
            assert not re.search(re.escape(rule) if "[" not in rule else rule, code), (
                f"{name} re-implements `{rule}` instead of calling the shared normalizer")

    def test_the_normalizer_is_defined_once(self):
        src = (REPO / "scripts" / "corpus_normalize.py").read_text()
        assert len(re.findall(r"^def normalize\(", src, re.M)) == 1


class TestTheCorporaAreNotPinnedToAnInterpreter:
    """The first fix skipped these checks off 3.12. That traded away real coverage for nothing —
    the normalizer makes them hold everywhere, so they must actually RUN everywhere."""

    @pytest.mark.parametrize("path", ["tests/test_golden_output.py", "tests/test_back_compat.py"])
    def test_no_version_skip_remains(self, path):
        src = (REPO / path).read_text()
        assert "CORPUS_PYTHON" not in src and "_wrong_python" not in src, (
            f"{path} skips the corpus check on some interpreters; the shared normalizer removed "
            f"the need, and a skipped gate protects nothing on the version it skipped")
