"""
test_binary_bundles_skills — the packaged binary must ship every skill a source checkout has.

The build bundled docs/ and the example configs but not skills/, so `ascend skills` from the
release asset said "no skills packaged in this build" while a checkout lists six. An agent on
the binary was told the procedures do not exist. Nothing in a source checkout can see this;
this test pins the build script instead, which is where it went wrong.
"""
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def test_build_script_bundles_the_skills_directory():
    script = (REPO / "scripts" / "build_binary.sh").read_text(encoding="utf-8")
    assert re.search(r'--add-data\s+"skills:skills"', script), \
        "scripts/build_binary.sh must pass --add-data \"skills:skills\" or the binary ships no skills"


def test_there_are_skills_to_bundle():
    skills = sorted(p.parent.name for p in (REPO / "skills").glob("*/SKILL.md"))
    assert len(skills) >= 6, skills
