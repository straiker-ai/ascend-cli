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


def _continuation_block(script: str):
    """The lines of the pyinstaller command: from the script-name line, every preceding line that
    ends in a backslash. A blank line ends the chain -- and the command -- early."""
    lines = script.splitlines()
    i = next(k for k, l in enumerate(lines) if l.strip().startswith("shells/cli/ascend.py"))
    j = i - 1
    while j >= 0 and lines[j].rstrip().endswith("\\"):
        j -= 1
    return lines[j + 1:i + 1]


def test_the_build_command_is_one_unbroken_continuation():
    """A blank line inside the backslash continuation ends the command before the script name:
    `pyinstaller: error: the following arguments are required: scriptname`. That is how the
    first 1.1.3 asset build failed."""
    block = _continuation_block((REPO / "scripts" / "build_binary.sh").read_text(encoding="utf-8"))
    assert block and "pyinstaller" in block[0], \
        f"the script name is not attached to the pyinstaller command: chain starts at {block[:1]!r}"


def test_skills_are_found_from_a_frozen_bundle(tmp_path, monkeypatch):
    """PyInstaller puts the entry script at the bundle root, so `Path(__file__).parents[2]` is one
    level ABOVE the bundle and `REPO / "skills"` does not exist: the shipped binary said "no
    skills packaged in this build" even after skills/ was bundled. The lookup must start at
    sys._MEIPASS when frozen."""
    import sys
    sys.path.insert(0, str(REPO / "shells" / "cli"))
    for p in ("control", "runtime"):
        sys.path.insert(0, str(REPO / p))
    import ascend
    bundle = tmp_path / "bundle"
    (bundle / "skills" / "one-skill").mkdir(parents=True)
    (bundle / "skills" / "one-skill" / "SKILL.md").write_text("---\nname: one-skill\ndescription: a test skill\n---\nbody\n")
    monkeypatch.setattr(sys, "_MEIPASS", str(bundle), raising=False)
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    assert ascend._skills_root() == bundle / "skills"
    monkeypatch.delattr(sys, "_MEIPASS", raising=False)
    monkeypatch.delattr(sys, "frozen", raising=False)
    assert ascend._skills_root() == ascend.REPO / "skills"
