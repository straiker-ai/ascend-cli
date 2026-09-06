"""
test_skills_name_real_commands — every `ascend …` a skill tells an operator to run must parse.

A skill is obeyed harder than documentation: in a measured round, agents given a skill that named
a command form which did not work followed it into the dead end more often than agents with no
skill at all. The one stale reference found by checking all six skills against the real parser
(`bridge logs --app <name>`; the app is positional) is exactly the class this test now forbids.

For every skill: extract each `ascend <verb> [<sub>] … --flag …` invocation, resolve the verb path
against the live argparse tree, and require (1) the path is a real command and (2) every `--flag`
it uses is one that command accepts. Placeholders like `<name>` are ignored; flags are not.
"""
import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
CLI = [sys.executable, str(REPO / "shells" / "cli" / "ascend.py")]
SKILLS = sorted((REPO / "skills").glob("*/SKILL.md"))
DOCS = sorted([REPO / "README.md"] + list((REPO / "docs").glob("*.md")))

sys.path.insert(0, str(REPO / "scripts"))
import check_doc_commands as validator  # noqa: E402  (the same rules, runnable against any docs tree)

_help_cache = {}


def _help(path):
    key = tuple(path)
    if key not in _help_cache:
        r = subprocess.run(CLI + list(path) + ["--help"], capture_output=True, text=True)
        flags = set(re.findall(r"(?<![\w-])(--[a-z][a-z0-9-]*)", r.stdout + r.stderr))
        _help_cache[key] = (r.returncode == 0, flags)
    return _help_cache[key]


def _invocations(text):
    """(verb_path, flags_used, raw_line) for every `ascend …` in the skill text."""
    for m in re.finditer(r"ascend\s+([a-z][a-z-]*)(?:\s+([a-z][a-z-]*))?([^\n`]*)", text):
        v1, v2, rest = m.group(1), m.group(2), m.group(3) or ""
        path = [v1] + ([v2] if v2 else [])
        ok, flags = _help(path)
        if not ok and len(path) == 2:            # second token was an argument, not a subcommand
            path = [v1]
            ok, flags = _help(path)
        used = set(re.findall(r"(?<![\w-])(--[a-z][a-z0-9-]*)", rest))
        yield path, ok, used, flags, m.group(0).strip()


def test_there_are_skills():
    assert len(SKILLS) >= 6, [s.parent.name for s in SKILLS]


@pytest.mark.parametrize("skill", SKILLS, ids=[s.parent.name for s in SKILLS])
def test_every_command_a_skill_names_is_real_and_takes_those_flags(skill):
    problems = []
    for path, ok, used, accepted, raw in _invocations(skill.read_text(encoding="utf-8")):
        if not ok:
            problems.append(f"not a command: `ascend {' '.join(path)}`   ({raw[:80]})")
            continue
        for fl in sorted(used - accepted):
            problems.append(f"`ascend {' '.join(path)}` does not accept {fl}   ({raw[:80]})")
    assert not problems, f"{skill.parent.name}/SKILL.md names commands that do not work:\n  " + "\n  ".join(problems)


@pytest.mark.parametrize("doc", DOCS, ids=[d.name for d in DOCS])
def test_every_command_a_doc_names_is_real_and_takes_those_flags(doc):
    """Same rule for the documentation an agent is pointed at: 4 stale flags were found in 576
    documented invocations the first time this ran (`bridge logs --app`, `bridge start --adapter`
    x3, `bridge start --capture`) -- each a dead end for anyone following the page."""
    problems = validator.check(doc.read_text(encoding="utf-8"), doc.name)
    assert not problems, "\n  ".join([f"{doc.name} names commands that do not work:"] + problems)
