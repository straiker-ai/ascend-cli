#!/usr/bin/env python3
"""Every `ascend …` a document tells someone to run must parse against the real CLI.

    python3 scripts/check_doc_commands.py [PATH ...]      # default: README.md docs/ skills/

Point it at a docs checkout (Markdown or MDX) to validate the product documentation too. An agent
follows a documented command form with far more confidence than a person does, so a stale flag in
a doc is not a typo, it is a dead end on the documented first step. Exit 1 on any problem.
"""
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
CLI = [sys.executable, str(REPO / "shells" / "cli" / "ascend.py")]
EXT = {".md", ".mdx", ".markdown", ".txt"}
_help = {}


def helpfor(path):
    key = tuple(path)
    if key not in _help:
        r = subprocess.run(CLI + list(path) + ["--help"], capture_output=True, text=True)
        flags = set(re.findall(r"(?<![\w-])(--[a-z][a-z0-9-]*)", r.stdout + r.stderr))
        _help[key] = (r.returncode == 0, flags)
    return _help[key]


# `ascend <verb> [<sub>] rest…` — stop at a newline, a backtick, a pipe, or a shell separator
INVOKE = re.compile(r"(?<![\w./-])ascend[ \t]+([a-z][a-z-]*)(?:[ \t]+([a-z][a-z-]*))?([^\n`|;&#]*)")
BOX = re.compile(r"[\u2500-\u257f]")           # box-drawing: a diagram, not a command
# flags mentioned in prose outside a command are not checked; only those on the same invocation
FLAG = re.compile(r"(?<![\w-])(--[a-z][a-z0-9-]*)")


def check(text, where):
    out = []
    for m in INVOKE.finditer(text):
        line_text = text[text.rfind("\n", 0, m.start()) + 1: text.find("\n", m.end()) if text.find("\n", m.end()) != -1 else len(text)]
        if BOX.search(line_text):
            continue
        v1, v2, rest = m.group(1), m.group(2), m.group(3) or ""
        path = [v1] + ([v2] if v2 else [])
        ok, accepted = helpfor(path)
        if not ok and len(path) == 2:
            path, (ok, accepted) = [v1], helpfor([v1])
        line = text.count("\n", 0, m.start()) + 1
        if not ok:
            out.append(f"{where}:{line}: not a command: `ascend {' '.join(path)}`")
            continue
        for fl in sorted(set(FLAG.findall(rest)) - accepted):
            out.append(f"{where}:{line}: `ascend {' '.join(path)}` does not accept {fl}")
    return out


def main(argv):
    roots = [Path(a) for a in argv] or [REPO / "README.md", REPO / "docs", REPO / "skills"]
    files = []
    for r in roots:
        files += [r] if r.is_file() else [p for p in r.rglob("*") if p.suffix in EXT]
    problems, n = [], 0
    for f in sorted(files):
        try:
            text = f.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        n += len(INVOKE.findall(text))
        problems += check(text, str(f))
    print(f"checked {n} `ascend …` invocations across {len(files)} files: {len(problems)} problem(s)")
    for p in problems:
        print("  " + p)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
