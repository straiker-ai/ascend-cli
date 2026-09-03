#!/usr/bin/env python3
"""
corpus_normalize.py — the ONE normalizer for both recorded corpora.

`golden_output.py` and `back_compat.py` each carried their own copy of this, character for
character, and they had already drifted: a fix for argparse's version-dependent wording landed in
one and not the other, so the same CLI output compared equal in one gate and unequal in the other.

That is the same duplicate-logic defect that caused most of the bugs this release — in the two
scripts whose whole job is to catch drift.

WHAT GETS NORMALIZED, AND WHY EACH ONE IS SAFE

A corpus is only worth having if it fails for a change THIS PROJECT made. Everything stripped here
belongs to the machine or to CPython, so keeping it would make the gate fail on days when nothing
changed — and a gate that cries wolf gets re-recorded, which silently buries whatever it was
protecting.

  * Absolute paths (`<REPO>`, `<HOME>`). The first recording baked in the path of the clone that
    made it, so the corpus passed on exactly one machine.
  * `/private/tmp` -> `/tmp`. macOS spells the same directory both ways.
  * argparse's optional-arguments HEADER. Python 3.10 renamed `optional arguments:` to `options:`.
  * argparse's invalid-choice LIST. `(choose from 'a', 'b')` lost its inner quotes during 3.12, so
    a corpus recorded on 3.12.7 failed on the 3.12.14 a CI runner happened to have. Pinning to a
    minor version was not enough; pinning to a patch is worse, because the runner updates
    underneath you.

Note what is NOT lost by the last two: which commands exist, and every flag on them, are asserted
by `gen_command_map.py --check`, which diffs the entire parser tree. These two rules drop CPython's
rendering, not our surface.
"""
import os
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def normalize(text, repo=None):
    """Strip machine- and interpreter-specific text so a corpus holds in ANY checkout."""
    repo = str(repo or REPO)
    home = os.path.expanduser("~")
    out = text.replace(repo + os.sep, "<REPO>/").replace(repo, "<REPO>")
    out = out.replace(home + os.sep, "<HOME>/").replace(home, "<HOME>")
    out = out.replace("/private/tmp", "/tmp")
    # CPython's own wording, not ours — see the module docstring.
    out = out.replace("optional arguments:", "options:")
    out = re.sub(r"\(choose from [^)]*\)", "(choose from <COMMANDS>)", out)
    return out
