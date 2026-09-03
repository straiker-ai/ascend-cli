"""
test_golden_output — the plain-text output a pipe, a script or an agent sees must not move.

The visual work is for a human at a TTY. Everyone else — CI, `| tee`, a coding agent reading
stdout — must get byte-identical output to before. A promise like that is only worth something if
it is checkable, so `scripts/golden_output.py` records stdout, stderr AND the exit code for a set
of offline commands under NO_COLOR, and this test diffs them.

When a diff is intentional, review it by eye and re-record:
    python3 scripts/golden_output.py --record
"""
import pytest
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def test_plain_output_matches_the_golden_corpus():
    r = subprocess.run([sys.executable, str(REPO / "scripts" / "golden_output.py"), "--check"],
                       capture_output=True, text=True, cwd=str(REPO), timeout=600)
    assert r.returncode == 0, r.stdout + r.stderr
