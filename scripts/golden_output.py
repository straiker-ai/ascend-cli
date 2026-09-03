#!/usr/bin/env python3
"""
golden_output.py — capture or verify the CLI's plain-text output.

Why: the visual work must not change a single byte of what a pipe, a script, or an agent sees.
That promise is only worth something if it is mechanically checkable, so this records stdout and
stderr for a fixed set of offline commands under NO_COLOR and diffs them later.

    python3 scripts/golden_output.py --record     # refresh the corpus (review the diff!)
    python3 scripts/golden_output.py --check      # fail if anything drifted

Only commands that need no network are listed: the point is a deterministic byte comparison, not
coverage of the platform.

Two cases were tried and removed rather than fudged: `adapter configs` and a not-found `--config`
both LIST the operator's own config files. Every config directory that gets searched -- including
the repo's own `configs/` -- holds untracked local files, so that output differs per machine by
design and no amount of path normalization makes it comparable. A corpus case that cannot hold
everywhere is worse than no case: it fails for whoever runs it next, and the natural response is
to re-record and bury whatever it was protecting.
"""
import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
CLI = REPO / "shells" / "cli" / "ascend.py"
GOLDEN = REPO / "tests" / "golden"

CASES = {
    "help":               ["--help"],
    "version":            ["version"],
    "help_target":        ["target", "--help"],
    "help_target_add":    ["target", "add", "--help"],
    "help_assess":        ["assess", "--help"],
    "help_assess_watch":  ["assess", "watch", "--help"],
    "help_bridge":        ["bridge", "--help"],
    "help_adapter":       ["adapter", "--help"],
    "help_results":       ["results", "--help"],
    "help_status":        ["status", "--help"],
    "adapter_list":       ["adapter", "list"],
    "bad_out_dir":        ["adapter", "build", "--api", "http://127.0.0.1:1/x", "--out", "./"],
    "unknown_command":    ["not-a-command"],
}

ENV = {"NO_COLOR": "1", "ASCEND_NO_SPINNER": "1", "ASCEND_SKIP_TENANT_CHECK": "1",
       "STRAIKER_PAT": "s6r_pat_dummy", "COLUMNS": "100", "TERM": "dumb"}


def _normalize(text):
    """Delegates to the ONE normalizer — see scripts/corpus_normalize.py.

    This was a private copy, duplicated verbatim in back_compat.py, and the two had already
    drifted: an argparse fix landed here and not there, so identical CLI output compared equal in
    one gate and unequal in the other.
    """
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from corpus_normalize import normalize
    return normalize(text, REPO)


def run(argv):
    env = {k: v for k, v in os.environ.items()
           if k not in ("ASCEND_FORCE_COLOR", "ASCEND_PLAIN", "ASCEND_COLOR_DEPTH",
                        "COLORTERM", "TERM_PROGRAM", "ASCEND_CONFIG_DIR")}
    env.update(ENV)
    r = subprocess.run([sys.executable, str(CLI), *argv], capture_output=True, text=True,
                       cwd=str(REPO), env=env, timeout=180)
    # The exit code is part of the contract, so it is recorded alongside the text.
    return _normalize(
        f"$ ascend {' '.join(argv)}\n--- exit {r.returncode}\n--- stdout\n{r.stdout}"
        f"--- stderr\n{r.stderr}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--record", action="store_true")
    ap.add_argument("--check", action="store_true")
    a = ap.parse_args()
    GOLDEN.mkdir(parents=True, exist_ok=True)
    drift = []
    for name, argv in CASES.items():
        got = run(argv)
        path = GOLDEN / f"{name}.txt"
        if a.record:
            path.write_text(got)
            continue
        want = path.read_text() if path.is_file() else None
        if want is None:
            drift.append(f"{name}: no golden file (run --record)")
        elif want != got:
            drift.append(f"{name}: output changed")
    if a.record:
        print(f"recorded {len(CASES)} case(s) into {GOLDEN}")
        return 0
    if drift:
        print("golden output drifted:", *(f"  {d}" for d in drift), sep="\n")
        print("\nreview the change, then re-record with:  "
              "python3 scripts/golden_output.py --record")
        return 1
    print(f"golden output unchanged ({len(CASES)} cases)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
