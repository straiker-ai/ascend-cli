#!/usr/bin/env python3
"""Run the live adapter matrix and APPEND one dated row to docs/LIVE_MATRIX.md.

Run after every merge to main. The number of shapes passing must only go up; a dip is a
regression caught in an hour instead of a round. This is the visibility that was missing: the
gates run in CI, but the matrix needs the local forge and a live tenant, so it is a recorded
post-merge step rather than a CI job.

    python3 scripts/live_matrix_record.py            # derive stage, every shape
    python3 scripts/live_matrix_record.py --stage full --shapes json,session
"""
import argparse, json, subprocess, sys, datetime as dt
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
LOG = REPO / "docs" / "LIVE_MATRIX.md"

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--stage", default="derive")
    ap.add_argument("--shapes", default="all")
    a = ap.parse_args()
    out = REPO / "captures" / "live_matrix_last.json"
    out.parent.mkdir(exist_ok=True)
    r = subprocess.run([sys.executable, str(REPO / "scripts" / "live_matrix.py"),
                        "--stage", a.stage, "--shapes", a.shapes, "--out", str(out)],
                       text=True)
    rows = json.loads(out.read_text()) if out.is_file() else []
    ok = [x for x in rows if x.get("ok")]
    bad = [x for x in rows if not x.get("ok")]
    sha = subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True,
                         text=True, cwd=REPO).stdout.strip()
    line = (f"| {dt.date.today().isoformat()} | `{sha}` | {a.stage} | **{len(ok)}/{len(rows)}** | "
            + (", ".join(f"`{x['shape']}`" for x in bad) if bad else "—") + " |\n")
    if not LOG.is_file():
        LOG.write_text("# Live adapter matrix — shapes passing over time\n\n"
                       "Appended by `scripts/live_matrix_record.py` after every merge to main. Read the\n"
                       "last column first: it must be empty, and the count must never go down.\n\n"
                       "| date | main | stage | passing | failing shapes |\n|---|---|---|---|---|\n")
    LOG.write_text(LOG.read_text() + line)
    print(f"\n  recorded: {line.strip()}")
    return 0 if not bad else 1

if __name__ == "__main__":
    sys.exit(main())
