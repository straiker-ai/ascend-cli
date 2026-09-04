#!/usr/bin/env python3
"""
live_sweep.py — drive EVERY command of the real CLI against a real agent on the real tenant.

`scripts/live_matrix.py` proves the adapters can talk to each wire shape. This proves the rest of
the surface: all 59 leaf commands, with their real flags, in the order an operator would use them,
against a target that answers with a Bedrock brain and an app registered on the demo tenant.
Nothing is mocked. Every row is a real process exit code and real output.

    export STRAIKER_PAT=s6r_pat_...        # demo tenant
    python3 demo/localhost_agent.py --port 8600 &
    python3 scripts/live_sweep.py [--keep] [--json out.json]

WHAT IT DOES
  1. onboards ONE target for real (`target add`, scoped to `sys_prompt_leak` so the assessment it
     runs is ~4 probes, not the catalog), and remembers the exact app name it created;
  2. runs every command in dependency order — read-only ones first, then the ones that need a
     registered app, then the lifecycle (assess run -> results -> export -> ci);
  3. tears down exactly what it created, by exact name — never a prefix sweep;
  4. prints a table and exits non-zero if any command that MUST work did not.

WHAT IT REFUSES TO RUN, AND SAYS SO
  * `tenant switch --confirm` — clears every stored bridge key on this machine. Manual only.
  * `keys prune` without a dry-run flag — same blast radius.
  * `bridge start --foreground` is run with a timeout because it is a known crash (open bug); a
    crash is recorded as a FINDING, not skipped.

Exit codes are read from the process, never from `$?` after a pipe — that produced three false
results in one session. Every expectation is a measured fact from this run, not an assumption.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
CLI = [sys.executable, str(REPO / "shells" / "cli" / "ascend.py")]
STAMP = time.strftime("%H%M%S")
APP = f"Sweep {STAMP}"                 # exact name; teardown deletes ONLY this
CFG = f"sweep-{STAMP}"
TARGET = os.environ.get("SWEEP_TARGET", "http://127.0.0.1:8600/chat")
rows: list[dict] = []
state: dict = {"app_id": None, "assessment": None}


def run(label, argv, *, must=True, expect_exit=0, timeout=300, stdin=None, env=None,
        note=""):
    """One command, one row. `must` marks commands the sweep fails on."""
    t0 = time.time()
    try:
        r = subprocess.run(CLI + argv, capture_output=True, text=True, timeout=timeout,
                           input=stdin, env={**os.environ, "COLUMNS": "120", **(env or {})})
        code, out, err = r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired as e:
        code, out, err = -9, (e.stdout or ""), f"TIMEOUT after {timeout}s"
    ok = code == expect_exit
    rows.append({"cmd": " ".join(argv[:3]), "label": label, "exit": code,
                 "expected": expect_exit, "ok": ok, "must": must,
                 "ms": int((time.time() - t0) * 1000),
                 "note": note or (err.strip().splitlines()[-1][:110] if not ok and err.strip() else "")})
    print(f"  {'ok ' if ok else 'XX '} {label:40} exit={code:<3} {int((time.time()-t0)*1000):>6}ms"
          + (f"  {rows[-1]['note']}" if not ok else ""), flush=True)
    return code, out, err


def jq(out, *keys):
    try:
        d = json.loads(out)
        for k in keys:
            d = d[k]
        return d
    except Exception:
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--keep", action="store_true", help="leave the app it created on the tenant")
    ap.add_argument("--json", help="write the rows here")
    a = ap.parse_args()
    if not os.environ.get("STRAIKER_PAT"):
        sys.exit("STRAIKER_PAT is not set; the sweep needs the demo tenant")

    print(f"\n== READ-ONLY, no target needed ==")
    run("version", ["version"])
    run("version --json", ["version", "--json"])
    run("doctor", ["doctor"])
    run("tenant show", ["tenant", "show"])
    run("controls list", ["controls", "list"])
    run("controls validate", ["controls", "validate", "sys_prompt_leak"])
    run("controls validate (unknown -> 3)", ["controls", "validate", "no_such_control_zz"],
        expect_exit=3, note="unknown id must exit 3, not 0")
    run("target types", ["target", "types"])
    run("adapter list", ["adapter", "list"])
    run("adapter configs", ["adapter", "configs"])
    run("adapter show example", ["adapter", "show", "example-direct_api"])
    run("keys list", ["keys", "list"])
    run("policy show", ["policy", "show"])
    run("status", ["status"])
    run("bridge ls", ["bridge", "ls"])
    run("relay ls (legacy alias)", ["relay", "ls"])
    run("app list", ["app", "list"])
    run("reports", ["reports"])
    run("results (platform view)", ["results"])
    run("assess watch --once (no live run)", ["assess", "watch", "--all", "--once"], must=False)
    run("bare `ascend` on a pipe", [], expect_exit=2, must=False,
        note="exit 2 collides with the documented findings-gate code (open finding)")

    print(f"\n== DERIVE, no registration ==")
    run("target add --dry-run", ["target", "add", TARGET, "--save-as", CFG + "-dry", "--dry-run",
                                 "--timeout", "30"])
    run("adapter build (legacy)", ["adapter", "build", "--api", TARGET, "--out",
                                   f"/tmp/{CFG}-ab.json", "--timeout", "30"])
    run("map (legacy alias)", ["map", "--api", TARGET, "--out", f"/tmp/{CFG}-map.json",
                               "--timeout", "30"])
    run("adapter validate --file", ["adapter", "validate", "--file", f"/tmp/{CFG}-ab.json",
                                    "--timeout", "30"])
    run("adapter show (built)", ["adapter", "show", f"/tmp/{CFG}-ab.json"], must=False)
    run("chat (3 turns, stdin)", ["chat", TARGET, "--timeout", "30"],
        stdin="hello\nwhat can you do\n/quit\n", must=False, timeout=120)
    run("target add --scaffold", ["target", "add", TARGET, "--scaffold", f"/tmp/{CFG}-custom.py",
                                  "--save-as", CFG + "-scaf", "--dry-run", "--timeout", "30"],
        must=False)

    print(f"\n== REGISTER for real (scoped to one control) ==")
    code, out, err = run("target add (register)", ["target", "add", TARGET, "--save-as", CFG,
                                                    "--name", APP, "--controls", "sys_prompt_leak",
                                                    "--timeout", "30", "--json"])
    state["app_id"] = jq(out, "app_id") or jq(out, "data", "app_id") or \
        (re.search(r"(aapp_[A-Za-z0-9]+)", out + err) or [None, None])[1]
    print(f"     app: {state['app_id']}")
    if not state["app_id"]:
        print("  cannot continue without a registered app"); return finish(a)

    run("target list", ["target", "list"])
    run("target list --json", ["target", "list", "--json"])
    run("target show", ["target", "show", APP])
    run("target check", ["target", "check", APP, "--timeout", "30"])
    run("app get", ["app", "get", state["app_id"]])
    run("app resolve", ["app", "resolve", APP])
    run("app update --qpm", ["app", "update", state["app_id"], "--qpm", "20"], must=False)
    run("keys list (now has ours)", ["keys", "list"])
    run("app bind", ["app", "bind", CFG, "--app", state["app_id"]], must=False)
    run("policy set", ["policy", "set", "--fail-on-severity", "high"], must=False)
    run("policy push", ["policy", "push", "--app", state["app_id"]], must=False)
    run("assess list", ["assess", "list", "--app", APP])

    print(f"\n== LIFECYCLE: run -> results -> export -> ci ==")
    code, out, err = run("assess run (real probes)", ["assess", "run", "--app", APP, "--name",
                         f"sweep-{STAMP}", "--interval", "10", "--timeout", "900"], timeout=960)
    m = re.search(r"(asmt_[A-Za-z0-9]+)", out + err)
    state["assessment"] = m.group(1) if m else None
    print(f"     assessment: {state['assessment']}")
    run("bridge ls (after run)", ["bridge", "ls"])
    run("bridge logs", ["bridge", "logs", APP], must=False)
    if state["assessment"]:
        run("assess status", ["assess", "status", "--app", APP, "--assessment", state["assessment"]])
        run("assess results", ["assess", "results", "--app", APP, "--assessment", state["assessment"]])
        run("assess results --detail", ["assess", "results", "--app", APP, "--assessment",
                                        state["assessment"], "--detail"])
    run("results --app", ["results", "--app", APP])
    run("results --app --detail", ["results", "--app", APP, "--detail"])
    run("export json", ["export", "--app", APP, "--format", "json"])
    run("export csv", ["export", "--app", APP, "--format", "csv"])
    run("export markdown", ["export", "--app", APP, "--format", "markdown"])
    run("export sarif", ["export", "--app", APP, "--format", "sarif"])
    run("ci --app (latest run)", ["ci", "--app", APP, "--fail-on-severity", "high"])
    run("ci --junit", ["ci", "--app", APP, "--fail-on-severity", "high", "--junit",
                       f"/tmp/{CFG}-junit.xml"])
    run("assess diff (needs 2 runs)", ["assess", "diff", "--app", APP], must=False)

    print(f"\n== BRIDGE / RELAY controls ==")
    run("bridge stop --all", ["bridge", "stop", "--all"], must=False)
    run("bridge start --foreground (KNOWN CRASH)", ["bridge", "start", "--app", APP, "--config",
        CFG, "--foreground"], must=False, timeout=15, expect_exit=-9,
        note="expected: runs until timeout; a crash exits <15s with a traceback (open bug)")
    run("bridge start (background)", ["bridge", "start", "--app", APP, "--config", CFG], must=False)
    time.sleep(3)
    run("bridge ls (serving)", ["bridge", "ls"])
    run("bridge stop --app", ["bridge", "stop", "--app", APP], must=False)
    run("bridge sync", ["bridge", "sync"], must=False,
        note="open finding: starts bridges for unrelated apps; run last")
    run("runtime start (legacy, short)", ["runtime", "start", "--config", CFG, "--wait-ms", "2000"],
        must=False, timeout=20, expect_exit=-9)

    print(f"\n== SECOND RUN so diff has two ==")
    run("assess run #2", ["assess", "run", "--app", APP, "--name", f"sweep-{STAMP}-b",
                          "--interval", "10", "--timeout", "900", "--controls", "sys_prompt_leak"],
        timeout=960)
    run("assess diff", ["assess", "diff", "--app", APP], must=False)

    return finish(a)


def finish(a):
    print(f"\n== TEARDOWN (exact names only) ==")
    if state["app_id"] and not a.keep:
        run("bridge stop --all", ["bridge", "stop", "--all"], must=False)
        run(f"keys rm {state['app_id']}", ["keys", "rm", state["app_id"]], must=False)
        run(f"target rm '{APP}'", ["target", "rm", APP, "--json"])
        run("app list (ours gone)", ["app", "list"])
    for f in Path("/tmp").glob(f"{CFG}-*"):
        f.unlink(missing_ok=True)
    print("\n  NOT run, by design: tenant switch --confirm (clears every stored key), keys prune")

    bad = [r for r in rows if r["must"] and not r["ok"]]
    soft = [r for r in rows if not r["must"] and not r["ok"]]
    print(f"\n== {len(rows)} commands: {len(rows)-len(bad)-len(soft)} ok, "
          f"{len(bad)} MUST-fix, {len(soft)} soft findings ==")
    for r in bad:
        print(f"  MUST  {r['label']:40} exit={r['exit']} {r['note']}")
    for r in soft:
        print(f"  soft  {r['label']:40} exit={r['exit']} {r['note']}")
    if a.json:
        Path(a.json).write_text(json.dumps({"app": APP, "rows": rows}, indent=1))
        print(f"  wrote {a.json}")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
