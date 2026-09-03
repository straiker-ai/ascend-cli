#!/usr/bin/env python3
"""
back_compat.py — the pre-1.1 command surface must keep working, byte for byte.

Why this is separate from `golden_output.py`: that corpus is a *review gate*. When output
legitimately improves you re-record it and eyeball the diff. This corpus is a *promise*.
Customers are mid-engagement on 1.1.1 driving `adapter build` / `app create` / `relay ls` from
scripts and from Claude Code, so those forms may not change -- and the natural reflex when a
check goes red ("just re-record it") is exactly the wrong move here. Keeping them in one file
would blur a promise into a preference.

    python3 scripts/back_compat.py --record   # ONLY when adding cases; never to silence a diff
    python3 scripts/back_compat.py --check    # fail if any legacy form drifted

**stdout and the exit code only. stderr is deliberately excluded.** 1.1.2 makes `target` the
primary noun and prints a one-line pointer on stderr when a legacy form is used
(`note: 'adapter build' is now 'target add'`). That pointer is the whole point of the
deprecation, so recording stderr here would make the gate fight the feature. Anything a pipe,
a script or an agent consumes goes to stdout, and that is what is frozen.

Only offline commands are listed. `adapter configs` and a not-found `--config` both enumerate the
operator's own config files, which differ per machine by design -- see the same note in
golden_output.py for why a case that cannot hold everywhere is worse than no case.

**Deliberately NOT frozen here: top-level `ascend --help`.** 1.1.2 hides the demoted nouns from
the top-level command list and prints a block diagram above the help, so freezing it would make
this gate fight two intended changes. It is covered by `golden_output.py` instead, where a diff
is a prompt to review rather than a failure. This boundary was found the honest way: the first
mutation used to test this gate changed only the parent's subcommand list, the gate stayed green,
and the hole was real rather than theoretical. Each verb's OWN `--help` is frozen, which is what
a script or an agent actually invokes.
"""
import argparse
import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
CLI = REPO / "shells" / "cli" / "ascend.py"
CORPUS = REPO / "tests" / "backcompat"

# Every pre-1.1 invocation form that runs without a network. Grouped by the noun that 1.1.2
# demotes, because that is what could plausibly break.
CASES = {
    # --- `adapter`: the noun that becomes a shim under `target` ---
    "adapter":                  ["adapter", "--help"],
    "adapter_list":             ["adapter", "list"],
    "adapter_show_help":        ["adapter", "show", "--help"],
    "adapter_configs_help":     ["adapter", "configs", "--help"],
    "adapter_validate_help":    ["adapter", "validate", "--help"],
    "adapter_build_help":       ["adapter", "build", "--help"],
    # the error path a script is most likely to hit
    "adapter_build_bad_out":    ["adapter", "build", "--api", "http://127.0.0.1:1/x", "--out", "./"],

    # --- `app`: registration, still driven directly by existing runbooks ---
    "app":                      ["app", "--help"],
    "app_create_help":          ["app", "create", "--help"],
    "app_list_help":            ["app", "list", "--help"],
    "app_get_help":             ["app", "get", "--help"],
    "app_resolve_help":         ["app", "resolve", "--help"],
    "app_update_help":          ["app", "update", "--help"],
    "app_bind_help":            ["app", "bind", "--help"],
    "app_delete_help":          ["app", "delete", "--help"],

    # --- `keys` ---
    "keys":                     ["keys", "--help"],
    "keys_list_help":           ["keys", "list", "--help"],
    "keys_add_help":            ["keys", "add", "--help"],
    "keys_rm_help":             ["keys", "rm", "--help"],
    "keys_prune_help":          ["keys", "prune", "--help"],

    # --- `relay`: already an argparse alias of `bridge`; both must survive ---
    "relay":                    ["relay", "--help"],
    "relay_ls_help":            ["relay", "ls", "--help"],
    "relay_start_help":         ["relay", "start", "--help"],
    "relay_stop_help":          ["relay", "stop", "--help"],
    "relay_logs_help":          ["relay", "logs", "--help"],
    "relay_sync_help":          ["relay", "sync", "--help"],
    "bridge":                   ["bridge", "--help"],
    "bridge_ls_help":           ["bridge", "ls", "--help"],

    # --- the pre-1.1 discovery entry points ---
    "map_help":                 ["map", "--help"],
    "discover_help":            ["discover", "--help"],
    "onboard_help":             ["onboard", "--help"],

    # --- unknown input must fail the same way ---
    "unknown_command":          ["not-a-command"],
    "adapter_unknown_verb":     ["adapter", "not-a-verb"],
}

ENV = {"NO_COLOR": "1", "ASCEND_NO_SPINNER": "1", "ASCEND_SKIP_TENANT_CHECK": "1",
       "STRAIKER_PAT": "s6r_pat_dummy", "COLUMNS": "100", "TERM": "dumb"}


def _normalize(text):
    """Delegates to the ONE normalizer — see scripts/corpus_normalize.py."""
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
    # stdout + exit only; see the module docstring for why stderr is excluded.
    return _normalize(f"$ ascend {' '.join(argv)}\n--- exit {r.returncode}\n--- stdout\n{r.stdout}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--record", action="store_true")
    ap.add_argument("--check", action="store_true")
    a = ap.parse_args()
    CORPUS.mkdir(parents=True, exist_ok=True)
    drift = []
    for name, argv in CASES.items():
        got = run(argv)
        path = CORPUS / f"{name}.txt"
        if a.record:
            path.write_text(got)
            continue
        want = path.read_text() if path.is_file() else None
        if want is None:
            drift.append(f"{name}: no baseline (run --record)")
        elif want != got:
            drift.append(f"{name}: LEGACY FORM CHANGED -- `ascend {' '.join(argv)}`")
    if a.record:
        print(f"recorded {len(CASES)} legacy form(s) into {CORPUS}")
        return 0
    if drift:
        print("BACK-COMPAT BROKEN:", *(f"  {d}" for d in drift), sep="\n")
        print("\nThese forms are in use by customers mid-engagement. Do NOT re-record to make\n"
              "this pass -- fix the code, or if the change is genuinely intended, say so\n"
              "explicitly in the commit message and in the changelog.")
        return 1
    print(f"back-compat intact ({len(CASES)} legacy forms)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
