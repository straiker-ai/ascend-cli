#!/usr/bin/env python3
"""
live_auth_matrix.py — onboard a REAL target behind each authentication gate and assert what
`ascend target add` makes of it. Nothing is mocked: the targets are agent-forge (a live model
behind ten auth gates on consecutive ports), and the CLI is the real one.

    python3 scripts/live_auth_matrix.py                 # derive only: --dry-run, no platform writes
    python3 scripts/live_auth_matrix.py --base-port 8920

The gate → expectation table is the contract this checks:

    gate          port  flags                                       expect
    apikey-hdr    +0    --api-key 'X-API-Key:env:FORGE_KEY'         answered, auth static/api_key, no secret in config
    apikey-qry    +1    --api-key 'key:env:FORGE_KEY:in=query'      answered, auth static/api_key in=query
    basic         +2    --basic 'demo:env:FORGE_PW'                 answered, auth static/basic
    token-ttl     +3    --login-url …/token --login-body {} --token-path access_token   answered, auth block present
    accesscode    +4    --body-field access_code=hunter2            answered
    cookiegate    +5    --login-url …/login --login-method GET      answered, auth block present
    csrf          +6    --login-url …/ --login-method GET --token-regex … --token-header X-CSRF-Token   answered
    hmac          +7    (none)                                      REFUSED, hint names --scaffold
    oauth2        +8    --login-url …/oauth2/token --login-body grant_type=client_credentials&…   answered, auth block present
    nonce         +9    (none)                                      REFUSED, hint names --scaffold

Exit 0 iff every row matches. Like scripts/live_matrix.py this is a release step, not CI: it needs a
real target on the network (CHANGE_CONTROL.md).
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
CLI = [sys.executable, str(REPO / "shells" / "cli" / "ascend.py")]
CONFIG_DIR = REPO / "configs"


def gates(base):
    u = lambda off, path="/chat": f"http://127.0.0.1:{base + off}{path}"  # noqa: E731
    return [
        ("apikey-hdr", u(0), ["--api-key", "X-API-Key:env:FORGE_KEY"], {"answered": True, "auth": ("static", "api_key"), "no_secret": "sk-demo-123"}),
        ("apikey-qry", u(1), ["--api-key", "key:env:FORGE_KEY:in=query"], {"answered": True, "auth": ("static", "api_key"), "no_secret": "sk-demo-123"}),
        ("basic", u(2), ["--basic", "demo:env:FORGE_PW"], {"answered": True, "auth": ("static", "basic"), "no_secret": "hunter2"}),
        ("token-ttl", u(3), ["--login-url", u(3, "/token"), "--login-body", "{}", "--token-path", "access_token"], {"answered": True, "auth_any": True}),
        ("accesscode", u(4), ["--body-field", "access_code=hunter2"], {"answered": True}),
        ("cookiegate", u(5), ["--login-url", u(5, "/login"), "--login-method", "GET"], {"answered": True, "auth_any": True}),
        ("csrf", u(6), ["--login-url", u(6, "/"), "--login-method", "GET", "--token-regex", 'csrf-token" content="([^"]+)', "--token-header", "X-CSRF-Token"], {"answered": True, "auth_any": True}),
        ("hmac", u(7), [], {"refused": "--scaffold"}),
        ("oauth2", u(8), ["--login-url", u(8, "/oauth2/token"), "--login-body", "grant_type=client_credentials&client_id=cid&client_secret=csecret", "--token-path", "access_token"], {"answered": True, "auth_any": True}),
        ("nonce", u(9), [], {"refused": "--scaffold"}),
    ]


def run_gate(label, url, flags, timeout):
    name = f"lam-{label}"
    (CONFIG_DIR / f"{name}.json").unlink(missing_ok=True)
    env = dict(os.environ, FORGE_KEY=os.environ.get("FORGE_KEY", "sk-demo-123"), FORGE_PW=os.environ.get("FORGE_PW", "hunter2"))
    r = subprocess.run(CLI + ["target", "add", "--api", url, "--save-as", name, "--dry-run", "--timeout", str(timeout)] + flags,
                       capture_output=True, text=True, env=env, timeout=timeout * 6)
    out = r.stdout + r.stderr
    cfg_path = CONFIG_DIR / f"{name}.json"
    cfg = json.loads(cfg_path.read_text()) if cfg_path.is_file() else None
    raw = cfg_path.read_text() if cfg_path.is_file() else ""
    return r.returncode, out, cfg, raw


def check(expect, rc, out, cfg, raw):
    problems = []
    if "refused" in expect:
        if rc == 0:
            problems.append("was not refused")
        if expect["refused"] not in out:
            problems.append(f"hint does not name {expect['refused']}")
        return problems
    if expect.get("answered") and "target replied" not in out and rc != 0:
        problems.append(f"no live reply (rc={rc})")
    auth = (cfg or {}).get("auth") or {}
    if "auth" in expect:
        want_type, want_mode = expect["auth"]
        if auth.get("type") != want_type or auth.get("mode") != want_mode:
            problems.append(f"auth is {auth.get('type')}/{auth.get('mode')}, want {want_type}/{want_mode}")
    if expect.get("auth_any") and not auth:
        problems.append("no auth block (the handshake recipe was not recorded)")
    if expect.get("no_secret") and expect["no_secret"] in raw:
        problems.append("the secret is stored in the config")
    return problems


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-port", type=int, default=8920)
    ap.add_argument("--timeout", type=int, default=25)
    ap.add_argument("--gates", default="all", help="comma-separated labels")
    a = ap.parse_args()
    rows = []
    for label, url, flags, expect in gates(a.base_port):
        if a.gates != "all" and label not in a.gates.split(","):
            continue
        try:
            rc, out, cfg, raw = run_gate(label, url, flags, a.timeout)
        except subprocess.TimeoutExpired:
            rc, out, cfg, raw = 124, "timeout", None, ""
        problems = check(expect, rc, out, cfg, raw)
        rows.append((label, rc, problems))
        (CONFIG_DIR / f"lam-{label}.json").unlink(missing_ok=True)
    width = max(len(r[0]) for r in rows)
    ok = True
    for label, rc, problems in rows:
        status = "ok" if not problems else "FAIL"
        ok &= not problems
        print(f"  {label:{width}}  rc={rc:<3} {status}" + (f"  — {'; '.join(problems)}" if problems else ""))
    print(f"\n{sum(1 for r in rows if not r[2])}/{len(rows)} gates as expected")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
