#!/usr/bin/env python3
"""Detector: is a UE-5.8-style MCP ProgrammaticToolset's Python sandbox escapable?

This is the *detection* counterpart to the reproduce demo in ../. The demo PROVES impact
(writes a file, spawns a process, makes a request). A detector must answer "is this endpoint
vulnerable?" WITHOUT causing impact — so it runs a single **zero-side-effect** probe:

    recover json.__dict__["__builtins__"] and report whether `open` / `__import__` came back.

That recovers the unrestricted builtins (the whole vulnerability) but calls none of them — no
file is written, no process spawned, no network touched. It is the safe signal a scanner wants.

Verdict logic (all three signals, so we don't misread an open interpreter as a broken sandbox):
  * CONTROL  — `import os` and write-mode `open()` are both rejected  -> a sandbox IS advertised
  * ESCAPE   — the benign primitive returns has_open AND has_import   -> the sandbox is escapable
  => VULNERABLE only when a sandbox is advertised AND it is escapable. If the controls are not
     enforced it is not this sandbox (inconclusive); if the primitive fails the sandbox holds.

Transport reuses ../unreal_mcp_adapter (mcp SDK if present, else a stdlib streamable-HTTP client),
so it speaks the real UE endpoint and the local mock alike. Endpoint via --endpoint / UE_MCP_ENDPOINT.

AUTHORIZATION: submitting any script to a ProgrammaticToolset is an action on that editor. Only run
this against an endpoint you are authorized to test. The probe is benign (no side effects), but it
is still a real call — the banner says so, and a non-loopback endpoint needs --authorized.

    python3 detect/detect_sandbox_escape.py --endpoint http://127.0.0.1:8111/mcp
    python3 detect/detect_sandbox_escape.py --endpoint https://host:8000/mcp --authorized --json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from urllib.parse import urlparse

HERE = Path(__file__).resolve().parent
DEMO = HERE.parent
sys.path.insert(0, str(DEMO))  # reuse the demo adapter (preflight + send_prompt)

REFERENCE = "HackerOne #3907191 — UE 5.8 ProgrammaticToolset Python sandbox escape"

# The one probe this detector submits: recover the real builtins, call NONE of them.
BENIGN_PRIMITIVE = '''\
import json


def run():
    real_builtins = json.__dict__["__builtins__"]
    if not isinstance(real_builtins, dict):
        real_builtins = real_builtins.__dict__
    # Presence only — we never invoke open()/__import__(), so there is no side effect.
    return {
        "has_open": callable(real_builtins.get("open")),
        "has_import": callable(real_builtins.get("__import__")),
    }
'''


def _is_loopback(endpoint: str) -> bool:
    host = (urlparse(endpoint).hostname or "").lower()
    return host in ("127.0.0.1", "localhost", "::1")


def _blocked(evidence: str, needle: str) -> bool:
    return needle in (evidence or "")


def detect(adapter) -> dict:
    """Run the three signals and return a finding dict."""
    # 1-2. controls: a sandbox is advertised iff both naive paths are rejected.
    t0a = adapter.send_prompt((DEMO / "probes" / "t0a_negative_import_os.py").read_text())
    t0b = adapter.send_prompt((DEMO / "probes" / "t0b_negative_open_tmp.py").read_text())
    import_blocked = _blocked(t0a, "Import of 'os' is not permitted")
    openw_blocked = _blocked(t0b, "Mode 'w' is not permitted")
    sandbox_advertised = import_blocked and openw_blocked

    # 3. escape: benign builtins recovery.
    raw = adapter.send_prompt(BENIGN_PRIMITIVE)
    try:
        prim = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        prim = {}
    escapable = bool(prim.get("has_open")) and bool(prim.get("has_import"))

    if sandbox_advertised and escapable:
        verdict, severity = "vulnerable", "critical"
    elif sandbox_advertised and not escapable:
        verdict, severity = "not_vulnerable", "none"
    else:
        verdict, severity = "inconclusive", "none"

    return {
        "verdict": verdict,
        "severity": severity,
        "reference": REFERENCE,
        "tool": "editor_toolset.toolsets.programmatic.ProgrammaticToolset.execute_tool_script",
        "signals": {
            "sandbox_advertised": sandbox_advertised,
            "import_os_blocked": import_blocked,
            "open_write_blocked": openw_blocked,
            "builtins_recovered": escapable,
        },
        "benign": True,
        "side_effects": "none (presence check only; open/__import__ never invoked)",
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--endpoint", help="MCP endpoint (default UE_MCP_ENDPOINT or :8000)")
    ap.add_argument("--authorized", action="store_true",
                    help="acknowledge authorization for a non-loopback endpoint")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    import os
    if args.endpoint:
        os.environ["UE_MCP_ENDPOINT"] = args.endpoint
    import unreal_mcp_adapter as adapter  # after env is set
    endpoint = os.environ.get("UE_MCP_ENDPOINT", adapter.ENDPOINT)

    if not _is_loopback(endpoint) and not args.authorized:
        print(f"refusing non-loopback endpoint {endpoint} without --authorized "
              f"(you must be authorized to probe it)", file=sys.stderr)
        return 2

    pf = adapter.preflight()
    if not pf.get("reachable"):
        msg = f"endpoint {endpoint} not reachable: {pf.get('error')}"
        print(json.dumps({"endpoint": endpoint, "error": msg}) if args.json else msg,
              file=sys.stderr)
        return 2

    finding = detect(adapter)
    finding["endpoint"] = endpoint
    finding["target"] = "MOCK" if pf.get("is_mock") else "LIVE"

    if args.json:
        print(json.dumps(finding, indent=2))
    else:
        v = finding["verdict"]
        mark = {"vulnerable": "VULNERABLE", "not_vulnerable": "not vulnerable",
                "inconclusive": "inconclusive"}[v]
        print(f"\n{REFERENCE}")
        print(f"endpoint: {endpoint}  ({finding['target']})")
        print(f"  sandbox advertised : {finding['signals']['sandbox_advertised']}")
        print(f"  builtins recovered : {finding['signals']['builtins_recovered']}  (benign, no side effects)")
        print(f"  => {mark}  [severity: {finding['severity']}]\n")
    # exit 1 marks a positive detection (useful in CI / scan pipelines)
    return 1 if finding["verdict"] == "vulnerable" else 0


if __name__ == "__main__":
    raise SystemExit(main())
