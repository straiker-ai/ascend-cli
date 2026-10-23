#!/usr/bin/env python3
"""run_demo.py — drive the UE 5.8 sandbox-escape probe pack through the Ascend adapter.

This is the self-scored local runner for the demo. It reads probes/manifest.json, submits each
script body through unreal_mcp_adapter.send_prompt (the same adapter the Ascend bridge would
load), and judges PASS/FAIL from the returned evidence — no cloud, no external scorer.

    # 1. start the mock UE MCP endpoint (or point at a live UE 5.8 editor)
    python3 demo/unreal-mcp/mock_ue_mcp_server.py 8000 &

    # 2. run the pack (local-only probes: filesystem write + process exec)
    python3 demo/unreal-mcp/run_demo.py

    # against a live editor, or a different port:
    UE_MCP_ENDPOINT=http://127.0.0.1:8000/mcp python3 demo/unreal-mcp/run_demo.py --allow-network
    python3 demo/unreal-mcp/run_demo.py --endpoint http://127.0.0.1:8000/mcp

By default the two network probes (T3/T3b, a real outbound HTTP GET) are SKIPPED; pass
--allow-network to include them. Exit code is 0 only if every executed probe scored as expected.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))  # so `import unreal_mcp_adapter` resolves beside this file

GREEN, RED, DIM, BOLD, RESET = "\033[32m", "\033[31m", "\033[2m", "\033[1m", "\033[0m"


def _color(enabled: bool):
    if enabled:
        return GREEN, RED, DIM, BOLD, RESET
    return "", "", "", "", ""


def _score(evidence: str, expect: dict) -> tuple[bool, str]:
    """Judge one probe's evidence string against its manifest expectation."""
    kind = expect.get("type")
    if kind == "blocked":
        needle = expect.get("contains", "")
        return (needle in evidence), f"sandbox message contains {needle!r}"
    # type == "evidence": the escape returned a JSON dict from run()
    try:
        obj = json.loads(evidence)
    except (json.JSONDecodeError, TypeError):
        return False, f"expected JSON evidence, got: {evidence[:120]!r}"
    if not isinstance(obj, dict):
        return False, "evidence was not a JSON object"
    if expect.get("ok") and not obj.get("ok"):
        return False, f"run() reported ok=false: {obj}"
    if "field" in expect:
        got = obj.get(expect["field"])
        want = expect.get("equals")
        if got != want:
            return False, f"{expect['field']}={got!r}, expected {want!r}"
    if "field_nonempty" in expect:
        got = obj.get(expect["field_nonempty"])
        if not got:
            return False, f"{expect['field_nonempty']} was empty"
    if "field_present" in expect and expect["field_present"] not in obj:
        return False, f"missing field {expect['field_present']}"
    return True, "evidence matches"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--endpoint", help="override UE_MCP_ENDPOINT")
    parser.add_argument("--allow-network", action="store_true",
                        help="also run the network-egress probes (T3/T3b)")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    parser.add_argument("--no-color", action="store_true")
    args = parser.parse_args(argv)

    if args.endpoint:
        os.environ["UE_MCP_ENDPOINT"] = args.endpoint

    # import AFTER setting the env var, so the adapter binds the right endpoint
    import unreal_mcp_adapter as adapter

    g, r, dim, bold, rst = _color(not args.no_color and sys.stdout.isatty())

    manifest = json.loads((HERE / "probes" / "manifest.json").read_text())
    endpoint = os.environ.get("UE_MCP_ENDPOINT", adapter.ENDPOINT)

    # Preflight: reachable? mock or live? One clear line instead of six identical failures.
    pf = adapter.preflight()
    if not pf.get("reachable"):
        msg = (f"endpoint {endpoint} is not reachable: {pf.get('error')}\n"
               f"start the mock (python3 demo/unreal-mcp/mock_ue_mcp_server.py <port>) "
               f"or point --endpoint at a live UE 5.8 MCP editor.")
        if args.json:
            print(json.dumps({"endpoint": endpoint, "preflight": pf, "error": msg}, indent=2))
        else:
            print(f"\n{r}preflight failed:{rst} {msg}\n")
        return 2
    kind = "MOCK" if pf.get("is_mock") else "LIVE"
    prog = "" if pf.get("has_programmatic") else "  (ProgrammaticToolset not advertised)"

    rows = []
    passed = failed = skipped = 0
    for probe in manifest["probes"]:
        pid = probe["id"]
        body = (HERE / "probes" / probe["file"]).read_text()
        if probe.get("network") and not args.allow_network:
            rows.append((pid, "SKIP", probe["intent"], "network probe (use --allow-network)"))
            skipped += 1
            continue
        try:
            evidence = adapter.send_prompt(body)
            ok, why = _score(evidence, probe["expect"])
        except Exception as exc:  # transport / target failure
            ok, why, evidence = False, f"adapter error: {exc}", ""
        rows.append((pid, "PASS" if ok else "FAIL", probe["intent"], why))
        passed += ok
        failed += not ok

    if args.json:
        print(json.dumps({
            "endpoint": endpoint,
            "preflight": pf,
            "summary": {"pass": passed, "fail": failed, "skip": skipped},
            "results": [{"id": i, "status": s, "intent": intent, "detail": d}
                        for i, s, intent, d in rows],
        }, indent=2))
        return 0 if failed == 0 else 1

    print(f"\n{bold}UE 5.8 ProgrammaticToolset sandbox-escape — Ascend adapter demo{rst}")
    print(f"{dim}endpoint: {endpoint}{rst}")
    tag = f"{dim}MOCK{rst}" if kind == "MOCK" else f"{bold}LIVE{rst}"
    print(f"{dim}detected:{rst} {tag}  {dim}server={pf['server_name']}{rst}{dim}{prog}{rst}\n")
    print(f"  {'ID':<5} {'RESULT':<7} INTENT")
    print(f"  {'-'*5} {'-'*7} {'-'*50}")
    for pid, status, intent, why in rows:
        if status == "PASS":
            tag = f"{g}PASS{rst}   "
        elif status == "FAIL":
            tag = f"{r}FAIL{rst}   "
        else:
            tag = f"{dim}SKIP{rst}   "
        print(f"  {pid:<5} {tag} {intent}")
        if status == "FAIL":
            print(f"        {r}{dim}{why}{rst}")
    print(f"\n  {bold}{passed} passed, {failed} failed, {skipped} skipped{rst}")
    if failed == 0 and passed:
        print(f"  {g}Sandbox escape reproduced end-to-end through the Ascend adapter.{rst}\n")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
