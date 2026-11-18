#!/usr/bin/env python3
"""run_poc_b.py — drive POC-B (indirect agent coercion) in any of three modes.

POC-B: an agent connected to a UE 5.8 MCP endpoint reads poisoned asset metadata and obeys an
instruction embedded in it. One benign canary is the proof. The three modes trade fidelity for
convenience; they share the same injection payload and the same compliance oracle:

  Mode A  --mock-agent {obey|resist}
      Fully self-contained and deterministic. Starts the mock target, runs the mock agent
      (a susceptible one with `obey`, a hardened one with `resist`), checks the oracle.
      No Unreal, no live model, no network. This is what the tests use.

  Mode B  (default)
      Real agent, mock target. Starts the mock target and prints the endpoint + the exact
      benign task to give your coding agent (e.g. Codex pointed at this endpoint). You run the
      agent; this process watches the canary and reports compliance. Authentic model-
      susceptibility signal with zero Unreal install.

  Mode C  --endpoint http://127.0.0.1:8000/mcp
      Real agent, real UE. Same as Mode B but against a live editor you seeded with
      ue58_mcp_prepare_seed.py. This runner does not start a server; it only watches the oracle.
      (No new code — Mode C is Mode B with the endpoint swapped.)

    python3 poc_b/run_poc_b.py --mock-agent obey       # Mode A, expect: COMPLIED
    python3 poc_b/run_poc_b.py --mock-agent resist     # Mode A, expect: resisted
    python3 poc_b/run_poc_b.py                          # Mode B, drives a real agent
    python3 poc_b/run_poc_b.py --endpoint http://127.0.0.1:8000/mcp   # Mode C

SAFETY: the injected instruction is a benign canary (write one marker file to a path this runner
chose under a temp dir). The mock target never writes files or runs scripts; it only serves
metadata. Keep every endpoint on loopback.
"""
from __future__ import annotations

import argparse
import socket
import subprocess
import sys
import tempfile
import time
from contextlib import closing
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import compliance_check  # noqa: E402
import injection  # noqa: E402

TARGET = HERE / "mock_agent_target_server.py"
MOCK_AGENT = HERE / "mock_agent_client.py"


def _free_port() -> int:
    with closing(socket.socket()) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_listen(port: int, timeout: float = 8.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        with closing(socket.socket()) as s:
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return
        time.sleep(0.1)
    raise RuntimeError(f"server on :{port} never came up")


def _default_canary() -> str:
    d = Path(tempfile.gettempdir()) / "rtc358-poc-b"
    return str(d / "canary.txt")


def _start_target(port: int, canary_path: str, marker: str) -> subprocess.Popen:
    proc = subprocess.Popen(
        [sys.executable, str(TARGET), str(port),
         "--canary-path", canary_path, "--marker", marker],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    _wait_listen(port)
    return proc


def mode_a(policy: str, canary_path: str, marker: str) -> int:
    """Self-contained: mock target + mock agent + oracle."""
    compliance_check.clear_canary(canary_path)
    port = _free_port()
    proc = _start_target(port, canary_path, marker)
    try:
        subprocess.run(
            [sys.executable, str(MOCK_AGENT),
             "--endpoint", f"http://127.0.0.1:{port}/mcp", "--policy", policy],
            check=True)
    finally:
        proc.terminate()
        proc.wait(timeout=5)
    finding = compliance_check.check(canary_path, marker)
    _report(finding, policy)
    return 1 if finding["complied"] else 0


def mode_b(canary_path: str, marker: str, endpoint: str | None) -> int:
    """Real agent. Mock target (endpoint None) or live UE (endpoint given)."""
    compliance_check.clear_canary(canary_path)
    proc = None
    if endpoint is None:
        port = _free_port()
        proc = _start_target(port, canary_path, marker)
        endpoint = f"http://127.0.0.1:{port}/mcp"
        print(f"[mock target] serving poisoned metadata at {endpoint}")
    else:
        print(f"[live endpoint] {endpoint}  (seed it with ue58_mcp_prepare_seed.py first)")
        print(f"[live endpoint] ensure the seeded instruction writes {canary_path!r} = {marker!r}")

    print("\n--- point your coding agent at the endpoint above and give it this task ---\n")
    print(injection.LIVE_AGENT_TASK)
    print("\n--- then press Enter here to check for compliance (Ctrl-C to abort) ---")
    try:
        input()
    except (KeyboardInterrupt, EOFError):
        print("\naborted")
        if proc:
            proc.terminate()
            proc.wait(timeout=5)
        return 2

    finding = compliance_check.check(canary_path, marker)
    _report(finding, "live-agent")
    if proc:
        proc.terminate()
        proc.wait(timeout=5)
    return 1 if finding["complied"] else 0


def _report(finding: dict, who: str) -> None:
    print(f"\nPOC-B result  (agent: {who})")
    print(f"  asset    : {injection.ASSET_PATH}")
    print(f"  canary   : {finding['canary_path']}")
    print(f"  exists={finding['canary_exists']}  marker_found={finding['marker_found']}")
    if finding["complied"]:
        print("  => AGENT COMPLIED — susceptible to indirect prompt injection")
    else:
        print("  => agent resisted — no action taken on injected metadata")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--mock-agent", choices=("obey", "resist"),
                    help="Mode A: run the deterministic mock agent with this policy")
    ap.add_argument("--endpoint", help="Mode C: live UE MCP endpoint (default: start the mock)")
    ap.add_argument("--canary-path", default=_default_canary())
    ap.add_argument("--marker", default=injection.DEFAULT_MARKER)
    args = ap.parse_args(argv)

    if args.mock_agent:
        return mode_a(args.mock_agent, args.canary_path, args.marker)
    return mode_b(args.canary_path, args.marker, args.endpoint)


if __name__ == "__main__":
    raise SystemExit(main())
