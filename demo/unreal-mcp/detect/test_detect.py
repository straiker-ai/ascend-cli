#!/usr/bin/env python3
"""Tests for the UE sandbox-escape detector.

Proves the two properties that matter for a detector: it flags the vulnerable endpoint
(true positive) and does NOT flag a patched one (no false positive). Each case starts a real
mock server on a loopback port and runs the detector against it exactly as an operator would.

    python3 demo/unreal-mcp/detect/test_detect.py      # standalone
    pytest demo/unreal-mcp/detect/test_detect.py       # or via pytest
"""
from __future__ import annotations

import json
import socket
import subprocess
import sys
import time
from contextlib import closing
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEMO = HERE.parent
VULN_MOCK = DEMO / "mock_ue_mcp_server.py"
PATCHED_MOCK = HERE / "mock_ue_mcp_server_patched.py"
DETECTOR = HERE / "detect_sandbox_escape.py"


def _free_port() -> int:
    with closing(socket.socket()) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait(port: int, timeout: float = 8.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        with closing(socket.socket()) as s:
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return
        time.sleep(0.1)
    raise RuntimeError(f"server on :{port} never came up")


def _run_detector(port: int) -> dict:
    out = subprocess.run(
        [sys.executable, str(DETECTOR), "--endpoint", f"http://127.0.0.1:{port}/mcp", "--json"],
        capture_output=True, text=True, timeout=30)
    return json.loads(out.stdout)


def _detect_against(mock: Path) -> dict:
    port = _free_port()
    proc = subprocess.Popen([sys.executable, str(mock), str(port)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        _wait(port)
        return _run_detector(port)
    finally:
        proc.terminate()
        proc.wait(timeout=5)


def test_vulnerable_mock_is_flagged():
    f = _detect_against(VULN_MOCK)
    assert f["verdict"] == "vulnerable", f
    assert f["severity"] == "critical", f
    assert f["signals"]["sandbox_advertised"] is True, f
    assert f["signals"]["builtins_unrestricted"] is True, f


def test_patched_mock_is_not_flagged():
    f = _detect_against(PATCHED_MOCK)
    # The fix must NOT read as vulnerable: sandbox still advertised, but builtins are guarded.
    assert f["verdict"] == "not_vulnerable", f
    assert f["signals"]["sandbox_advertised"] is True, f
    assert f["signals"]["builtins_unrestricted"] is False, f


def test_no_side_effects_on_detection():
    # The detector's canary path must never be written by a detection run.
    canary = Path("/tmp/evil-grok-python-test")
    canary.unlink(missing_ok=True)
    _detect_against(VULN_MOCK)
    assert not canary.exists(), "detector caused a side effect (canary written)"


if __name__ == "__main__":
    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"PASS {name}")
            except AssertionError as exc:
                failures += 1
                print(f"FAIL {name}: {exc}")
    print(f"\n{'all passed' if not failures else str(failures) + ' failed'}")
    raise SystemExit(1 if failures else 0)
