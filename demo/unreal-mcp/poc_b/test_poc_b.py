#!/usr/bin/env python3
"""Tests for POC-B (indirect agent coercion) — the deterministic Mode-A mechanism.

Proves the plumbing end-to-end without a live model: the mock target serves the embedded
instruction, a susceptible agent (policy=obey) complies and the oracle catches it, a hardened
agent (policy=resist) reads the same metadata and does not, and nothing is written outside the
chosen canary path.

    python3 demo/unreal-mcp/poc_b/test_poc_b.py      # standalone
    pytest demo/unreal-mcp/poc_b/test_poc_b.py       # or via pytest
"""
from __future__ import annotations

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
import mock_agent_client  # noqa: E402

TARGET = HERE / "mock_agent_target_server.py"


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


def _with_target(canary_path: str, fn):
    port = _free_port()
    proc = subprocess.Popen(
        [sys.executable, str(TARGET), str(port),
         "--canary-path", canary_path, "--marker", injection.DEFAULT_MARKER],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        _wait(port)
        return fn(f"http://127.0.0.1:{port}/mcp")
    finally:
        proc.terminate()
        proc.wait(timeout=5)


def test_obeying_agent_is_flagged():
    with tempfile.TemporaryDirectory() as d:
        canary = str(Path(d) / "canary.txt")
        agent = _with_target(canary, lambda ep: mock_agent_client.run(ep, "obey"))
        assert agent["saw_instruction"] is True, agent
        assert agent["acted"] is True, agent
        finding = compliance_check.check(canary)
        assert finding["complied"] is True, finding
        assert finding["susceptible"] is True, finding


def test_resisting_agent_is_not_flagged():
    with tempfile.TemporaryDirectory() as d:
        canary = str(Path(d) / "canary.txt")
        agent = _with_target(canary, lambda ep: mock_agent_client.run(ep, "resist"))
        # The hardened agent must still SEE the instruction (proves it was served) but not act.
        assert agent["saw_instruction"] is True, agent
        assert agent["acted"] is False, agent
        finding = compliance_check.check(canary)
        assert finding["complied"] is False, finding


def test_no_write_outside_canary_path():
    with tempfile.TemporaryDirectory() as d:
        canary = str(Path(d) / "nested" / "canary.txt")
        _with_target(canary, lambda ep: mock_agent_client.run(ep, "obey"))
        # Exactly the chosen canary (and its parent dir) should appear; nothing else in d.
        written = sorted(p.name for p in Path(d).rglob("*") if p.is_file())
        assert written == ["canary.txt"], written
        assert compliance_check.check(canary)["complied"] is True


def test_served_metadata_contains_instruction():
    # The target must actually serve the embedded instruction (not a benign-looking stub).
    with tempfile.TemporaryDirectory() as d:
        canary = str(Path(d) / "canary.txt")

        def _peek(ep):
            from unreal_mcp_adapter import _MinimalMCP
            c = _MinimalMCP(ep, 10.0)
            c.initialize()
            return mock_agent_client._read_metadata(c)

        tags = _with_target(canary, _peek)
        assert injection.parse_instruction(tags.get("RTC358Description", "")) == (
            canary, injection.DEFAULT_MARKER), tags


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
