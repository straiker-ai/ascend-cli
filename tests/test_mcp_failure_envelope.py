"""A CLI failure reaches the agent with its code, hint and diagnosis as fields.

The shim returned `error: <stderr text>` and the JSON envelope only as a `stdout` string; the
structured reason inside it had to be regexed out. Now the fields are on the result."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shells" / "mcp"))

import server  # noqa: E402


def _fake_run(stdout: str, stderr: str, code: int):
    def run(*a, **kw):
        return subprocess.CompletedProcess(a, code, stdout=stdout, stderr=stderr)
    return run


def test_envelope_fields_are_surfaced(monkeypatch):
    env = {"ok": False, "error": {"code": "capture_no_prompt", "message": "the capture never delivered the prompt",
                                  "hint": "try --manual", "exit_code": 2},
           "diagnosis": {"reason": "site_root_no_widget", "detail": "drive was at /", "next": "capture the page URL"}}
    monkeypatch.setattr(server.subprocess, "run", _fake_run("  step 1\n" + json.dumps(env), "error: the capture never delivered the prompt", 2))
    monkeypatch.setattr(server, "_cli_argv", lambda name, args: ["true"], raising=False)
    out = server.run_tool("ascend_target_add", {"source": "https://x"})
    assert out["ok"] is False and out["returncode"] == 2
    assert out["error"].startswith("the capture never delivered the prompt")
    assert out["error_code"] == "capture_no_prompt" and out["hint"] == "try --manual"
    assert out["diagnosis"]["reason"] == "site_root_no_widget" and out["diagnosis"]["next"] == "capture the page URL"


def test_a_plain_failure_keeps_the_old_shape(monkeypatch):
    monkeypatch.setattr(server.subprocess, "run", _fake_run("", "boom", 1))
    out = server.run_tool("ascend_target_add", {"source": "https://x"})
    assert out["ok"] is False and out["error"].startswith("boom") and "diagnosis" not in out


def test_last_json_skips_progress_lines():
    assert server._last_json("progress\n{\"ok\": false}\n")["ok"] is False
    assert server._last_json("nothing here") is None
