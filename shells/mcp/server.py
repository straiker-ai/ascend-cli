#!/usr/bin/env python3
"""
Ascend Bridge v2 — THIN MCP server (optional passthrough, shell-less hosts only).

Per docs/SURFACE.md the primary surfaces are the deterministic CLI
(`ascend <group> <verb> --json`) and the reasoning Skills that orchestrate it.
This MCP server is a **thin 1:1 shim**: every tool simply shells out to the same
CLI with `--json` and returns the parsed JSON. It contains NO business logic,
NO API calls, NO adapter code — it is an auto-generated-style passthrough so that
hosts *without* a shell (claude.ai web, Cowork, locked-down enterprise agent
runtimes) can still reach the exact same core.

If your agent host has a shell (Claude Code, Codex, Cursor, a plain terminal),
DO NOT use this server — call `python3 shells/cli/ascend.py <verb> --json`
directly. The MCP tool-definition overhead (schemas resident in context on every
turn) costs materially more tokens than a one-line CLI call, and it is a second
place that can drift from the CLI. This shim exists only to remove the "no shell"
blocker, never to be a parallel product surface.

Design notes
------------
* stdlib only. No `mcp` package dependency. A minimal but spec-shaped stdio
  JSON-RPC 2.0 loop implements `initialize`, `tools/list`, `tools/call`, `ping`
  and `shutdown` (MCP protocol revision 2024-11-05).
* The tool catalog is a plain data structure (`TOOLS`) so it is testable without
  a live client: `build_argv(name, args)` and `run_tool(name, args)` can be
  called directly from a unit test, and `list_tools()` returns the manifest.
* Auth flows through the CLI exactly as it does on the command line: set
  `$STRAIKER_PAT` (and, for a live probe, `$STRAIKER_BRIDGE_API_KEY`) in the
  process environment. Each tool also accepts optional `token` / `base` /
  `bridge_base` arguments that map to the CLI global flags, for hosts that inject
  per-call credentials instead of environment variables.

Run as a server:      python3 shells/mcp/server.py
Inspect the manifest: python3 shells/mcp/server.py --manifest
Invoke one tool:      python3 shells/mcp/server.py --call ascend_doctor '{}'
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

# --------------------------------------------------------------------------- paths
# shells/mcp/server.py -> repo root is two parents up.
REPO = Path(__file__).resolve().parents[2]
CLI = REPO / "shells" / "cli" / "ascend.py"
PY = sys.executable or "python3"

PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "ascend-bridge"
SERVER_VERSION = "0.1.0"

# Global CLI flags (top-level parser). These MUST precede the group/verb, so the
# shim always emits them first. `token`/`base`/`bridge_base` are optional per-call
# overrides; auth otherwise comes from $STRAIKER_PAT in the environment.
_GLOBALS = (("token", "--token"), ("base", "--base"), ("bridge_base", "--bridge-base"))


# --------------------------------------------------------------------------- manifest
# Each tool declares:
#   cli    : the [group, verb] tokens appended after the global flags
#   params : ordered mapping name -> spec. spec.kind is one of
#            "positional" | "flag" (store_true bool) | "option" (--flag value)
#   schema : the JSON Schema `properties` block (input schema)
# The manifest is intentionally a pure data structure so it can be asserted on in
# tests with no subprocess and no network.
TOOLS: list[dict[str, Any]] = [
    # The target tools lead the manifest on purpose: an agent reads tools/list top-down, so the
    # golden path has to be the first thing it sees — the same reason the CLI tiers its root help.
    # Before these existed the shim could run an assessment but could not CREATE a target, so an
    # agent could never get from "here is a URL" to a result without leaving MCP entirely.
    {
        "name": "ascend_target_add",
        "description": (
            "Onboard a target from a URL, a cURL/HAR file, or a saved config name, and register it "
            "with Ascend. `source` is auto-detected — do not pre-classify it. This is the one call "
            "that goes from nothing to a ready target; follow it with ascend_target_check."
        ),
        "cli": ["target", "add"],
        "params": {
            "source": {"kind": "positional", "required": True},
            "name": {"kind": "option", "flag": "--name"},
            "system_prompt": {"kind": "option", "flag": "--system-prompt"},
            "controls": {"kind": "option", "flag": "--controls"},
            "bearer": {"kind": "option", "flag": "--bearer"},
            "api_key": {"kind": "option", "flag": "--api-key"},
            "size": {"kind": "option", "flag": "--size"},
            "qpm": {"kind": "option", "flag": "--qpm"},
            "run": {"kind": "flag", "flag": "--run"},
        },
        "schema": {
            "source": {"type": "string", "description":
                       "a URL, a path to a cURL/HAR file, or an existing config name"},
            "name": {"type": "string", "description": "application name (default: derived from the URL)"},
            "system_prompt": {"type": "string", "description":
                              "the target's REAL system prompt, scored against to detect a leak. "
                              "Ask the user for it before onboarding; without it the app carries "
                              "only its name and ascend_assess_run will refuse to start"},
            "controls": {"type": "string", "description":
                         "comma-separated control ids (default: the full non-deprecated catalog)"},
            "bearer": {"type": "string", "description": "bearer token for the target"},
            "api_key": {"type": "string", "description": "NAME:VALUE[:in=header|query]"},
            "size": {"type": "string", "enum": ["small", "medium", "large"]},
            "qpm": {"type": "integer", "description": "queries per minute cap"},
            "run": {"type": "boolean", "description":
                    "also start an assessment immediately (default: register only)"},
        },
        "required": ["source"],
    },
    {
        "name": "ascend_target_check",
        "description": (
            "Re-prove a target against its LIVE endpoint: sends a real prompt through the adapter "
            "and reports auth, extraction and per-probe-window problems. Run this before every "
            "assessment — a stale adapter otherwise produces a clean-looking run that measured nothing."
        ),
        "cli": ["target", "check"],
        "params": {
            "target": {"kind": "positional", "required": True},
            "prompt": {"kind": "option", "flag": "--prompt"},
            "expect": {"kind": "option", "flag": "--expect"},
            "timeout": {"kind": "option", "flag": "--timeout"},
            "adapter": {"kind": "option", "flag": "--adapter"},
        },
        "schema": {
            "target": {"type": "string", "description": "target name, config name, or aapp_ id"},
            "prompt": {"type": "string", "description": "prompt to send (default: a benign hello)"},
            "expect": {"type": "string", "description": "require this substring in the reply"},
            "timeout": {"type": "number", "description": "per-request timeout in seconds"},
            "adapter": {"type": "string", "description": "override the adapter type"},
        },
        "required": ["target"],
    },
    {
        "name": "ascend_app_list",
        "description": "List Ascend applications in the tenant (id, api_type, name).",
        "cli": ["app", "list"],
        "params": {},
        "schema": {},
    },
    {
        "name": "ascend_app_create_bridge",
        "description": (
            "Create a bridge-type Ascend application and return its one-time tc- bridge key "
            "(thin_api_key). Store the key in $STRAIKER_BRIDGE_API_KEY — it is shown once."
        ),
        "cli": ["app", "create", "--type", "bridge"],
        "params": {
            "name": {"kind": "option", "flag": "--name", "required": True},
            "system_prompt": {"kind": "option", "flag": "--system-prompt"},
            "controls": {"kind": "option", "flag": "--controls"},
            "size": {"kind": "option", "flag": "--size"},
            "qpm": {"kind": "option", "flag": "--qpm"},
        },
        "schema": {
            "name": {"type": "string", "description": "application display name"},
            "system_prompt": {"type": "string", "description":
                              "the target's REAL system prompt — ask the user for it (defaults to "
                              "the name, which ascend_assess_run refuses to score against)"},
            "controls": {"type": "string", "description": "comma-separated control ids (validated first)"},
            "size": {"type": "string", "enum": ["small", "medium", "large"], "description": "assessment size"},
            "qpm": {"type": "integer", "description": "queries per minute cap"},
        },
        "required": ["name"],
    },
    {
        "name": "ascend_controls_list",
        "description": "List the control catalog, optionally filtered by category / agentic / deprecated.",
        "cli": ["controls", "list"],
        "params": {
            "category": {"kind": "option", "flag": "--category"},
            "include_deprecated": {"kind": "flag", "flag": "--include-deprecated"},
            "agentic_only": {"kind": "flag", "flag": "--agentic-only"},
        },
        "schema": {
            "category": {"type": "string", "description": "filter by category_id"},
            "include_deprecated": {"type": "boolean", "description": "include deprecated controls"},
            "agentic_only": {"type": "boolean", "description": "only agentic controls"},
        },
    },
    {
        "name": "ascend_controls_validate",
        "description": (
            "Validate a comma-separated control selection before a run. Returns "
            "valid / deprecated / unknown / agentic ids and warnings (e.g. zero-probe)."
        ),
        "cli": ["controls", "validate"],
        "params": {
            "controls": {"kind": "positional", "required": True},
        },
        "schema": {
            "controls": {"type": "string", "description": "comma-separated control ids"},
        },
        "required": ["controls"],
    },
    {
        "name": "ascend_assess_run",
        "description": (
            "Create -> pause -> resume -> poll an assessment for an app (id or name). "
            "Blocks until terminal unless no_wait is set. BEFORE calling this, ask the user for "
            "the target agent's system prompt and pass it as system_prompt: auto recon rarely "
            "recovers it, and leak controls scored against a placeholder report false passes. "
            "A run on an app with no real prompt fails with error code system_prompt_required."
        ),
        "cli": ["assess", "run"],
        "params": {
            "app": {"kind": "option", "flag": "--app", "required": True},
            "name": {"kind": "option", "flag": "--name", "required": True},
            "controls": {"kind": "option", "flag": "--controls"},
            "no_wait": {"kind": "flag", "flag": "--no-wait"},
            "interval": {"kind": "option", "flag": "--interval"},
            "timeout": {"kind": "option", "flag": "--timeout"},
            "force": {"kind": "flag", "flag": "--force"},
            "system_prompt": {"kind": "option", "flag": "--system-prompt"},
            "no_system_prompt": {"kind": "flag", "flag": "--no-system-prompt"},
        },
        "schema": {
            "app": {"type": "string", "description": "app id (aapp_...) or name"},
            "name": {"type": "string", "description": "assessment name"},
            "controls": {"type": "string", "description": "comma-separated control ids to validate first"},
            "no_wait": {"type": "boolean", "description": "return immediately after resume instead of polling"},
            "interval": {"type": "integer", "description": "poll interval seconds (default 20)"},
            "timeout": {"type": "integer", "description": "poll timeout seconds (default 7200)"},
            "force": {"type": "boolean", "description": "run even if the selection generates zero probes"},
            "system_prompt": {"type": "string", "description":
                              "the target's real system prompt, obtained from the user (inline or "
                              "@path); written to the app before the run"},
            "no_system_prompt": {"type": "boolean", "description":
                                 "run without it — only when the user confirms it cannot be obtained"},
        },
        "required": ["app", "name"],
    },
    {
        "name": "ascend_assess_status",
        "description": "Get an assessment's status/progress/score/severity.",
        "cli": ["assess", "status"],
        "params": {
            "app": {"kind": "option", "flag": "--app", "required": True},
            "assessment": {"kind": "option", "flag": "--assessment", "required": True},
        },
        "schema": {
            "app": {"type": "string", "description": "app id or name"},
            "assessment": {"type": "string", "description": "assessment id"},
        },
        "required": ["app", "assessment"],
    },
    {
        "name": "ascend_assess_results",
        "description": "Get an assessment's full results object (with a summarized view).",
        "cli": ["assess", "results"],
        "params": {
            "app": {"kind": "option", "flag": "--app", "required": True},
            "assessment": {"kind": "option", "flag": "--assessment", "required": True},
        },
        "schema": {
            "app": {"type": "string", "description": "app id or name"},
            "assessment": {"type": "string", "description": "assessment id"},
        },
        "required": ["app", "assessment"],
    },
    {
        "name": "ascend_adapter_list",
        "description": "List registered adapter types (transport/preset names).",
        "cli": ["adapter", "list"],
        "params": {},
        "schema": {},
    },
    {
        "name": "ascend_doctor",
        "description": "Preflight checks: PAT presence/exchange, control catalog reachability, bridge reachability, config dir.",
        "cli": ["doctor"],
        "params": {},
        "schema": {},
    },
]

TOOLS_BY_NAME = {t["name"]: t for t in TOOLS}


# --------------------------------------------------------------------------- manifest helpers
def _input_schema(tool: dict[str, Any]) -> dict[str, Any]:
    """Build a JSON Schema object for a tool (adds the global override props)."""
    props = dict(tool.get("schema") or {})
    # optional per-call global overrides (auth normally via env)
    props.setdefault("token", {"type": "string", "description": "Straiker PAT override (else $STRAIKER_PAT)"})
    props.setdefault("base", {"type": "string", "description": "v3 API base URL override"})
    props.setdefault("bridge_base", {"type": "string", "description": "bridge base URL override"})
    schema: dict[str, Any] = {"type": "object", "properties": props}
    if tool.get("required"):
        schema["required"] = list(tool["required"])
    return schema


def list_tools() -> list[dict[str, Any]]:
    """Return the MCP tools/list payload — testable without a client."""
    return [
        {"name": t["name"], "description": t["description"], "inputSchema": _input_schema(t)}
        for t in TOOLS
    ]


def build_argv(name: str, arguments: dict[str, Any] | None) -> list[str]:
    """
    Map an MCP tool call to a concrete CLI argv. Pure/deterministic — the primary
    unit-test seam. Global flags (--json plus any token/base/bridge_base override)
    are emitted BEFORE the group/verb, as argparse requires.
    """
    tool = TOOLS_BY_NAME.get(name)
    if tool is None:
        raise KeyError(f"unknown tool: {name}")
    args = dict(arguments or {})

    argv = [str(CLI), "--json"]
    for key, flag in _GLOBALS:
        val = args.pop(key, None)
        if val not in (None, ""):
            argv += [flag, str(val)]

    argv += list(tool["cli"])

    for pname, pspec in tool["params"].items():
        if pspec.get("required") and args.get(pname) in (None, ""):
            raise ValueError(f"{name}: missing required argument {pname!r}")
    for pname, pspec in tool["params"].items():
        if pname not in args or args[pname] is None:
            continue
        val = args[pname]
        kind = pspec["kind"]
        if kind == "positional":
            argv.append(str(val))
        elif kind == "flag":
            if val:
                argv.append(pspec["flag"])
        elif kind == "repeat":
            # A flag argparse collects with action="append" — `--app a --app b`. Several CLI
            # options are repeatable (a fleet of targets, several headers), and without this an
            # agent could only ever drive one at a time: a list arrived here as its repr and was
            # passed through as a single nonsense value.
            for item in (val if isinstance(val, (list, tuple)) else [val]):
                if item not in (None, ""):
                    argv += [pspec["flag"], str(item)]
        else:  # option
            argv += [pspec["flag"], str(val)]
    return argv


def run_tool(name: str, arguments: dict[str, Any] | None, timeout: int = 7800) -> dict[str, Any]:
    """
    Execute a tool by shelling out to the CLI with --json and parsing stdout.
    Returns {"ok": bool, ...}. Never raises for CLI failures — surfaces them as
    structured errors so the MCP layer can report isError cleanly.
    """
    try:
        argv = build_argv(name, arguments)
    except (KeyError, ValueError) as e:
        return {"ok": False, "error": str(e)}

    try:
        proc = subprocess.run(
            [PY, *argv],
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(REPO),
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"{name}: CLI timed out after {timeout}s"}
    except Exception as e:  # pragma: no cover - defensive
        return {"ok": False, "error": f"{name}: failed to exec CLI: {e}"}

    out = (proc.stdout or "").strip()
    err = (proc.stderr or "").strip()
    if proc.returncode != 0:
        return {"ok": False, "returncode": proc.returncode, "error": err or out or "CLI error", "stdout": out}

    if not out:
        return {"ok": True, "result": None, "stderr": err or None}
    try:
        return {"ok": True, "result": json.loads(out)}
    except json.JSONDecodeError:
        # a --json path should always emit JSON; fall back to raw text rather than crash
        return {"ok": True, "result": out, "stderr": err or None}


# --------------------------------------------------------------------------- JSON-RPC loop
def _rpc_result(req_id: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _rpc_error(req_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


def handle_request(req: dict[str, Any]) -> dict[str, Any] | None:
    """
    Handle one JSON-RPC request object and return the response object (or None for
    notifications, which carry no id and get no reply). Pure dispatch — unit-testable.
    """
    method = req.get("method")
    req_id = req.get("id")
    params = req.get("params") or {}
    is_notification = "id" not in req

    if method == "initialize":
        return _rpc_result(req_id, {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            "instructions": (
                "Thin passthrough to the ascend CLI. Prefer the CLI directly if your "
                "host has a shell; use these tools only when it does not."
            ),
        })

    if method in ("notifications/initialized", "initialized"):
        return None  # notification, no reply

    if method == "ping":
        return _rpc_result(req_id, {})

    if method == "tools/list":
        return _rpc_result(req_id, {"tools": list_tools()})

    if method == "tools/call":
        tool_name = params.get("name")
        arguments = params.get("arguments") or {}
        if tool_name not in TOOLS_BY_NAME:
            return _rpc_error(req_id, -32602, f"unknown tool: {tool_name}")
        outcome = run_tool(tool_name, arguments)
        text = json.dumps(outcome, indent=2, default=str)
        return _rpc_result(req_id, {
            "content": [{"type": "text", "text": text}],
            "isError": not outcome.get("ok", False),
        })

    if method in ("shutdown",):
        return _rpc_result(req_id, {})

    if is_notification:
        return None
    return _rpc_error(req_id, -32601, f"method not found: {method}")


def serve(stdin=None, stdout=None) -> None:
    """Run the stdio JSON-RPC loop (newline-delimited JSON objects, one per line)."""
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            resp = _rpc_error(None, -32700, "parse error")
            stdout.write(json.dumps(resp) + "\n")
            stdout.flush()
            continue
        resp = handle_request(req)
        if resp is not None:
            stdout.write(json.dumps(resp, default=str) + "\n")
            stdout.flush()
        if req.get("method") == "shutdown":
            break


# --------------------------------------------------------------------------- entrypoint
def _main(argv: list[str]) -> int:
    if argv and argv[0] == "--manifest":
        print(json.dumps({"tools": list_tools()}, indent=2))
        return 0
    if argv and argv[0] == "--call":
        if len(argv) < 2:
            print("usage: server.py --call <tool_name> [json-args]", file=sys.stderr)
            return 2
        name = argv[1]
        arguments = json.loads(argv[2]) if len(argv) > 2 else {}
        print(json.dumps(run_tool(name, arguments), indent=2, default=str))
        return 0
    serve()
    return 0


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
