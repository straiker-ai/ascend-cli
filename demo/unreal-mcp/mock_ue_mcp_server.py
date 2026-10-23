#!/usr/bin/env python3
"""Mock of the Unreal Engine 5.8 native MCP endpoint — the sandbox, reproduced.

This exists so the UE 5.8 ProgrammaticToolset sandbox-escape demo is DETERMINISTIC and
runs with no Unreal install, matching this repo's convention that a demo drives a local
target (see tests/live/echo_target.py) rather than a live third party.

It is a *faithful* mock, not a stub that rubber-stamps the payloads: it reproduces the
real sandbox's behaviour so the SAME escape payloads that beat live UE 5.8 beat this too.

    * `import os`           -> "Import of 'os' is not permitted. Allowed modules: ..."
    * `open(path, "w")`     -> "Mode 'w' is not permitted. Allowed modes: ['r', 'rb', 'rt']"
    * BUT the real `json` module handed to the script still carries the REAL builtins on
      `json.__dict__["__builtins__"]`, so `json.__builtins__["open"]` / `["__import__"]`
      are unrestricted. That single fact is the vulnerability, and it is what the demo
      proves — a hard-coded "PASS" would prove nothing.

Wire protocol: MCP streamable-HTTP (JSON-RPC 2.0 over POST /mcp). Responses are plain
`application/json` — the paired client in unreal_mcp_adapter.py speaks both that and SSE,
and the real `mcp` SDK is only needed for the live endpoint.

Tools exposed (mirrors the real endpoint's meta-tools):
    list_toolsets, describe_toolset, call_tool(toolset_name, tool_name, arguments)
`call_tool` dispatches the one tool the escape needs:
    editor_toolset.toolsets.programmatic.ProgrammaticToolset.execute_tool_script(script=...)

Run:
    python3 demo/unreal-mcp/mock_ue_mcp_server.py 8000
    # endpoint: http://127.0.0.1:8000/mcp

SAFETY: executing a submitted script is the whole point of the escape, so this server
really runs the payload (that is what UE does). Keep it bound to loopback, feed it only
the benign canary payloads in ./probes, and never expose it on a routable interface.
"""
from __future__ import annotations

import builtins as _builtins
import io
import json
import sys
import traceback
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# The exact allowlist the real UE 5.8 ProgrammaticToolset advertises via
# get_execution_environment (recorded in the POC evidence). Reproduced verbatim so the
# negative controls (T0a/T0b) see the real error strings.
ALLOWED_MODULES = frozenset({"re", "copy", "datetime", "math", "json", "time"})
ALLOWED_OPEN_MODES = ("r", "rb", "rt")

PROGRAMMATIC_TOOLSET = "editor_toolset.toolsets.programmatic.ProgrammaticToolset"

_real_open = _builtins.open
_real_import = _builtins.__import__


def _guarded_import(name, globals=None, locals=None, fromlist=(), level=0):
    """The advertised import guard: only the allowlist, by top-level package name."""
    root = name.split(".")[0]
    if root in ALLOWED_MODULES:
        return _real_import(name, globals, locals, fromlist, level)
    raise RuntimeError(
        f"Import of '{name}' is not permitted. Allowed modules: {ALLOWED_MODULES!r}"
    )


def _guarded_open(file, mode="r", *args, **kwargs):
    """The advertised open guard: read modes only."""
    if mode not in ALLOWED_OPEN_MODES:
        raise ValueError(
            f"Mode '{mode}' is not permitted. Allowed modes: {list(ALLOWED_OPEN_MODES)}"
        )
    return _real_open(file, mode, *args, **kwargs)


def _sandbox_namespace() -> dict:
    """The execution namespace handed to a submitted script.

    `__builtins__` is a copy of the real builtins with `open` and `__import__` swapped for
    the guards — the naive paths are blocked. The allowlisted modules are pre-bound as the
    real module objects, exactly as the real toolset does. That is the subtlety the escape
    turns: a genuinely-imported `json` module keeps the REAL builtins on its own
    `__dict__["__builtins__"]`, so recovering `open`/`__import__` from there is unguarded.
    """
    guarded = dict(vars(_builtins))
    guarded["open"] = _guarded_open
    guarded["__import__"] = _guarded_import

    import copy as _copy
    import datetime as _datetime
    import math as _math
    import re as _re
    import time as _time

    ns = {
        "__builtins__": guarded,
        "json": json,          # real module -> real builtins reachable via json.__builtins__
        "math": _math,
        "datetime": _datetime,
        "copy": _copy,
        "re": _re,
        "time": _time,
    }
    return ns


def execute_tool_script(script: str) -> dict:
    """Run a submitted script that must define run() -> dict. Mirrors the real tool.

    Returns {"returnValue": "<json string>"} on success (the real tool double-encodes the
    dict run() returns), or raises so the handler reports isError with the message/traceback.
    """
    ns = _sandbox_namespace()
    try:
        compiled = compile(script, "<script>", "exec")
        exec(compiled, ns)  # noqa: S102 - reproducing the vulnerable interpreter on purpose
    except Exception as exc:  # import/compile guard rejections land here
        raise _ScriptError(str(exc)) from exc
    run = ns.get("run")
    if not callable(run):
        raise _ScriptError("script must define a run() function")
    try:
        result = run()
    except Exception as exc:
        tb = traceback.format_exc(limit=3)
        raise _ScriptError(f"{type(exc).__name__}: {exc}\n{tb}") from exc
    return {"returnValue": json.dumps(result)}


class _ScriptError(RuntimeError):
    """A sandbox rejection or an in-script exception -> MCP isError result."""


# --------------------------------------------------------------------------- MCP dispatch

def _call_tool(toolset_name: str, tool_name: str, arguments: dict) -> dict:
    """The meta-tool. Only the programmatic toolset's execute_tool_script is wired."""
    if toolset_name == PROGRAMMATIC_TOOLSET and tool_name == "execute_tool_script":
        script = arguments.get("script") or arguments.get("code") or arguments.get("source")
        if not isinstance(script, str):
            raise _ScriptError("execute_tool_script requires a 'script' string argument")
        return execute_tool_script(script)
    raise _ScriptError(f"unknown tool: {toolset_name}.{tool_name}")


_TOOLS = [
    {"name": "list_toolsets", "description": "List available toolsets.",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "describe_toolset", "description": "Describe one toolset.",
     "inputSchema": {"type": "object", "properties": {"toolset_name": {"type": "string"}}}},
    {"name": "call_tool", "description": "Call any registered tool.",
     "inputSchema": {"type": "object", "properties": {
         "toolset_name": {"type": "string"}, "tool_name": {"type": "string"},
         "arguments": {"type": "object"}}}},
]


def _handle_rpc(msg: dict) -> dict | None:
    """Handle one JSON-RPC message; return a response dict, or None for a notification."""
    method = msg.get("method")
    mid = msg.get("id")
    if method == "initialize":
        return _ok(mid, {
            "protocolVersion": "2025-03-26",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "mock-ue58-mcp", "version": "1.0.0"},
        })
    if method == "notifications/initialized":
        return None
    if method == "tools/list":
        return _ok(mid, {"tools": _TOOLS})
    if method == "tools/call":
        params = msg.get("params") or {}
        name = params.get("name")
        arguments = params.get("arguments") or {}
        if name != "call_tool":
            # allow calling the meta tools directly too
            if name == "list_toolsets":
                return _tool_ok(mid, {"returnValue": [PROGRAMMATIC_TOOLSET]})
            return _tool_err(mid, f"unknown tool: {name}")
        try:
            result = _call_tool(arguments.get("toolset_name", ""),
                                arguments.get("tool_name", ""),
                                arguments.get("arguments") or {})
        except _ScriptError as exc:
            return _tool_err(mid, str(exc))
        return _tool_ok(mid, result)
    if mid is not None:
        return {"jsonrpc": "2.0", "id": mid,
                "error": {"code": -32601, "message": f"method not found: {method}"}}
    return None


def _ok(mid, result):
    return {"jsonrpc": "2.0", "id": mid, "result": result}


def _tool_ok(mid, payload):
    """A tools/call result: content[] of text, isError False (matches the evidence shape)."""
    return _ok(mid, {"content": [{"type": "text", "text": json.dumps(payload)}],
                     "isError": False})


def _tool_err(mid, message):
    return _ok(mid, {"content": [{"type": "text", "text": message}], "isError": True})


class _Handler(BaseHTTPRequestHandler):
    server_version = "mock-ue58-mcp/1.0"

    def log_message(self, *a):  # quiet
        pass

    def _send_json(self, obj, status=200, session_id=None):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if session_id:
            self.send_header("Mcp-Session-Id", session_id)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.rstrip("/").endswith("mcp"):
            self._send_json({"ok": True, "server": "mock-ue58-mcp"})
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if not self.path.rstrip("/").endswith("mcp"):
            self.send_response(404)
            self.end_headers()
            return
        n = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(n) if n else b"{}"
        try:
            msg = json.loads(raw or b"{}")
        except json.JSONDecodeError:
            self._send_json({"jsonrpc": "2.0", "id": None,
                             "error": {"code": -32700, "message": "parse error"}}, 400)
            return
        session_id = None
        if msg.get("method") == "initialize":
            session_id = self.headers.get("Mcp-Session-Id") or uuid.uuid4().hex
        resp = _handle_rpc(msg)
        if resp is None:
            # a notification -> 202 Accepted, empty body (streamable-HTTP convention)
            self.send_response(202)
            self.end_headers()
            return
        self._send_json(resp, session_id=session_id)


def main(argv=None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    port = int(argv[0]) if argv else 8000
    host = "127.0.0.1"
    srv = ThreadingHTTPServer((host, port), _Handler)
    print(f"mock UE 5.8 MCP on http://{host}:{port}/mcp  "
          f"(tool: {PROGRAMMATIC_TOOLSET}.execute_tool_script)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
