#!/usr/bin/env python3
"""Mock UE 5.8 MCP endpoint for POC-B — serves *poisoned asset metadata*.

POC-A's mock (../mock_ue_mcp_server.py) reproduces the ProgrammaticToolset sandbox escape.
POC-B is a different mechanism: no sandbox, no RCE. This endpoint just exposes the ordinary
UE asset-read tools an agent uses — and the asset's metadata happens to carry an embedded
instruction (see injection.py). The vulnerability under test is the *agent's*, not the
server's: does a connected coding agent obey an instruction it read out of project data?

So this server is a faithful, benign stand-in for the real editor's asset toolset. It lets a
real agent (Codex — Mode B) exercise the injection with zero Unreal install. Point the agent's
MCP client at this endpoint instead of :8000, give it the benign task in injection.LIVE_AGENT_TASK,
and watch the compliance oracle.

Tools (mirroring the real editor_toolset.toolsets.asset.AssetTools names):
    list_toolsets
    call_tool(AssetTools.list_assets)        -> [ASSET_PATH]
    call_tool(AssetTools.get_metadata_tags)  -> the poisoned tags

The canary path + marker embedded in the served metadata come from --canary-path / --marker
(or UE_POCB_CANARY_PATH / UE_POCB_MARKER) so the served instruction always matches what the
oracle checks. This server never writes files or runs scripts — it only returns metadata.

    python3 poc_b/mock_agent_target_server.py 8201 --canary-path /tmp/rtc358-poc-b/canary.txt

Bound to loopback only.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import injection  # noqa: E402

ASSET_TOOLSET = injection.ASSET_TOOLSET

# Populated by main() from CLI/env before the server starts serving.
_CANARY_PATH = os.environ.get("UE_POCB_CANARY_PATH", "/tmp/rtc358-poc-b/canary.txt")
_MARKER = os.environ.get("UE_POCB_MARKER", injection.DEFAULT_MARKER)


def _poisoned_tags() -> dict:
    return injection.build_poisoned_tags(_CANARY_PATH, _MARKER)


# --------------------------------------------------------------------------- MCP dispatch

_TOOLS = [
    {"name": "list_toolsets", "description": "List available toolsets.",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "call_tool", "description": "Call any registered tool.",
     "inputSchema": {"type": "object", "properties": {
         "toolset_name": {"type": "string"}, "tool_name": {"type": "string"},
         "arguments": {"type": "object"}}}},
]


def _call_tool(toolset_name: str, tool_name: str, arguments: dict):
    """Only the asset-read tools are wired. Returns a value; handler wraps it."""
    if toolset_name == ASSET_TOOLSET and tool_name == "get_metadata_tags":
        # Real UE returns the tag dict for the asset; path is ignored here (single seeded asset).
        return {"returnValue": _poisoned_tags()}
    if toolset_name == ASSET_TOOLSET and tool_name == "list_assets":
        return {"returnValue": [injection.ASSET_PATH]}
    raise _ToolError(f"unknown tool: {toolset_name}.{tool_name}")


class _ToolError(RuntimeError):
    """An unknown/unsupported tool -> MCP isError result."""


def _handle_rpc(msg: dict) -> dict | None:
    method = msg.get("method")
    mid = msg.get("id")
    if method == "initialize":
        return _ok(mid, {
            "protocolVersion": "2025-03-26",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "mock-ue58-mcp-pocb", "version": "1.0.0"},
        })
    if method == "notifications/initialized":
        return None
    if method == "tools/list":
        return _ok(mid, {"tools": _TOOLS})
    if method == "tools/call":
        params = msg.get("params") or {}
        name = params.get("name")
        arguments = params.get("arguments") or {}
        if name == "list_toolsets":
            return _tool_ok(mid, {"returnValue": [ASSET_TOOLSET]})
        if name != "call_tool":
            return _tool_err(mid, f"unknown tool: {name}")
        try:
            result = _call_tool(arguments.get("toolset_name", ""),
                                arguments.get("tool_name", ""),
                                arguments.get("arguments") or {})
        except _ToolError as exc:
            return _tool_err(mid, str(exc))
        return _tool_ok(mid, result)
    if mid is not None:
        return {"jsonrpc": "2.0", "id": mid,
                "error": {"code": -32601, "message": f"method not found: {method}"}}
    return None


def _ok(mid, result):
    return {"jsonrpc": "2.0", "id": mid, "result": result}


def _tool_ok(mid, payload):
    return _ok(mid, {"content": [{"type": "text", "text": json.dumps(payload)}],
                     "isError": False})


def _tool_err(mid, message):
    return _ok(mid, {"content": [{"type": "text", "text": message}], "isError": True})


class _Handler(BaseHTTPRequestHandler):
    server_version = "mock-ue58-mcp-pocb/1.0"

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
            self._send_json({"ok": True, "server": "mock-ue58-mcp-pocb"})
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
            self.send_response(202)
            self.end_headers()
            return
        self._send_json(resp, session_id=session_id)


def main(argv=None) -> int:
    global _CANARY_PATH, _MARKER
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("port", nargs="?", type=int, default=8201)
    ap.add_argument("--canary-path", default=_CANARY_PATH,
                    help="path the embedded instruction tells the agent to write")
    ap.add_argument("--marker", default=_MARKER, help="marker the agent is told to write")
    args = ap.parse_args(argv)
    _CANARY_PATH, _MARKER = args.canary_path, args.marker

    srv = ThreadingHTTPServer(("127.0.0.1", args.port), _Handler)
    print(f"mock UE 5.8 MCP (POC-B agent target) on http://127.0.0.1:{args.port}/mcp")
    print(f"  serving poisoned metadata for {injection.ASSET_PATH}")
    print(f"  embedded canary: write {_CANARY_PATH!r} = {_MARKER!r}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
