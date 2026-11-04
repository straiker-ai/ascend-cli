"""unreal_mcp_adapter.py — a bespoke Ascend custom adapter for a UE 5.8 native MCP target.

The paradigm (see runtime/adapters/custom_module.py) is  Ascend -> bridge -> adapter -> target.
This adapter's target is the Unreal Engine 5.8 *native MCP endpoint* (streamable HTTP, default
http://127.0.0.1:8000/mcp). One probe = one script body submitted to the ProgrammaticToolset's
`execute_tool_script` tool; the reply is the tool's evidence, returned as text for the scorer.

    def send_prompt(prompt: str) -> str

`prompt` is the Python script body to run inside the toolset (it must define `run()`), e.g. the
sandbox-escape payloads in ./probes. We submit it to:

    call_tool(
        toolset_name = "editor_toolset.toolsets.programmatic.ProgrammaticToolset",
        tool_name    = "execute_tool_script",
        arguments    = {"script": <prompt>},
    )

and return the inner `returnValue` as a string — the attacker-observable evidence (canary
read-back, process stdout, HTTP status). Per the custom-adapter contract, we return the WORDS the
target produced, not the JSON-RPC envelope, so the scorer reads evidence and not transport noise.

Transport: the real `mcp` SDK if it is importable (the proven path against live UE, mirroring
ue58-mcp-helpers/scripts/ue58_mcp_call.py), otherwise a minimal stdlib streamable-HTTP client so
the demo runs offline against the mock with zero pip installs. Both are live-capable.

Config / env:
    UE_MCP_ENDPOINT   MCP endpoint URL        (default http://127.0.0.1:8000/mcp)
    UE_MCP_TOOLSET    toolset name            (default the ProgrammaticToolset above)
    UE_MCP_TOOL       tool name               (default execute_tool_script)
    UE_MCP_TIMEOUT_S  per-call timeout seconds(default 60)
"""
from __future__ import annotations

import json
import os
import urllib.request

ENDPOINT = os.environ.get("UE_MCP_ENDPOINT", "http://127.0.0.1:8000/mcp")
TOOLSET = os.environ.get(
    "UE_MCP_TOOLSET", "editor_toolset.toolsets.programmatic.ProgrammaticToolset")
TOOL = os.environ.get("UE_MCP_TOOL", "execute_tool_script")
TIMEOUT_S = float(os.environ.get("UE_MCP_TIMEOUT_S", "60"))

META = {
    "target": ENDPOINT,
    "kind": "custom",
    "generated_from": "unreal-mcp-poc",
    "note": "UE 5.8 ProgrammaticToolset execute_tool_script (sandbox-escape demo)",
}


# --------------------------------------------------------------------------- result shaping

def _unwrap_tool_result(result: dict) -> str:
    """Turn a tools/call result into the evidence string the scorer should read.

    The tool returns content[].text; for execute_tool_script that text is a JSON object
    {"returnValue": "<json string>"}. We surface returnValue (the script's own output), so a
    PASS probe yields its evidence dict and a blocked probe yields the sandbox error message.
    An isError result returns its message verbatim — that is the signal for a negative control.
    """
    content = result.get("content") or []
    text = ""
    for part in content:
        if isinstance(part, dict) and part.get("type") == "text":
            text = part.get("text", "")
            break
    if result.get("isError"):
        return text  # e.g. "Import of 'os' is not permitted. ..." — a real, scorable signal
    try:
        obj = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return text
    if isinstance(obj, dict) and "returnValue" in obj:
        rv = obj["returnValue"]
        return rv if isinstance(rv, str) else json.dumps(rv)
    return text


# --------------------------------------------------------------------- transport: mcp SDK

def _call_via_sdk(script: str) -> str:
    import asyncio

    from mcp import ClientSession
    try:
        from mcp.client.streamable_http import streamable_http_client as http_client
    except ImportError:  # older/newer SDK name drift (see ue58_mcp_call.py)
        from mcp.client.streamable_http import streamablehttp_client as http_client

    async def _run() -> str:
        async with http_client(ENDPOINT, terminate_on_close=False) as streams:
            read, write = streams[0], streams[1]
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool(
                    "call_tool",
                    {"toolset_name": TOOLSET, "tool_name": TOOL,
                     "arguments": {"script": script}},
                )
                dumped = result.model_dump(by_alias=True, mode="json", exclude_none=True) \
                    if hasattr(result, "model_dump") else result
                return _unwrap_tool_result(dumped)

    return asyncio.run(_run())


# ----------------------------------------------------------- transport: stdlib (no SDK)

class _MinimalMCP:
    """A tiny MCP streamable-HTTP client over urllib — enough for initialize + tools/call.

    Speaks JSON-RPC 2.0 over POST, accepts either an application/json response (the mock) or a
    text/event-stream SSE response (real UE), and threads the Mcp-Session-Id header the server
    hands back at initialize. No third-party packages.
    """

    def __init__(self, endpoint: str, timeout_s: float):
        self.endpoint = endpoint
        self.timeout_s = timeout_s
        self.session_id = None
        self._id = 0

    def _post(self, payload: dict, expect_response: bool = True) -> dict | None:
        self._id += 1
        if "method" in payload and payload.get("_notify"):
            payload.pop("_notify")
        else:
            payload.setdefault("id", self._id)
        payload.setdefault("jsonrpc", "2.0")
        data = json.dumps(payload).encode()
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        req = urllib.request.Request(self.endpoint, data=data, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
            sid = resp.headers.get("Mcp-Session-Id")
            if sid:
                self.session_id = sid
            if not expect_response or resp.status == 202:
                resp.read()
                return None
            ctype = (resp.headers.get("Content-Type") or "").lower()
            raw = resp.read().decode("utf-8", "replace")
        if "text/event-stream" in ctype:
            return self._parse_sse(raw)
        return json.loads(raw) if raw.strip() else None

    @staticmethod
    def _parse_sse(raw: str) -> dict | None:
        """Return the last JSON-RPC object carried in SSE `data:` frames."""
        last = None
        for line in raw.splitlines():
            if line.startswith("data:"):
                chunk = line[len("data:"):].strip()
                if not chunk:
                    continue
                try:
                    last = json.loads(chunk)
                except json.JSONDecodeError:
                    continue
        return last

    def initialize(self):
        resp = self._post({
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "ascend-ue-demo", "version": "1.0.0"},
            },
        })
        # notifications/initialized — a notification carries no id and expects no response body
        self._post({"method": "notifications/initialized", "_notify": True},
                   expect_response=False)
        return resp

    def call_tool(self, name: str, arguments: dict) -> dict:
        resp = self._post({"method": "tools/call",
                           "params": {"name": name, "arguments": arguments}})
        if not resp or "result" not in resp:
            err = (resp or {}).get("error", {})
            raise RuntimeError(f"MCP call failed: {err or resp}")
        return resp["result"]


def _call_via_stdlib(script: str) -> str:
    client = _MinimalMCP(ENDPOINT, TIMEOUT_S)
    client.initialize()
    result = client.call_tool(
        "call_tool",
        {"toolset_name": TOOLSET, "tool_name": TOOL, "arguments": {"script": script}},
    )
    return _unwrap_tool_result(result)


# ------------------------------------------------------------------------------- preflight

def _classify(server_name: str, toolsets) -> dict:
    """Shape a preflight result from the server's own self-report."""
    name = server_name or ""
    has_prog = bool(toolsets) and any(TOOLSET in str(t) for t in toolsets)
    return {
        "reachable": True,
        "server_name": name or "(unnamed)",
        "is_mock": "mock" in name.lower(),
        "toolsets": toolsets,
        "has_programmatic": has_prog,
        "error": None,
    }


def _list_toolsets_payload(result: dict):
    """Pull the toolset list out of a list_toolsets tool result, or None."""
    text = _unwrap_tool_result(result)
    try:
        obj = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return None
    return obj if isinstance(obj, list) else obj.get("returnValue") if isinstance(obj, dict) else None


def _preflight_via_stdlib() -> dict:
    client = _MinimalMCP(ENDPOINT, min(TIMEOUT_S, 10.0))
    init = client.initialize() or {}
    info = ((init.get("result") or {}).get("serverInfo")) or {}
    toolsets = None
    try:
        toolsets = _list_toolsets_payload(client.call_tool("list_toolsets", {}))
    except Exception:  # list_toolsets is best-effort; initialize already proved reachability
        pass
    return _classify(info.get("name", ""), toolsets)


def _preflight_via_sdk() -> dict:
    import asyncio

    from mcp import ClientSession
    try:
        from mcp.client.streamable_http import streamable_http_client as http_client
    except ImportError:
        from mcp.client.streamable_http import streamablehttp_client as http_client

    async def _run() -> dict:
        async with http_client(ENDPOINT, terminate_on_close=False) as streams:
            read, write = streams[0], streams[1]
            async with ClientSession(read, write) as session:
                init = await session.initialize()
                name = getattr(getattr(init, "serverInfo", None), "name", "") or ""
                toolsets = None
                try:
                    res = await session.call_tool("list_toolsets", {})
                    dumped = res.model_dump(by_alias=True, mode="json", exclude_none=True) \
                        if hasattr(res, "model_dump") else res
                    toolsets = _list_toolsets_payload(dumped)
                except Exception:
                    pass
                return _classify(name, toolsets)

    return asyncio.run(_run())


def preflight() -> dict:
    """Probe the endpoint before running the pack: is it reachable, and mock or live?

    Returns a dict: reachable, server_name, is_mock, toolsets, has_programmatic, error.
    On an unreachable endpoint, reachable is False and error carries the reason — the runner
    turns that into one clear message instead of six identical probe failures.
    """
    try:
        try:
            import mcp  # noqa: F401
        except ImportError:
            return _preflight_via_stdlib()
        return _preflight_via_sdk()
    except Exception as exc:  # connection refused, timeout, bad endpoint
        return {"reachable": False, "server_name": None, "is_mock": None,
                "toolsets": None, "has_programmatic": False, "error": str(exc)}


# ------------------------------------------------------------------------------- contract

def send_prompt(prompt: str) -> str:
    """Submit one script body to the UE MCP toolset and return the evidence string."""
    try:
        import mcp  # noqa: F401  — prefer the real SDK when present (live UE path)
        return _call_via_sdk(prompt)
    except ImportError:
        return _call_via_stdlib(prompt)


if __name__ == "__main__":
    # Manual poke:  python3 unreal_mcp_adapter.py < some_payload.py
    import sys
    body = sys.stdin.read()
    print(send_prompt(body))
