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
            "that goes from nothing to a ready target; follow it with ascend_target_check. "
            "IT CAN AUTHENTICATE: bearer, api_key, basic (user:pass), cookie, a raw header, or a "
            "full LOGIN via login_url/login_body when the target wants credentials exchanged for "
            "a token. Prefer login_url over a static token whenever a login exists — it survives "
            "the token expiring mid-run, which a pasted bearer does not. "
            "IF THIS RETURNS `auth_required`: do NOT go and read documentation, and do not ask "
            "the operator for anything yet. The error text names the exact remedy and you "
            "already hold every parameter it names — CALL THIS TOOL AGAIN with them. For an "
            "OAuth2 client_credentials target that is login_url=<token endpoint>, "
            "login_body='grant_type=client_credentials&client_id=<id>&client_secret=<secret>', "
            "token_path='access_token'. Use an env reference (client_secret=env:NAME) when the "
            "secret is in the credential store rather than in the conversation. A second "
            "attempt carrying the credential is nearly always right; a detour into the docs is "
            "nearly always wrong."
        ),
        "cli": ["target", "add"],
        "params": {
            "source": {"kind": "positional", "required": True},
            "name": {"kind": "option", "flag": "--name"},
            "system_prompt": {"kind": "option", "flag": "--system-prompt"},
            "controls": {"kind": "option", "flag": "--controls"},
            "bearer": {"kind": "option", "flag": "--bearer"},
            "api_key": {"kind": "option", "flag": "--api-key"},
            # EVERY way a real target authenticates, not just two. `target add` has accepted all
            # of these for a long time; the tool surface exposed `bearer` and `api_key` alone, so
            # an agent driving this could not wire a target behind HTTP Basic, a session cookie,
            # a custom header, or — the most common enterprise flow of all — an OAuth2 login.
            # MEASURED: asked to red-team an OAuth2 client_credentials target with the client id,
            # the secret and the token URL all given in the request, the agent could only try a
            # bare probe, got a 401, and gave up. Not because it lacked the credential or the
            # knowledge, but because the parameter did not exist.
            # The exact request, as a curl command, inline. This is what the probe's own
            # `bad_shape` hint asks for, and the model reached for it twice unprompted.
            "curl": {"kind": "option", "flag": "--curl"},
            "basic": {"kind": "option", "flag": "--basic"},
            "cookie": {"kind": "option", "flag": "--cookie"},
            "header": {"kind": "option", "flag": "--header", "repeat": True},
            "token_file": {"kind": "option", "flag": "--token-file"},
            "login_url": {"kind": "option", "flag": "--login-url"},
            "login_body": {"kind": "option", "flag": "--login-body"},
            "login_method": {"kind": "option", "flag": "--login-method"},
            "token_path": {"kind": "option", "flag": "--token-path"},
            "size": {"kind": "option", "flag": "--size"},
            "qpm": {"kind": "option", "flag": "--qpm"},
            "run": {"kind": "flag", "flag": "--run"},
        },
        "schema": {
            "source": {"type": "string", "description":
                       "a URL, a path to a cURL/HAR file, or an existing config name"},
            "name": {"type": "string", "description": "application name (default: derived from the URL)"},
            "system_prompt": {"type": "string", "description":
                              "what the target is — steers which probes are relevant"},
            "controls": {"type": "string", "description":
                         "comma-separated control ids (default: the full non-deprecated catalog)"},
            "bearer": {"type": "string", "description": "bearer token for the target"},
            "api_key": {"type": "string", "description": "NAME:VALUE[:in=header|query]"},
            "curl": {"type": "string", "description":
                     "ONE WORKING REQUEST, as a curl command, pasted inline — e.g. "
                     "\"curl -X POST https://host/api/chat -H 'Content-Type: application/json' "
                     "-d '{\\\"message\\\":\\\"hi\\\"}'\". Use this when probing comes back "
                     "`bad_shape`: it stops the guessing, because the request no longer has to "
                     "be derived. A file path or '-' for stdin also work."},
            "basic": {"type": "string", "description":
                      "HTTP Basic as USER:PASS. 'user:env:MY_PW' keeps the password out of argv."},
            "cookie": {"type": "string", "description": "Cookie header for a session-gated target"},
            "header": {"type": "string", "description":
                       "one raw header, 'Name: value' — for a credential under a custom name"},
            "token_file": {"type": "string", "description": "read a bearer token from this file"},
            "login_url": {"type": "string", "description":
                          "LOG IN FIRST, then use the token. POST here to exchange credentials. "
                          "This is the right answer for OAuth2 and for any portal login: it "
                          "records a repeatable recipe, so the relay RE-AUTHENTICATES during a "
                          "long run instead of 401-ing once the first token expires."},
            "login_body": {"type": "string", "description":
                           "body for login_url — JSON or form-encoded, whichever the endpoint "
                           "wants (RFC 6749 token endpoints take form). Put credentials in as "
                           "env references, e.g. "
                           "'grant_type=client_credentials&client_id=env:ID&client_secret=env:SEC', "
                           "so the secret stays out of the config file."},
            "login_method": {"type": "string", "enum": ["POST", "GET"], "description":
                             "GET for a bootstrap that only needs to set a cookie"},
            "token_path": {"type": "string", "description":
                           "dot-path to the token in the login response (default: token; "
                           "OAuth2 uses access_token)"},
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
            "system_prompt": {"type": "string", "description": "system prompt / description (defaults to name)"},
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
            "Blocks until terminal unless no_wait is set."
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
        },
        "schema": {
            "app": {"type": "string", "description": "app id (aapp_...) or name"},
            "name": {"type": "string", "description": "assessment name"},
            "controls": {"type": "string", "description": "comma-separated control ids to validate first"},
            "no_wait": {"type": "boolean", "description": "return immediately after resume instead of polling"},
            "interval": {"type": "integer", "description": "poll interval seconds (default 20)"},
            "timeout": {"type": "integer", "description": "poll timeout seconds (default 7200)"},
            "force": {"type": "boolean", "description": "run even if the selection generates zero probes"},
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


def _flags_as_params(name: str, text: str) -> str:
    """Translate the CLI flags a hint names into the PARAMETERS a caller of this tool can set.

    The CLI writes excellent remedies and writes them for a human at a shell: "re-run with
    --login-url URL --login-body '...' --token-path access_token". An agent driving this server
    cannot pass a flag — it passes `login_url`, `login_body`, `token_path` — and it is told
    elsewhere never to reach for the command line. So the most actionable sentence the product
    produces arrived in a vocabulary the reader could not use.

    MEASURED: an OAuth2 target returned that exact hint on four consecutive attempts. The model
    had the parameters, had a description telling it to use them, and still retried unchanged
    every time. The hint said `--login-url`; nothing said that was `login_url`.

    So the mapping this server already holds — parameter to flag — is inverted and appended.
    Nothing is invented: only flags this tool really accepts are named.
    """
    spec = next((t for t in TOOLS if t.get("name") == name), None)
    if not spec or not text:
        return ""
    by_flag = {}
    for param, meta in (spec.get("params") or {}).items():
        flag = (meta or {}).get("flag")
        if flag:
            by_flag[flag] = param
    hit = [by_flag[f] for f in by_flag if f in text]
    if not hit:
        return ""
    return ("\n\nAs parameters of this tool, the remedy above is: "
            + ", ".join(sorted(hit))
            + ". Call this tool again with them — do not run a shell command.")


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
        msg = err or out or "CLI error"
        res = {"ok": False, "returncode": proc.returncode,
               "error": msg + _flags_as_params(name, msg), "stdout": out}
        # The CLI's JSON error envelope is on stdout: its code, hint and — when the code knows
        # the cause — a {reason, detail, next} diagnosis. Surfaced as fields, so a caller never
        # has to regex the human text for them.
        env = _last_json(out)
        if isinstance(env, dict) and env.get("ok") is False:
            e = env.get("error")
            if isinstance(e, dict):
                if e.get("message"):
                    res["error"] = str(e["message"]) + _flags_as_params(name, str(e["message"]))
                if e.get("code"):
                    res["error_code"] = e["code"]
                if e.get("hint"):
                    res["hint"] = e["hint"]
            d = env.get("diagnosis") or (e.get("diagnosis") if isinstance(e, dict) else None)
            if isinstance(d, dict):
                res["diagnosis"] = d
        return res

    if not out:
        return {"ok": True, "result": None, "stderr": err or None}
    try:
        return {"ok": True, "result": json.loads(out)}
    except json.JSONDecodeError:
        # a --json path should always emit JSON; fall back to raw text rather than crash
        return {"ok": True, "result": out, "stderr": err or None}


def _last_json(text: str):
    """The last line of stdout that parses as JSON: the envelope, after any progress lines."""
    for line in reversed((text or "").splitlines()):
        line = line.strip()
        if line.startswith("{"):
            try:
                return json.loads(line)
            except ValueError:
                continue
    return None


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
