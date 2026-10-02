#!/usr/bin/env python3
"""The adapter as a hosted service: POST /chat {"prompt": …} -> {"response": …}.

Runs one adapter config through the same TargetCaller the relay and `ascend chat` use, so
conversation state and credential lifecycle behave exactly as validated. Register a DIRECT app on
the platform against this URL (request {"prompt": "{{PROMPT}}"}, response {"response": "{{RESPONSE}}"},
header X-Shim-Key) and the platform's API connects straight to it — no long-poll relay.

    SHIM_KEY=… python3 app.py adapter.json 8787        # vendored runtime beside this file, or the CLI tree
"""
from __future__ import annotations

import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
for cand in (HERE.parent / "vendor", HERE.parent, HERE.parents[1] if len(HERE.parents) > 1 else HERE):
    if (cand / "runtime").is_dir():
        sys.path.insert(0, str(cand / "runtime")); sys.path.insert(0, str(cand / "control")); sys.path.insert(0, str(cand))
        break

CONFIG_PATH = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("ADAPTER_CONFIG", str(HERE.parent / "adapter.json"))
PORT = int(sys.argv[2] if len(sys.argv) > 2 else os.environ.get("PORT", "8787"))
KEY = os.environ.get("SHIM_KEY", "")


def build_caller():
    from call_target import TargetCaller  # noqa: PLC0415
    cfg = json.load(open(CONFIG_PATH))
    return TargetCaller(cfg.get("adapter") or "direct_api", "inline", config=cfg)


def chat(caller, body: dict) -> tuple[int, dict]:
    prompt = body.get("prompt") or body.get("message") or ""
    if not prompt:
        return 400, {"error": "prompt required"}
    message = {"payload": {"body": {"prompt": prompt}}}
    if body.get("conversation_id"):
        message["conversation_id"] = body["conversation_id"]
    status, out = caller.handler(message)
    if status >= 400 or out.get("_error"):
        return (status if status >= 400 else 502), {"error": out.get("_error") or f"target returned {status}"}
    return 200, {"response": out.get("response", ""), "conversation_id": body.get("conversation_id")}


class Handler(BaseHTTPRequestHandler):
    caller = None

    def _send(self, status: int, payload: dict) -> None:
        data = json.dumps(payload).encode()
        self.send_response(status); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)

    def do_GET(self):
        self._send(200, {"ok": True, "adapter": Handler.caller.adapter_type}) if self.path.rstrip("/") in ("", "/healthz", "/healthcheck") else self._send(404, {"error": "not found"})

    def do_POST(self):
        if self.path.rstrip("/") != "/chat":
            return self._send(404, {"error": "not found"})
        if KEY and self.headers.get("X-Shim-Key", "") != KEY:
            return self._send(401, {"error": "X-Shim-Key required"})
        try:
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
        except ValueError:
            return self._send(400, {"error": "body must be JSON"})
        self._send(*chat(Handler.caller, body))

    def log_message(self, fmt, *args):  # one line per call, no client secrets
        sys.stderr.write("shim %s %s\n" % (self.command, self.path))


if __name__ == "__main__":
    Handler.caller = build_caller()
    print(f"shim: adapter {Handler.caller.adapter_type} from {CONFIG_PATH} on :{PORT} ({'X-Shim-Key required' if KEY else 'NO key set'})", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
