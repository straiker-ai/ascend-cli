"""The same shim as a Lambda (function URL or API Gateway HTTP API): POST /chat -> {"response"}.

Package this folder with adapter.json and vendor/ (the bundle already has both); handler is
`lambda_handler.handler`. Secrets (the env: references in adapter.json, SHIM_KEY) come from the
function's environment or a secret store. One warm container keeps conversation state between calls.
"""
from __future__ import annotations

import json
import os

import app as shim  # the HTTP shim's chat() and build_caller(), reused

_caller = None


def handler(event, context):
    global _caller
    if _caller is None:
        _caller = shim.build_caller()
    headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}
    key = os.environ.get("SHIM_KEY", "")
    if key and headers.get("x-shim-key", "") != key:
        return {"statusCode": 401, "body": json.dumps({"error": "X-Shim-Key required"})}
    try:
        body = json.loads(event.get("body") or "{}")
    except ValueError:
        return {"statusCode": 400, "body": json.dumps({"error": "body must be JSON"})}
    status, payload = shim.chat(_caller, body)
    return {"statusCode": status, "headers": {"Content-Type": "application/json"}, "body": json.dumps(payload)}
