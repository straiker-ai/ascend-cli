#!/usr/bin/env python3
"""Straiker Bridge - pull-mode reference client.

Standard library only, no dependencies to install. See README.md / openapi.yaml in this same
folder for the full protocol writeup - this file implements it directly: long-poll /v2/lease
for probes addressed to your app, call your own target application, submit the result via
/v2/result, repeat.

Edit call_target() below and the constants that follow it before running.

Usage:
    STRAIKER_BRIDGE_URL=https://<your-host> STRAIKER_BRIDGE_API_KEY=<thin_api_key> \\
        python3 bridge_client.py
"""
import json
import os
import socket
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor


# ==================================================================================================
# REPLACE ME: this is the one function you need to write. Everything below this point is fixed
# protocol plumbing - you shouldn't need to touch it.
#
# Call your own target application (the thing being assessed) with `body` - the already-
# rendered probe content - and whatever headers/auth your app needs. Return
# (status_code, response_body): the real HTTP status and body your target returned.
#
# The implementation below is illustrative, NOT a working default - it will call whatever
# literal URL you leave in place. Point it at your real target before running this.
# ==================================================================================================
def call_target(body, headers):
    target_url = "https://your-target-app.example.com/api/chat"  # <-- your target's URL
    req = urllib.request.Request(
        target_url,
        data=json.dumps(body).encode("utf-8"),   # <-- reshape if your app expects something else
        method="POST",                            # <-- your target's method
        headers={"Content-Type": "application/json", **headers},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return e.code, {"error": e.read().decode("utf-8", errors="replace")}
# ==================================================================================================
# END REPLACE ME
# ==================================================================================================


BASE_URL = os.environ.get("STRAIKER_BRIDGE_URL", "https://ascendai-bridge.prod.straiker.ai")
API_KEY = os.environ["STRAIKER_BRIDGE_API_KEY"]  # per-app thin-client token, provisioned by Straiker
CONSUMER = os.environ.get("STRAIKER_BRIDGE_CONSUMER", f"bridge-{socket.gethostname()}")

LEASE_URL = f"{BASE_URL}/v2/lease"
RESULT_URL = f"{BASE_URL}/v2/result"
MAX_PROBES_PER_LEASE = 10
WAIT_MS = 25000  # server-side long-poll hold; clamped server-side to [0, 55000]
HTTP_TIMEOUT_SECONDS = (WAIT_MS / 1000) + 10  # comfortably above the long-poll hold

# the platform dispatches up to probe_dispatch_concurrency (20 by default, a multi-tenancy
# fairness knob, nothing to do with bridge specifically) probes at once. Processing a leased
# batch one at a time here means the 15th-or-so queued probe can sit waiting long enough to
# exceed the lease service's BRIDGE_RESPONSE_TIMEOUT (120s) purely from queueing delay - which
# surfaces as a synthetic 504 indistinguishable from a real target failure, and can trip
# escalate_target_health's consecutive-failure streak even though the target is fine. This
# cap matches the Straiker bridge's own Go client default maxWorkers.
MAX_WORKERS = 10


def _post_json(url, payload):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {API_KEY}",
        },
    )
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_SECONDS) as resp:
        return json.loads(resp.read().decode("utf-8"))


def lease():
    return _post_json(
        LEASE_URL,
        {"consumer": CONSUMER, "max": MAX_PROBES_PER_LEASE, "wait_ms": WAIT_MS},
    )


def submit_result(request_id, msg_id, status_code, body, headers=None):
    return _post_json(
        RESULT_URL,
        {
            "request_id": request_id,
            "msg_id": msg_id,
            "payload": {"status_code": status_code, "body": body, "headers": headers or {}},
        },
    )


def run_forever():
    print(f"[straiker-bridge] starting, consumer={CONSUMER}")
    printed_ready = False
    backoff_seconds = 1
    while True:
        try:
            leased = lease()
            backoff_seconds = 1
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                # Non-retriable: a bad/expired token won't heal on retry.
                print(f"Fatal: bridge rejected the API key (HTTP {e.code}). "
                      f"Check STRAIKER_BRIDGE_API_KEY.", file=sys.stderr)
                sys.exit(1)
            print(f"lease failed: HTTP {e.code}, retrying in {backoff_seconds}s", file=sys.stderr)
            time.sleep(backoff_seconds)
            backoff_seconds = min(backoff_seconds * 2, 30)
            continue
        except (urllib.error.URLError, socket.timeout, TimeoutError) as e:
            print(f"lease failed: {e}, retrying in {backoff_seconds}s", file=sys.stderr)
            time.sleep(backoff_seconds)
            backoff_seconds = min(backoff_seconds * 2, 30)
            continue

        if not printed_ready:
            # First successful /v2/lease call is the real "ready" signal - it confirms
            # BASE_URL/API_KEY are actually valid, not just that the loop started.
            print(f"[straiker-bridge] ready - consumer={CONSUMER}, watching for probes")
            printed_ready = True

        # An empty probes list is the normal outcome of a timed-out long-poll, not an error.
        probes = leased.get("probes", [])
        if probes:
            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
                # list(...) forces the map to actually run to completion (and surface any
                # exception) before the next lease cycle - .map()'s own return value is a lazy
                # generator that would otherwise go unconsumed and silently hide errors.
                list(pool.map(_process_probe, probes))


def _process_probe(probe):
    request_id = probe["request_id"]
    msg_id = probe["msg_id"]
    payload = probe["message"]["payload"]

    try:
        status_code, response_body = call_target(payload["body"], payload.get("headers", {}))
    except Exception as e:
        # Still submit a result rather than dropping the probe - a synthesized failure
        # completes the assessment's accounting; a dropped probe is only reclaimed
        # after ~90s, slower and noisier for no benefit.
        status_code, response_body = 500, {"error": str(e)}

    try:
        submit_result(request_id, msg_id, status_code, response_body)
    except Exception as e:
        # Safe to leave unsubmitted: the server reclaims and redelivers this probe
        # after ~90s of inactivity.
        print(f"submit_result failed for {request_id}: {e}", file=sys.stderr)


if __name__ == "__main__":
    run_forever()
