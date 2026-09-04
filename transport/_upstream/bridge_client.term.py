#!/usr/bin/env python3
"""Straiker Bridge - pull-mode reference client for a CLI/terminal-backed AI agent target.

For target applications only reachable as an interactive command-line program (e.g. a
terminal-based coding agent, a chat REPL) rather than over HTTP - this attaches to a tmux
session running your agent and drives it via `tmux send-keys`/`tmux capture-pane`, instead of
making an HTTP call like bridge_client.py's call_target() does.

Standard library only (no pip install) - but requires the `tmux` binary on PATH, and requires
YOU to start your agent inside a tmux session before running this script:

    tmux new -s straiker-agent 'claude'
    # ... do any one-time interactive setup your agent needs (login, trust prompts, etc.) ...
    # detach with Ctrl-b d, leaving the session running in the background

This script only attaches to that already-running session by name - it never launches or
owns your agent's process, so restarting this script (or it crashing) never resets your
agent's state, and any interactive setup you did stays done. If the session disappears (you
killed it, or the agent itself exited), that's surfaced as a clear per-probe error rather than
silently auto-relaunching something on your behalf.

See README.md / openapi.yaml in this same folder for the full protocol writeup - this file
implements it directly: long-poll /v2/lease for probes addressed to your app, type each
probe's prompt into the tmux session, submit whatever appears in the pane back via
/v2/result, repeat.

Edit call_target() and the constants that follow it before running.

Usage:
    STRAIKER_BRIDGE_URL=https://<your-host> STRAIKER_BRIDGE_API_KEY=<thin_api_key> \\
        python3 bridge_client.term.py
"""
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import textwrap
import threading
import time
import urllib.error
import urllib.request


# ==================================================================================================
# REPLACE ME: point this at your own tmux session and tune how "done responding" is detected.
# Everything below this point is fixed protocol plumbing - you shouldn't need to touch it.
# ==================================================================================================

# The tmux session your agent is already running in (see the module docstring above for how
# to start it). This script attaches to it by name - it does not create or launch it.
TMUX_SESSION = os.environ.get("STRAIKER_BRIDGE_TMUX_SESSION", "straiker-agent")

# How many lines of pane history to capture on each read. Needs to comfortably exceed the
# longest single reply your agent ever prints, or TmuxAgentSession._new_lines() below can't
# tell where the old content ends and the new reply begins.
HISTORY_LINES = 2000

# How often to poll the pane for new output while waiting for a reply.
POLL_INTERVAL_SECONDS = 0.5

# How long the pane must show NO change before deciding the agent is done responding. Most CLI
# agents don't print a stable, parseable "ready for input" prompt (or if they do, it varies by
# version/config) - idle-quiet detection is the generic fallback that works regardless. Raise
# this if your agent has long human-visible pauses mid-response (e.g. tool calls) that
# shouldn't be mistaken for "done".
IDLE_QUIET_SECONDS = 3.0

# Absolute cap on how long to wait for one turn, even if the pane never goes quiet (e.g. the
# agent streams continuously). Whatever's captured by then is submitted as-is.
MAX_RESPONSE_SECONDS = 90.0

# Exclude the pane's last new line from idle-quiet stability checks - set this if your agent
# has a live-updating trailing line (elapsed time, token/cost counter, spinner) that would
# otherwise tick forever and never register as "quiet", forcing every single turn to run all
# the way to MAX_RESPONSE_SECONDS. Leave False if your agent has no such line - the trade-off
# is that a genuine reply consisting of only one line, streamed in place with nothing else on
# screen changing, will get cut off after IDLE_QUIET_SECONDS regardless of this setting's
# value once it's True. CHROME_LINE_PATTERNS below is the more precise tool for a ticking
# line that ISN'T positioned last - use this as a fallback for anything that isn't.
IGNORE_LAST_LINE_FOR_QUIET = True

# Regexes for chrome your agent's TUI prints that is never part of its actual reply - box
# borders, a status/footer bar, input hints, etc. Matched against each line AFTER stripping
# leading/trailing whitespace; a matching line is dropped entirely, both from what's
# submitted as the response and from idle-quiet stability checks (so a ticking status bar
# doesn't prevent "done responding" from ever being detected, wherever it's positioned).
# The examples below are illustrative - replace with whatever your agent's TUI actually prints.
CHROME_LINE_PATTERNS = [
    r"^▸ Credits: .* • Time: .*$",           # per-turn cost/time footer
    r"^\S+ · auto · .*%.*$",                 # bottom status bar (session/context indicator)
    r"^ask a question or describe a task ↵$",  # input hint
    r"^/copy to clipboard$",                 # input hint
]

# Lines made up entirely of box-drawing/rule characters (─│┌┐└┘├┤═║ etc.) or repeated plain
# ASCII rule characters (---, ===, ___) - generic decorative borders that many CLI/TUI agents
# draw around each turn, not specific to any one agent's wording like CHROME_LINE_PATTERNS is.
_BOX_DRAWING_LINE_RE = re.compile(r"^[─-╿▀-▟\-=_~\s]+$")


def _strip_chrome_lines(text):
    kept = []
    for line in text.split("\n"):
        stripped = line.strip()
        if stripped and (_BOX_DRAWING_LINE_RE.match(stripped)
                          or any(re.match(p, stripped) for p in CHROME_LINE_PATTERNS)):
            continue
        kept.append(line)
    return "\n".join(kept)


def _strip_echoed_prompt(lines, prompt_text):
    # tmux/the agent's TUI echoes the typed prompt back into the pane - often wrapped across
    # several lines with the agent's own indentation (not just terminal soft-wrap, which -J
    # already join in _capture()). Reconstructs the echo by stripping and rejoining lines
    # with a single space and comparing against the whitespace-normalized prompt, so it's
    # recognized and dropped regardless of how many lines or how much indentation the
    # agent's own rendering wrapped it into. Only ever advances past a line whose
    # accumulated text is still a genuine prefix of the prompt, so it's a no-op (strips
    # nothing) if the agent doesn't echo input at all.
    normalized_prompt = " ".join(prompt_text.split())
    accumulated = ""
    cut = 0
    for i, line in enumerate(lines):
        piece = line.strip()
        if not piece:
            continue
        candidate = f"{accumulated} {piece}".strip() if accumulated else piece
        if normalized_prompt.startswith(candidate):
            accumulated = candidate
            cut = i + 1
            if candidate == normalized_prompt:
                break
        else:
            break
    return lines[cut:]


def _extract_prompt(body):
    # Mirrors the fallback chain used by the other reference clients in this folder - real
    # probe bodies commonly use one of these shapes.
    if isinstance(body, dict):
        return body.get("prompt") or body.get("message") or body.get("action") or str(body)
    return str(body)


class TmuxAgentSession:
    """Drives an externally-managed tmux session, one turn at a time.

    Unlike a spawned subprocess, this never creates or restarts the session - if it's gone,
    that's someone else's action (you killed it, or the agent exited) and is reported back as
    a per-probe error rather than papered over.
    """

    def __init__(self, session_name):
        self.session_name = session_name
        self._lock = threading.Lock()

    def _session_exists(self):
        result = subprocess.run(
            ["tmux", "has-session", "-t", self.session_name],
            capture_output=True,
        )
        return result.returncode == 0

    def _capture(self):
        result = subprocess.run(
            # -J joins soft-wrapped lines back into their original logical line. Without it,
            # a long probe (a single logical line) gets hard-split across several physical
            # rows at the pane's width, which would prevent _strip_echoed_prompt() below from
            # recognizing the echoed prompt as a single unit and dropping it cleanly.
            ["tmux", "capture-pane", "-t", self.session_name, "-p", "-J", "-S", f"-{HISTORY_LINES}"],
            capture_output=True, text=True, check=True,
        )
        # tmux pads capture-pane's output with blank lines up to the pane's current height
        # whenever content doesn't fill it yet - without stripping that, two captures a
        # moment apart differ only in how much padding they have (not in real content),
        # which breaks both change-detection in _wait_for_quiet() and the diff in
        # _new_lines() below.
        return result.stdout.rstrip("\n")

    def _send(self, prompt_text):
        # -l sends the text as literal characters, not tmux key names - important since
        # probe content is adversarial test input and could otherwise be misread as tmux key
        # syntax (e.g. a probe literally containing the text "Enter" or "C-c"). The Enter
        # keypress that submits it is sent separately, without -l.
        subprocess.run(
            ["tmux", "send-keys", "-t", self.session_name, "-l", "--", prompt_text],
            check=True,
        )
        subprocess.run(["tmux", "send-keys", "-t", self.session_name, "Enter"], check=True)

    @staticmethod
    def _new_lines(before, after):
        # Diffed line-by-line, not as one whole string: a raw `after.startswith(before)`
        # check breaks the instant ANY earlier line re-renders differently - e.g. a live
        # status/footer line (elapsed time, token/cost counter, spinner) that ticks on its
        # own regardless of new input. One changed trailing line would otherwise fail the
        # whole-string prefix check and fall back to returning the ENTIRE accumulated pane
        # as "new" output on every single turn. Comparing line-by-line means only the lines
        # that actually changed (the ticking footer, plus whatever's genuinely new) are
        # treated as new - the untouched conversation history above it still matches and is
        # correctly excluded.
        before_lines = before.split("\n")
        after_lines = after.split("\n")
        common = 0
        limit = min(len(before_lines), len(after_lines))
        while common < limit and before_lines[common] == after_lines[common]:
            common += 1
        return after_lines[common:]

    def _clean_new_lines(self, before, after):
        text = _strip_chrome_lines("\n".join(self._new_lines(before, after)))
        return text.split("\n")

    def _wait_for_quiet(self, before):
        deadline = time.monotonic() + MAX_RESPONSE_SECONDS
        current = self._capture()
        stable_part = self._clean_new_lines(before, current)
        if IGNORE_LAST_LINE_FOR_QUIET:
            stable_part = stable_part[:-1]
        last_change = time.monotonic()
        while True:
            now = time.monotonic()
            if now - last_change >= IDLE_QUIET_SECONDS or now >= deadline:
                return current
            time.sleep(POLL_INTERVAL_SECONDS)
            current = self._capture()
            new_stable_part = self._clean_new_lines(before, current)
            if IGNORE_LAST_LINE_FOR_QUIET:
                new_stable_part = new_stable_part[:-1]
            if new_stable_part != stable_part:
                stable_part = new_stable_part
                last_change = time.monotonic()

    def send_turn(self, prompt_text):
        """Send one turn to the agent and return (status_code, response_text)."""
        with self._lock:
            if not self._session_exists():
                return 500, (
                    f"tmux session '{self.session_name}' not found - start your agent inside "
                    f"it first, e.g.: tmux new -s {self.session_name} 'your-agent-cli'"
                )
            try:
                before = self._capture()
                self._send(prompt_text)
                after = self._wait_for_quiet(before)
                lines = self._clean_new_lines(before, after)
                lines = _strip_echoed_prompt(lines, prompt_text)
                # Some agents indent their whole conversation panel by a fixed margin -
                # dedent removes that COMMON leading whitespace across all lines without
                # disturbing any real nested indentation within a longer reply (code blocks,
                # lists), unlike a blanket per-line .strip() would.
                return 200, textwrap.dedent("\n".join(lines)).strip("\n")
            except subprocess.CalledProcessError as e:
                return 500, f"tmux command failed: {e}"


_session = TmuxAgentSession(TMUX_SESSION)


def call_target(body, headers):
    status_code, reply = _session.send_turn(_extract_prompt(body))
    return status_code, {"response": reply}
# ==================================================================================================
# END REPLACE ME
# ==================================================================================================


BASE_URL = os.environ.get("STRAIKER_BRIDGE_URL", "https://ascendai-bridge.prod.straiker.ai")
API_KEY = os.environ["STRAIKER_BRIDGE_API_KEY"]  # per-app thin-client token, provisioned by Straiker
CONSUMER = os.environ.get("STRAIKER_BRIDGE_CONSUMER", f"bridge-{socket.gethostname()}")

LEASE_URL = f"{BASE_URL}/v2/lease"
RESULT_URL = f"{BASE_URL}/v2/result"

# Leased one at a time, not in batches: the tmux session behind TmuxAgentSession can only work
# one turn at a time (see its docstring), so anything leased beyond what's actively being
# processed just sits queued - and each queued probe's clock (the lease service's
# BRIDGE_RESPONSE_TIMEOUT, 120s by default) keeps running the whole time it waits. Leasing 1
# at a time means a probe is never claimed before there's an actual turn in flight for it.
MAX_PROBES_PER_LEASE = 1
WAIT_MS = 25000  # server-side long-poll hold; clamped server-side to [0, 55000]
HTTP_TIMEOUT_SECONDS = (WAIT_MS / 1000) + 10  # comfortably above the long-poll hold


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
    if shutil.which("tmux") is None:
        print("Fatal: tmux is not installed / not on PATH.", file=sys.stderr)
        sys.exit(1)

    if _session._session_exists():
        print(f"[straiker-bridge] attached to tmux session '{TMUX_SESSION}'")
    else:
        print(f"[straiker-bridge] warning: tmux session '{TMUX_SESSION}' not found yet - "
              f"start your agent with: tmux new -s {TMUX_SESSION} 'your-agent-cli'",
              file=sys.stderr)

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
            # First successful /v2/lease call is the real "ready" signal - it confirms the
            # bridge URL/API key are valid, not just that tmux is set up locally.
            print(f"[straiker-bridge] ready - consumer={CONSUMER}, watching for probes")
            printed_ready = True

        # An empty probes list is the normal outcome of a timed-out long-poll, not an error.
        for probe in leased.get("probes", []):
            _process_probe(probe)


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
