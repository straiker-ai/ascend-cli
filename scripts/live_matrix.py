#!/usr/bin/env python3
"""
live_matrix.py — drive the REAL CLI against a real agent in every wire shape we have met.

The gap this closes: the offline suite mocks transport by design ("No sockets", says
test_adapters_config.py), and every STRAIKER_PAT in it is a dummy string. So for 14 of 15
adapters there was no evidence any of them could onboard and probe a real target. Green tests,
broken field. This is the test that can actually fail.

Nothing is mocked. The targets are real agents served by `agent-forge` (a live model behind eight
different wire contracts), and the platform half is the real demo tenant with the demo PAT.

    # free: derivation + a live reply. No platform writes, no probes.
    python3 scripts/live_matrix.py --stage derive

    # full lifecycle: registers an app per shape and runs a real assessment
    python3 scripts/live_matrix.py --stage full --controls sys_prompt_leak --size small

    python3 scripts/live_matrix.py --stage derive --shapes json,sse,sse-create

Two stages on purpose. `derive` costs nothing and catches most adapter bugs, so there is no
reason to spend probes to learn that a shape does not even parse. `full` registers real
applications and burns real probes, so it measures the cost of the FIRST shape and refuses to
fan out if that number is unexpectedly large -- a wrong `--size` should not quietly cost 8x.

Evidence is captured the way a customer produces it. For the multi-step shapes a bare URL cannot
express "create a conversation, then stream it", so the matrix performs the real call sequence and
writes a real HAR, which is exactly the artifact a customer exports from devtools.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
CLI = REPO / "shells" / "cli" / "ascend.py"
FORGE = Path(os.environ.get("AGENT_FORGE",
                            Path.home() / "Projects" / "agent-forge" / "agent_forge.py"))

QUESTION = "What is the status of order AC-10482273?"
# A word the model's real answer reliably contains for this order, used to prove the reply came
# from the agent rather than from progress chatter or an empty-but-successful frame.
ANSWER_MARK = re.compile(r"AC-10482273|shipp|august|aero", re.I)
CHATTER = re.compile(r"searching orders|analyz|thinking", re.I)


# ---------------------------------------------------------------------------- HAR capture
class Har:
    """A real HAR, built from real traffic.

    Hand-written fixtures encode the author's assumption about the payload shape, so the test
    ends up agreeing with the bug. These entries are recorded from actual requests instead.
    """

    def __init__(self):
        self.entries = []

    def call(self, method, url, body=None, headers=None, expect_stream=False):
        hdrs = {"Content-Type": "application/json", **(headers or {})}
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
        t0 = time.time()
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                raw, status, rh = r.read().decode("utf-8", "replace"), r.status, dict(r.headers)
        except urllib.error.HTTPError as e:
            raw, status, rh = e.read().decode("utf-8", "replace"), e.code, dict(e.headers)
        self.entries.append({
            "startedDateTime": "2026-09-03T00:00:00.000Z",
            "time": round((time.time() - t0) * 1000),
            "request": {
                "method": method, "url": url, "httpVersion": "HTTP/1.1",
                "headers": [{"name": k, "value": v} for k, v in hdrs.items()],
                "queryString": [], "cookies": [], "headersSize": -1,
                "bodySize": len(data or b""),
                **({"postData": {"mimeType": "application/json",
                                 "text": json.dumps(body)}} if data else {}),
            },
            "response": {
                "status": status, "statusText": "", "httpVersion": "HTTP/1.1",
                "headers": [{"name": k, "value": v} for k, v in rh.items()],
                "cookies": [], "redirectURL": "", "headersSize": -1, "bodySize": len(raw),
                "content": {"size": len(raw), "mimeType": rh.get("Content-Type", "text/plain"),
                            "text": raw},
            },
            "cache": {}, "timings": {"send": 0, "wait": 0, "receive": 0},
        })
        return status, raw

    def write(self, path: Path):
        path.write_text(json.dumps({
            "log": {"version": "1.2", "creator": {"name": "live_matrix", "version": "1"},
                    "entries": self.entries}}, indent=1))
        return path


def capture(shape: str, port: int, out_dir: Path) -> tuple[Path | None, str | None]:
    """Produce the evidence a customer would hand us, and the direct URL where one suffices.

    Returns (har_path_or_None, url_or_None).
    """
    b = f"http://127.0.0.1:{port}"
    h = Har()
    if shape == "json":
        h.call("POST", f"{b}/chat", {"message": QUESTION})
        return h.write(out_dir / "json.har"), f"{b}/chat"
    if shape == "sse":
        h.call("POST", f"{b}/chat", {"message": QUESTION}, expect_stream=True)
        return h.write(out_dir / "sse.har"), f"{b}/chat"
    if shape == "sentinel":
        h.call("POST", f"{b}/chat", {"message": QUESTION}, expect_stream=True)
        return h.write(out_dir / "sentinel.har"), f"{b}/chat"
    if shape == "sse-create":
        _, raw = h.call("POST", f"{b}/conversations", {"description": QUESTION})
        cid = (json.loads(raw) or {}).get("conversation_id")
        h.call("POST", f"{b}/conversations/{cid}/messages", {"message": QUESTION},
               expect_stream=True)
        return h.write(out_dir / "sse-create.har"), None      # a URL cannot express two steps
    if shape in ("session", "session-body", "session-both"):
        # The bare URL, on purpose. A customer hands over a URL, not a HAR -- that is the most
        # common case -- and since #68 the prober derives every placement of the session id from
        # it (URL, body, both). The HAR path is the fallback and is exercised by build-adapter.
        return None, b
    if shape == "poll":
        _, raw = h.call("POST", f"{b}/messages", {"message": QUESTION})
        jid = (json.loads(raw) or {}).get("job_id")
        for _ in range(30):
            _, r = h.call("GET", f"{b}/messages/{jid}")
            if (json.loads(r) or {}).get("status") != "pending":
                break
            time.sleep(0.6)
        return h.write(out_dir / "poll.har"), None
    if shape == "ack-poll":
        # The ACK-only contract: create, send (ack only), then the answer appears on a
        # transcript endpoint. Poll until the bot turn lands, so the capture contains a real
        # polling loop -- the FIRST poll fires before the agent has answered, and deriving the
        # transcript shape from that incomplete response is exactly how bot_roles fell back to
        # defaults instead of being read from the evidence.
        _, raw = h.call("POST", f"{b}/conversation/new", {})
        cid = (json.loads(raw) or {}).get("conversation_id")
        h.call("POST", f"{b}/chat/{cid}/message", {"message": QUESTION})
        for _ in range(40):
            _, r = h.call("GET", f"{b}/history?conversation_id={cid}")
            msgs = (json.loads(r) or {}).get("messages") or []
            if any(m.get("role") == "assistant" for m in msgs):
                break
            time.sleep(0.6)
        return h.write(out_dir / "ack-poll.har"), None
    # ---- the thirteen shapes added to the forge after this matrix was written ----------------
    # Single-shot shapes hand over a bare URL: that is what a customer gives us, and the prober
    # derives transport (JSON / NDJSON / text), the body template and the answer path from it.
    # A missing case here scored as "no evidence could be captured" and dragged the baseline to
    # 11/24 while every covered shape passed -- a coverage gap masquerading as a health number.
    if shape in ("ndjson", "lines", "blocks", "preamble", "envelope", "latin1", "form", "rotate"):
        return None, f"{b}/chat"
    if shape == "gateway":
        return None, f"{b}/api/v3/assistant/messages"
    if shape == "soap":
        return None, f"{b}/services/AssistantService"
    if shape == "grpc-web":
        return None, f"{b}/acmeshop.assistant.v1.Assistant/Ask"
    if shape == "widget":
        # create-then-message with a greeting gate; the bare base URL lets the prober find
        # /api/chat/v1/sessions and follow the id into /sessions/{id}/turns.
        return None, b
    if shape == "graphql":
        # The prober cannot guess a GraphQL operation -- it says so and asks for one working
        # request. Hand it exactly that, as the curl a customer would paste from their client.
        curl = out_dir / "graphql.curl"
        curl.write_text(
            f"curl -X POST {b}/graphql -H 'content-type: application/json' -d "
            + "'{\"query\":\"mutation($input:MessageInput!){sendMessage(input:$input){messages{role content}}}\","
            + "\"variables\":{\"input\":{\"message\":\"" + QUESTION + "\"}}}'\n")
        return curl, None
    if shape == "ws":
        return None, f"ws://127.0.0.1:{port}/"
    if shape == "page":
        return None, f"{b}/"
    return None, None


# ---------------------------------------------------------------------------- CLI driver
def ascend(*argv, timeout=900, env_extra=None):
    env = dict(os.environ)
    env.update({"NO_COLOR": "1", "TERM": "dumb", "ASCEND_NO_SPINNER": "1"})
    env.update(env_extra or {})
    r = subprocess.run([sys.executable, str(CLI), *argv], capture_output=True, text=True,
                       cwd=str(REPO), env=env, timeout=timeout)
    out = None
    if r.stdout.strip().startswith(("{", "[")):
        try:
            out = json.loads(r.stdout)
        except json.JSONDecodeError:
            out = None
    return r.returncode, out, r.stdout, r.stderr


def derive(shape, port, out_dir, expect):
    """`target add --dry-run`: derive the adapter and prove it against the live agent."""
    har, url = capture(shape, port, out_dir)
    source = str(har) if har else url
    row = {"shape": shape, "source": "har" if har else "url", "expect": expect}
    if not source:
        return {**row, "ok": False, "note": "no evidence could be captured"}
    argv = ["target", "add", source, "--save-as", f"forge-{shape}", "--dry-run",
            "--prompt", QUESTION, "--json"]
    if shape == "page":
        argv = ["target", "add", "--url", url, "--save-as", "forge-page", "--dry-run",
                "--prompt", QUESTION, "--json"]
    t0 = time.time()
    code, js, stdout, stderr = ascend(*argv)
    row["secs"] = round(time.time() - t0, 1)
    got = (js or {}).get("adapter")
    # The CLI prints this line with repr(), so the quote character is ' or " depending on
    # whether the reply itself contains an apostrophe. Matching only one of them reported a
    # perfectly good on-topic answer as "no-reply" -- a harness lie about a working product.
    reply = ""
    m = re.search(r"target replied: (['\"])(.*?)\1\s*$", stderr, re.M)
    if m:
        reply = m.group(2)
    # "answered" = a non-empty reply came back. "on-topic" = it actually addressed the order we
    # asked about, which is the stronger claim and the one that proves we read the agent's words
    # rather than a status frame.
    row.update(adapter=got, exit=code,
               validated=bool((js or {}).get("validated")),
               reply=reply[:70],
               answered=bool(reply.strip()),
               on_topic=bool(ANSWER_MARK.search(reply)),
               chatter_leak=bool(CHATTER.search(reply)))
    # A shape whose `expect` is None is one no shipped adapter covers. For those, PASSING means
    # the CLI REFUSED and said why -- not that it validated. Scoring them the same way as the
    # rest would demand a wrong answer, and a harness that cannot express "correctly declined"
    # will eventually be satisfied by making the product guess.
    tail = [l for l in stderr.strip().splitlines() if l.strip()][-1:] or [""]
    if expect is None:
        row["ok"] = (code != 0 and not got)
        row["note"] = ("correctly declined: " + tail[0][:88]) if row["ok"] else (
            f"expected NO adapter (no shipped adapter fits this shape), got {got}")
        row["declined"] = True
        return row
    row["ok"] = (code == 0 and got == expect and row["validated"])
    if not row["ok"]:
        row["note"] = (f"expected {expect}, got {got}" if got != expect else tail[0][:100])
    return row


def full(shape, row, controls, size, budget_guard):
    """Register, re-prove, assess for real, read findings."""
    name = f"forge-{shape}"
    code, js, out, err = ascend("target", "add", f"--config", name, "--name", name, "--json")
    if code != 0:
        row["note"] = "register failed: " + (err.strip().splitlines() or [""])[-1][:90]
        return row
    row["registered"] = True
    code, js, out, err = ascend("target", "check", name, "--json")
    row["reproved"] = (code == 0)
    argv = ["assess", "run", "--app", name, "--name", f"matrix {shape}",
            "--controls", controls, "--size", size, "--wait", "--json"]
    t0 = time.time()
    code, js, out, err = ascend(*argv, timeout=2400)
    row["assess_secs"] = round(time.time() - t0)
    js = js or {}
    answered = js.get("answered") or js.get("probes_answered")
    total = js.get("total") or js.get("probes")
    row.update(assess_exit=code, answered=answered, probes=total,
               findings=js.get("findings_count") or js.get("findings"))
    # A run that completes having measured nothing is the worst outcome: it looks like a pass.
    row["false_pass"] = bool(code == 0 and (answered in (0, None)))
    if budget_guard is not None and isinstance(total, int):
        budget_guard.append(total)
    return row


def print_table(rows, stage):
    w = shutil.get_terminal_size((120, 24)).columns
    print("\n" + "=" * min(w, 108))
    print(f"LIVE MATRIX — stage `{stage}`   real agent, real platform, nothing mocked")
    print("=" * min(w, 108))
    hdr = f"{'shape':<11} {'src':<4} {'adapter':<16} {'exp':<16} {'live reply':<10} {'':<6}"
    print(hdr)
    print("-" * min(w, 108))
    for r in rows:
        mark = ("DECLINE" if (r.get("ok") and r.get("declined"))
                else "PASS" if r.get("ok") else "FAIL")
        live = ("on-topic" if r.get("on_topic") else
                ("answered" if r.get("answered") else
                 ("no-reply" if r.get("validated") else "-")))
        if r.get("chatter_leak"):
            live += "+CHATTER"
        # str() on both: `expect` is None for a shape no adapter covers, and a bare
        # f"{None:<16}" raises TypeError -- which crashed the whole table after five good rows.
        exp = r["expect"] if r["expect"] is not None else "(none fits)"
        print(f"{r['shape']:<11} {r.get('source','-'):<4} {str(r.get('adapter')):<16} "
              f"{str(exp):<16} {live:<10} {mark:<6}")
        if r.get("note"):
            print(f"{'':<11} └─ {r['note']}")
        if stage == "full":
            print(f"{'':<11}    registered={r.get('registered')} reproved={r.get('reproved')} "
                  f"answered={r.get('answered')}/{r.get('probes')} "
                  f"findings={r.get('findings')} false_pass={r.get('false_pass')} "
                  f"({r.get('assess_secs')}s)")
    ok = sum(1 for r in rows if r.get("ok"))
    print("-" * min(w, 108))
    dec = sum(1 for r in rows if r.get("ok") and r.get("declined"))
    print(f"{ok}/{len(rows)} shapes behaved correctly "
          f"({ok - dec} derived and answered live, {dec} correctly declined as unsupported)")
    leaks = [r["shape"] for r in rows if r.get("chatter_leak")]
    if leaks:
        print(f"progress chatter reached the scored reply on: {', '.join(leaks)}")
    fp = [r["shape"] for r in rows if r.get("false_pass")]
    if fp:
        print(f"FALSE PASS (completed having measured nothing): {', '.join(fp)}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--stage", choices=["derive", "full"], default="derive")
    ap.add_argument("--shapes", default="all")
    ap.add_argument("--controls", default="sys_prompt_leak")
    ap.add_argument("--size", default="small")
    ap.add_argument("--base-port", type=int, default=8700)
    ap.add_argument("--max-first-probes", type=int, default=40,
                    help="refuse to fan out if the first shape's run is larger than this")
    ap.add_argument("--out", default=None, help="write the rows as JSON here")
    a = ap.parse_args()

    if not os.environ.get("STRAIKER_PAT"):
        print("STRAIKER_PAT is not set. This test talks to the real platform on purpose.",
              file=sys.stderr)
        return 2
    if not FORGE.is_file():
        print(f"agent-forge not found at {FORGE}. Set $AGENT_FORGE.", file=sys.stderr)
        return 2

    out_dir = REPO / ".matrix"
    out_dir.mkdir(exist_ok=True)
    proc = subprocess.Popen([sys.executable, str(FORGE), "--shape", "all",
                             "--base-port", str(a.base_port), "--json"],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                            cwd=str(FORGE.parent))
    try:
        book = None
        for _ in range(60):
            time.sleep(1)
            if proc.poll() is not None:
                print("agent-forge exited:\n" + (proc.stderr.read() or "")[:600], file=sys.stderr)
                return 1
            # the port map is one JSON object printed at boot
            try:
                proc.stdout.flush()
            except Exception:
                pass
            break
        # read the JSON object off stdout (it is printed once, then the process idles)
        buf = ""
        deadline = time.time() + 90
        while time.time() < deadline:
            line = proc.stdout.readline()
            if not line:
                time.sleep(0.2)
                continue
            buf += line
            if buf.count("{") and buf.count("{") == buf.count("}"):
                book = json.loads(buf)
                break
        if not book:
            print("agent-forge did not print its port map", file=sys.stderr)
            return 1
        print(f"agent-forge: {book['backend']}   gates: {book['gates']}")

        want = (list(book["shapes"]) if a.shapes == "all"
                else [s.strip() for s in a.shapes.split(",") if s.strip()])
        rows, guard = [], [] if a.stage == "full" else None
        for shape in want:
            info = book["shapes"].get(shape)
            if not info:
                print(f"  skip {shape}: not served"); continue
            print(f"  [{shape}] deriving from {'har' if shape not in ('ws','page','json','sse','sentinel') else 'url/har'} …",
                  flush=True)
            row = derive(shape, info["port"], out_dir, info["expect_adapter"])
            if a.stage == "full" and row.get("ok"):
                if guard and max(guard) > a.max_first_probes:
                    row["note"] = (f"skipped: first run was {max(guard)} probes, over the "
                                   f"--max-first-probes={a.max_first_probes} guard")
                else:
                    row = full(shape, row, a.controls, a.size, guard)
            rows.append(row)
        print_table(rows, a.stage)
        if a.out:
            Path(a.out).write_text(json.dumps(rows, indent=2, default=str))
            print(f"rows written to {a.out}")
        return 0 if all(r.get("ok") for r in rows) else 1
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()


if __name__ == "__main__":
    sys.exit(main())
