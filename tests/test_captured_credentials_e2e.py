"""
test_captured_credentials_e2e.py — wiring a target that REQUIRES a header, with nobody typing it.

`test_captured_credentials.py` beside this file tests the pieces: classify keeps the value, the
store holds it, `merge_auth` puts it back on the wire. Every one of those can pass while the
command a human actually runs still fails, because the piece that joins them —
`_store_captured_credentials` in `shells/cli/ascend.py` — is CLI glue that no unit test touches.
That glue has to run before the config is written and before the gate validates, and "before" is
not something a unit test of either end can see.

So this drives the real command, `ascend target add --har … --dry-run`, against a real HTTP
server that answers **401 to any request without the exact token the captured session presented**.
The server is the assertion: if the operator would have had to supply the credential, the gate
fails and this test fails with it.

`--dry-run` stops after the live validation and before registration, so this needs no platform,
no tenant and no network beyond loopback.

MUTATION-CHECKED: reverting `captured_secret_headers` to `return {}` — the original bug — makes
this fail at the gate with the config's `headers` holding only `Content-Type`, which is exactly
the shape of the run that measured 10 delivered / 0 answered.

Run:  python3 -m pytest tests/test_captured_credentials_e2e.py -q
"""
import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOKEN = "wt_e2e_9f2c41d07b3e5a8c1290ffee"



def _reply(raw: bytes, canned: str) -> bytes:
    """An answer that DEPENDS on the question.

    A stub that returns one constant is refused by `target add`, and rightly: every probe would
    score against the same string, so the run completes and reports LOW having measured nothing.
    The check exists because that is the one result worse than no result — so the fixture has to
    behave like a bot, not like a status endpoint.
    """
    try:
        asked = (json.loads(raw or b"{}") or {}).get("message") or ""
    except Exception:
        asked = ""
    return json.dumps({"reply": f"{canned} You asked: {asked[:60]}"}).encode()


class _Target(BaseHTTPRequestHandler):
    """A bot behind a session header — i.e. every bot worth red-teaming."""

    tokens_seen: list = []

    def log_message(self, *_a):
        pass

    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        got = self.headers.get("X-Window-Token")
        type(self).tokens_seen.append(got)
        if got != TOKEN:
            self.send_response(401)
            self.end_headers()
            self.wfile.write(b'{"error":"missing X-Window-Token"}')
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(_reply(raw, "It shipped on Tuesday."))


@pytest.fixture
def target():
    _Target.tokens_seen = []
    srv = HTTPServer(("127.0.0.1", 0), _Target)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}/api/chat", _Target
    srv.shutdown()


def _har(url):
    """One captured turn from a signed-in session, in the shape a browser exports."""
    return {"log": {"version": "1.2", "entries": [{
        "startedDateTime": "2026-09-21T00:00:00.000Z", "time": 5,
        "request": {"method": "POST", "url": url, "httpVersion": "HTTP/1.1",
                    "queryString": [], "cookies": [], "headersSize": -1, "bodySize": 30,
                    "headers": [{"name": "Content-Type", "value": "application/json"},
                                {"name": "X-Window-Token", "value": TOKEN}],
                    "postData": {"mimeType": "application/json",
                                 "text": '{"message":"where is my order?"}'}},
        "response": {"status": 200, "statusText": "OK", "httpVersion": "HTTP/1.1",
                     "headers": [{"name": "Content-Type", "value": "application/json"}],
                     "cookies": [], "redirectURL": "", "headersSize": -1, "bodySize": 30,
                     "content": {"size": 30, "mimeType": "application/json",
                                 "text": '{"reply":"It shipped on Tuesday."}'}},
        "cache": {}, "timings": {"send": 0, "wait": 0, "receive": 0}}]}}


def test_a_target_behind_a_session_header_wires_with_no_operator_input(target, tmp_path):
    url, server = target
    har_path = tmp_path / "session.har"
    har_path.write_text(json.dumps(_har(url)))

    env = dict(os.environ)
    env.update(ASCEND_HOME=str(tmp_path / "home"), ASCEND_STATE_DIR=str(tmp_path / "state"),
               ASCEND_CONFIG_DIR=str(tmp_path / "configs"),
               PYTHONPATH=os.path.join(REPO, "runtime"))
    for key in [k for k in env if k.startswith("ASCEND_SECRET_")]:
        env.pop(key)

    proc = subprocess.run(
        [sys.executable, "-B", "shells/cli/ascend.py", "target", "add", "--har", str(har_path),
         "--prompt", "where is my order?", "--name", "e2e-target", "--dry-run"],
        cwd=REPO, env=env, capture_output=True, text=True, timeout=180)
    out = (proc.stdout or "") + (proc.stderr or "")

    # The gate talks to the live target. Passing it IS the proof the credential got there.
    assert proc.returncode == 0, f"wiring failed — the operator would have to supply it:\n{out}"
    assert "It shipped on Tuesday." in out, f"the target never answered:\n{out}"
    assert TOKEN in server.tokens_seen, f"the target never received its token: {server.tokens_seen}"
    assert None not in server.tokens_seen, \
        f"a request went out unauthenticated: {server.tokens_seen}"

    # ...and the promise the original code was protecting still holds.
    configs = [p for p in (tmp_path / "configs").rglob("*.json")]
    assert configs, "no config was written — the assertion below would be vacuous"
    written = "\n".join(p.read_text() for p in configs)
    assert TOKEN not in written, "the token was baked into a config on disk"
    assert "env:ASCEND_SECRET_" in written, f"no reference was written either:\n{written}"

    stores = list((tmp_path / "state").rglob("target_secrets.json"))
    assert stores, "the credential was not stored anywhere — the next run cannot authenticate"
    assert TOKEN in stores[0].read_text()
    assert stores[0].stat().st_mode & 0o077 == 0, "the credential store is world-readable"


class _BasicTarget(BaseHTTPRequestHandler):
    """A bot behind HTTP Basic — the plainest "here is a username and password" case."""

    USER, PASS = "botuser", "s3cr3t-p4ssw0rd"
    seen: list = []

    def log_message(self, *_a):
        pass

    def do_POST(self):
        import base64
        raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        got = self.headers.get("Authorization") or ""
        type(self).seen.append(got)
        want = "Basic " + base64.b64encode(f"{self.USER}:{self.PASS}".encode()).decode()
        if got != want:
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="bot"')
            self.end_headers()
            self.wfile.write(b'{"error":"unauthorized"}')
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(_reply(raw, "Signed in. It shipped on Tuesday."))


@pytest.fixture
def basic_target():
    _BasicTarget.seen = []
    srv = HTTPServer(("127.0.0.1", 0), _BasicTarget)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}/api/chat", _BasicTarget
    srv.shutdown()


def test_a_username_and_password_handed_over_directly(basic_target, tmp_path):
    """`--basic USER:PASS` — the operator simply hands the credential over.

    It used to become `Authorization: Basic <base64>` inside `cfg["headers"]`, and
    `cfg["headers"]` is written to disk — so typing a password wrote it into a JSON file. Base64
    is an encoding, not encryption. The capture path was careful with credentials and the path
    where a human types one was not, which is the wrong way round.

    Now both go to the same 0600 store and the config keeps a reference. The server here refuses
    anything but the right Basic header, so a pass means the credential really did travel.
    """
    url, server = basic_target
    env = dict(os.environ)
    env.update(ASCEND_HOME=str(tmp_path / "home"), ASCEND_STATE_DIR=str(tmp_path / "state"),
               ASCEND_CONFIG_DIR=str(tmp_path / "configs"),
               PYTHONPATH=os.path.join(REPO, "runtime"))
    for key in [k for k in env if k.startswith("ASCEND_SECRET_")]:
        env.pop(key)

    proc = subprocess.run(
        [sys.executable, "-B", "shells/cli/ascend.py", "target", "add", "--api", url,
         "--basic", f"{_BasicTarget.USER}:{_BasicTarget.PASS}",
         "--prompt", "where is my order?", "--name", "basic-target", "--dry-run"],
        cwd=REPO, env=env, capture_output=True, text=True, timeout=180)
    out = (proc.stdout or "") + (proc.stderr or "")

    assert proc.returncode == 0, f"wiring with a username and password failed:\n{out}"
    assert "Signed in." in out, f"the target never authenticated:\n{out}"
    assert any(h.startswith("Basic ") for h in server.seen), \
        f"no Basic credential reached the target: {server.seen}"

    configs = list((tmp_path / "configs").rglob("*.json"))
    assert configs, "no config was written — the next assertions would be vacuous"
    written = "\n".join(p.read_text() for p in configs)
    assert _BasicTarget.PASS not in written, "the password was written into the config"
    import base64 as _b64
    blob = _b64.b64encode(f"{_BasicTarget.USER}:{_BasicTarget.PASS}".encode()).decode()
    assert blob not in written, \
        "the base64 of the password was written into the config — encoded is not protected"
    assert "env:ASCEND_SECRET_" in written, f"no reference was written either:\n{written}"

    stores = list((tmp_path / "state").rglob("target_secrets.json"))
    assert stores, "the credential was not stored — the next run cannot authenticate"
    assert stores[0].stat().st_mode & 0o077 == 0, "the credential store is world-readable"


class _LoginTarget(BaseHTTPRequestHandler):
    """A portal: POST credentials to /login, get a token, use it on /chat."""

    USER, PASS, TOKEN = "botuser", "s3cr3t-p4ssw0rd", "tok_live_0099aabb"
    login_bodies: list = []

    def log_message(self, *_a):
        pass

    def do_POST(self):
        import json as _j
        raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        if self.path.endswith("/login"):
            try:
                body = _j.loads(raw or b"{}")
            except ValueError:
                body = {}
            type(self).login_bodies.append(body)
            if body.get("username") != self.USER or body.get("password") != self.PASS:
                self.send_response(401); self.end_headers()
                self.wfile.write(b'{"error":"bad credentials"}'); return
            self.send_response(200)
            self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(_j.dumps({"token": self.TOKEN}).encode()); return
        if self.headers.get("Authorization") != f"Bearer {self.TOKEN}":
            self.send_response(401); self.end_headers()
            self.wfile.write(b'{"error":"unauthorized"}'); return
        self.send_response(200)
        self.send_header("Content-Type", "application/json"); self.end_headers()
        self.wfile.write(_reply(raw, "Logged in. It shipped on Tuesday."))


@pytest.fixture
def login_target():
    _LoginTarget.login_bodies = []
    srv = HTTPServer(("127.0.0.1", 0), _LoginTarget)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    yield base, _LoginTarget
    srv.shutdown()


def test_credentials_sourced_from_the_environment_reach_the_login(login_target, tmp_path):
    """Sourcing the credentials instead of typing them — the form the tool RECOMMENDS.

    `--login-body '{"username":"env:BOT_USER","password":"env:BOT_PASS"}'` turns the values into
    `inputs` references so the credential stays out of the config, and the warning in
    `_login_for_token` actively tells operators to use exactly this. But the login POST used the
    RAW parsed body, so it sent the literal nine-character string `env:BOT_USER` as the username
    and the login failed — the recommended form was the one that could not work. The stored
    recipe was correct; the login that produced it was not.

    The server asserts it: it 401s unless it receives the real username and password.
    """
    base, server = login_target
    env = dict(os.environ)
    env.update(ASCEND_HOME=str(tmp_path / "home"), ASCEND_STATE_DIR=str(tmp_path / "state"),
               ASCEND_CONFIG_DIR=str(tmp_path / "configs"),
               PYTHONPATH=os.path.join(REPO, "runtime"),
               BOT_USER=_LoginTarget.USER, BOT_PASS=_LoginTarget.PASS)
    for key in [k for k in env if k.startswith("ASCEND_SECRET_")]:
        env.pop(key)

    proc = subprocess.run(
        [sys.executable, "-B", "shells/cli/ascend.py", "target", "add",
         "--api", f"{base}/api/chat",
         "--login-url", f"{base}/login",
         "--login-body", '{"username":"env:BOT_USER","password":"env:BOT_PASS"}',
         "--prompt", "where is my order?", "--name", "login-target", "--dry-run"],
        cwd=REPO, env=env, capture_output=True, text=True, timeout=180)
    out = (proc.stdout or "") + (proc.stderr or "")

    assert proc.returncode == 0, f"the recommended env-reference form failed:\n{out}"
    assert server.login_bodies, "the login endpoint was never called"
    sent = server.login_bodies[0]
    assert sent.get("username") == _LoginTarget.USER, \
        f"the login got a literal reference instead of the value: {sent}"
    assert sent.get("password") == _LoginTarget.PASS, f"password not resolved: {sent}"
    assert "Logged in." in out, f"the target never answered:\n{out}"

    configs = list((tmp_path / "configs").rglob("*.json"))
    assert configs, "no config was written"
    written = "\n".join(p.read_text() for p in configs)
    assert _LoginTarget.PASS not in written, "the password was written into the config"
    assert _LoginTarget.TOKEN not in written, \
        "the login token was frozen into the config instead of the repeatable recipe"
