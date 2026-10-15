"""
test_tunnel_command — `ascend tunnel` and `ascend app tunnel-keys`, through the real CLI, offline.

The agent is a fake executable on PATH that speaks the real one's formats — `check`'s status
lines, `key`'s paste form, `run`'s JSON events — and records every argv it was given, so each
test pins what the CLI SENDS to the agent as well as what it prints. A second fake stands in for
`docker` and hands the arguments after the image name to the same fake agent, so the Docker path
is exercised end to end without a daemon. The platform is the suite's fake HTTP, so the PATCH
`app tunnel-keys` sends and the record it reads back are both on the wire.

Pins:
  * every verb parses and answers --json with one envelope on stdout, for success and failure;
  * check streams the agent's lines, exits 0 on WAIT and 1 on FAIL, and refuses a bad allow
    entry before anything is spawned; it claims every line passed only when no line read WARN,
    and it reads the 0.1.4 agent's lines (played back from a capture): an app URL in the scheme
    the agent found the target answering in is said as found, never as assumed;
  * --env resolves to the endpoint (and follows --base when not given), --relay / --host-key
    override it, and the agent's state directory is always passed explicitly;
  * key prints exactly what the agent printed and never the private half;
  * start / ls / logs / stop run on the bridge supervisor's contract (pid, log, status), a
    double start is refused with the pid, a start-up death is reported with the exit code, and
    Windows is refused before anything is spawned;
  * the Docker runner's argv mounts the state directory and names the container, and the
    container is removed by name on stop;
  * app tunnel-keys keeps every other template key, validates the line the engine's way, caps
    the list at 20, treats a listed key as a no-op, refuses an unlisted removal and a bridge app,
    and reports a PATCH that did not land;
  * the identity does not move with the tenant pin: in a fresh home, `check` (no platform call),
    then `app tunnel-keys --add` (the PAT exchange pins the tenant), then `key` report ONE agent
    id and leave ONE key file; a tunnel started before the pin is still in `ls` after it; a key an
    earlier CLI left under a tenant's state dir is adopted, and a second one is kept and named.
    The fake agent's FAKE_TUNNEL_MINT mode makes one identity per state directory, as the real
    agent does — the fixed vector could not tell two directories apart.
"""
import base64
import hashlib
import json
import os
import re
import shutil
import stat
import struct
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest

from conftest import FakeResponse, install_fake_requests

REPO = Path(__file__).resolve().parents[1]
for _p in ("control", "runtime", "shells/cli"):
    if str(REPO / _p) not in sys.path:
        sys.path.insert(0, str(REPO / _p))
import ascend  # noqa: E402
import tunnel as T  # noqa: E402

KEY_BLOB = "AAAAC3NzaC1lZDI1NTE5AAAAIOUCMT9hLrSSmTyPYnU+xGO8/gCs7AZy1c9ssMyLd6Mw"
KEY_LINE = "ssh-ed25519 " + KEY_BLOB
KEY_ID = "520de864"
OTHER_LINE = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAOhB7/zzhC+HXDdGOdLwJln5NYwm6UNXx3chmQSVTG4"
OTHER_ID = "95b9aca0"
PRIVATE = "-----BEGIN OPENSSH PRIVATE KEY-----\nFAKEPRIVATEHALF\n-----END OPENSSH PRIVATE KEY-----\n"

# The fake agent. Its outputs are the real agent's format strings (internal/agent/check.go,
# cmd/ascend-tunnel/main.go, internal/agent/agent.go), with the vector key above.
FAKE_AGENT = textwrap.dedent(f'''\
    #!{sys.executable}
    import json, os, signal, sys, time
    KEY = {KEY_BLOB!r}
    args = sys.argv[1:]
    rec = os.environ.get("FAKE_TUNNEL_RECORD")
    if rec:
        with open(rec, "a") as fh:
            fh.write(json.dumps(args) + "\\n")
    cmd = args[0] if args and not args[0].startswith("-") else "run"

    def flag(name, multi=False):
        out = [args[i + 1] for i, a in enumerate(args) if a == name and i + 1 < len(args)]
        return out if multi else (out[0] if out else None)
    state = flag("--state-dir")
    if state:
        os.makedirs(state, exist_ok=True)
        kf = os.path.join(state, "agent.key")
        if os.environ.get("FAKE_TUNNEL_MINT"):
            # As the real agent: one identity per state directory, made on first use and read
            # back after. The public blob rides on the second line of the fake private file.
            import base64, hashlib, struct
            lines = open(kf).read().splitlines() if os.path.exists(kf) else []
            KEY = lines[1] if len(lines) > 2 and lines[1].startswith("AAAAC3NzaC1lZDI1NTE5") else None
            if not KEY:
                KEY = base64.b64encode(struct.pack(">I", 11) + b"ssh-ed25519"
                                       + struct.pack(">I", 32) + os.urandom(32)).decode()
                with open(kf, "w") as fh:
                    fh.write("-----BEGIN OPENSSH PRIVATE KEY-----\\n" + KEY
                             + "\\nFAKEPRIVATEHALF\\n-----END OPENSSH PRIVATE KEY-----\\n")
        else:
            with open(kf, "w") as fh:
                fh.write({PRIVATE!r})
    import base64 as _b64, hashlib as _sha
    AID = _sha.sha256(_b64.b64decode(KEY)).hexdigest()[:8]      # the agent's rule for its id
    org, allows = flag("--org"), flag("--allow", multi=True)
    endpoint = flag("--relay") or "wss://ascendai-bridge.prod.straiker.ai/tunnel"

    def addr(a):
        host, _, port = a.partition(":")
        return host, int(port or 443)

    def app_url(a):
        host, port = addr(a)
        return ("http" if port == 80 else "https") + "://" + host + ".tun.straiker.ai"
    if cmd == "key":
        print(KEY)
        print("# agent id %s: paste the line above into each Ascend app\'s _tunnel_agent_keys" % AID,
              file=sys.stderr)
        sys.exit(0)
    if cmd == "check":
        canned = os.environ.get("FAKE_TUNNEL_CHECK_OUT")
        if canned:
            # A real agent's stdout, captured into the fixtures directory, played back.
            sys.stdout.write(open(canned).read())
            sys.exit(int(os.environ.get("FAKE_TUNNEL_CHECK_RC", "0")))
        if not org or not allows:
            print("ascend-tunnel: tenant (your Straiker org id) is required", file=sys.stderr)
            sys.exit(2)
        print("INFO  org %s, agent %s" % (org, AID))
        print("INFO  agent key (paste into the app\'s _tunnel_agent_keys): " + KEY)
        for a in allows:
            print("INFO  app URL for %s:%d: %s/... (the Ascend app\'s URL, with its path)" % (*addr(a), app_url(a)))
        print("INFO  relay %s, direct (no HTTPS_PROXY)" % endpoint)
        if os.environ.get("FAKE_TUNNEL_FAIL"):
            print("FAIL  relay WebSocket: dial tcp: i/o timeout (allow outbound HTTPS to it; set HTTPS_PROXY if you use a proxy)")
            sys.exit(1)
        if os.environ.get("FAKE_TUNNEL_UPGRADE"):
            # MEASURED 2026-10-13 against prod with the 0.1.2 agent, word for word.
            print("FAIL  relay WebSocket: relay %s: failed to WebSocket dial: expected handshake response status code 101 but got %s (allow outbound HTTPS to it; set HTTPS_PROXY if you use a proxy)" % (endpoint, os.environ["FAKE_TUNNEL_UPGRADE"]))
            for a in allows:
                print("PASS  target %s:%d reachable" % addr(a))
            sys.exit(1)
        print("PASS  relay WebSocket upgraded over HTTPS")
        if flag("--host-key"):
            print("PASS  relay host key matches the pinned key")
        else:
            print("WARN  relay host key SHA256:abc is not pinned (set host_key)")
        if os.environ.get("FAKE_TUNNEL_LISTED"):
            print("PASS  an Ascend app lists this agent\'s key: the relay accepts it")
        else:
            print("WAIT  no Ascend app lists this agent\'s key yet: paste it into the app, then test the connection")
        for a in allows:
            print("PASS  target %s:%d reachable" % addr(a))
        sys.exit(0)
    if cmd == "run":
        if os.environ.get("FAKE_TUNNEL_DIE"):
            print("ascend-tunnel: tenant (your Straiker org id) is required", file=sys.stderr)
            sys.exit(2)
        print(json.dumps({{"ts": "2026-10-09T00:00:00.000000+00:00", "event": "identity", "tenant": org,
                          "agent_id": AID, "agent_key": KEY, "app_urls": [app_url(a) for a in allows],
                          "hint": "paste agent_key into each Ascend app\'s _tunnel_agent_keys"}}), flush=True)
        print(json.dumps({{"ts": "2026-10-09T00:00:01.000000+00:00", "event": "waiting", "link": 0,
                          "agent_id": AID, "retry_every_s": 5,
                          "error": "no Ascend app lists this agent\'s key in _tunnel_agent_keys yet (or it was removed)"}}), flush=True)
        signal.signal(signal.SIGTERM, lambda *a: sys.exit(0))
        while True:
            time.sleep(0.2)
    print("unknown command %r" % cmd, file=sys.stderr)
    sys.exit(2)
''')

# A fake `docker`: answers the probes the CLI makes, records its argv, and hands the arguments
# after the image name to the fake agent.
FAKE_DOCKER = textwrap.dedent(f'''\
    #!{sys.executable}
    import json, os, subprocess, sys
    args = sys.argv[1:]
    rec = os.environ.get("FAKE_DOCKER_RECORD")
    if rec:
        with open(rec, "a") as fh:
            fh.write(json.dumps(args) + "\\n")
    if args[:1] == ["version"]:
        print("28.4.0"); sys.exit(0)
    if args[:2] == ["image", "inspect"]:
        sys.exit(1 if os.environ.get("FAKE_DOCKER_NO_IMAGE") else 0)
    if args[:1] == ["pull"]:
        sys.exit(0)
    if args[:1] == ["rm"]:
        sys.exit(0)
    if args[:1] == ["run"]:
        i = args.index({T.IMAGE!r})
        vols = {{}}
        for j, a in enumerate(args[:i]):
            if a == "-v" and j + 1 < i:
                host, _, cont = args[j + 1].partition(":")
                vols[cont.split(":")[0]] = host
        rest = [vols.get(a, a) for a in args[i + 1:]]
        os.execv(os.environ["FAKE_AGENT_PATH"], [os.environ["FAKE_AGENT_PATH"]] + rest)
    sys.exit(2)
''')


def _install(path: Path, source: str) -> Path:
    path.write_text(source)
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


@pytest.fixture
def state(tmp_path, monkeypatch):
    """An isolated CLI state dir, a short start-up watch, and no proxy in the environment."""
    monkeypatch.setenv("ASCEND_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("ASCEND_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("ASCEND_STARTUP_GRACE_S", "3")
    monkeypatch.setenv("STRAIKER_PAT", "s6r_pat_test")
    monkeypatch.setenv("ASCEND_SKIP_TENANT_CHECK", "1")
    monkeypatch.setenv("ASCEND_NO_CACHE", "1")
    monkeypatch.setenv("NO_COLOR", "1")
    for v in ("TUNNEL_STATE_DIR", "STRAIKER_API_BASE", "FAKE_TUNNEL_FAIL", "FAKE_TUNNEL_LISTED",
              "FAKE_TUNNEL_DIE", "FAKE_TUNNEL_MINT", "FAKE_TUNNEL_UPGRADE", "FAKE_DOCKER_NO_IMAGE",
              "FAKE_TUNNEL_CHECK_OUT", "FAKE_TUNNEL_CHECK_RC", *T.PROXY_VARS):
        monkeypatch.delenv(v, raising=False)
    # The binary's own default directory is the real home's (~/Library/… on macOS): never let a
    # test read or write it. An empty stand-in means "the binary never ran here" unless a test
    # puts a key there on purpose.
    monkeypatch.setattr(T, "binary_default_state_dir", lambda: tmp_path / "binary-default")
    return tmp_path / "state"


@pytest.fixture
def agent(tmp_path, monkeypatch, state):
    """The fake agent on PATH (and nothing else of ours), recording its argv."""
    d = tmp_path / "bin"
    d.mkdir()
    path = _install(d / "ascend-tunnel", FAKE_AGENT)
    rec = tmp_path / "agent-argv.jsonl"
    monkeypatch.setenv("FAKE_TUNNEL_RECORD", str(rec))
    monkeypatch.setenv("PATH", f"{d}:/usr/bin:/bin")

    class Agent:
        bin = path

        @staticmethod
        def argv():
            return [json.loads(l) for l in rec.read_text().splitlines()] if rec.exists() else []
    return Agent


@pytest.fixture
def docker(tmp_path, monkeypatch, state):
    """A fake docker on PATH and NO agent on PATH, so the runner falls through to Docker."""
    d = tmp_path / "dbin"
    d.mkdir()
    agent_path = _install(tmp_path / "elsewhere-ascend-tunnel", FAKE_AGENT)   # not on PATH
    _install(d / "docker", FAKE_DOCKER)
    rec, arec = tmp_path / "docker-argv.jsonl", tmp_path / "agent-argv.jsonl"
    monkeypatch.setenv("FAKE_DOCKER_RECORD", str(rec))
    monkeypatch.setenv("FAKE_TUNNEL_RECORD", str(arec))
    monkeypatch.setenv("FAKE_AGENT_PATH", str(agent_path))
    monkeypatch.setenv("PATH", f"{d}:/usr/bin:/bin")

    class Docker:
        @staticmethod
        def argv():
            return [json.loads(l) for l in rec.read_text().splitlines()] if rec.exists() else []

        @staticmethod
        def agent_argv():
            return [json.loads(l) for l in arec.read_text().splitlines()] if arec.exists() else []
    return Docker


@pytest.fixture
def cli(capsys, monkeypatch):
    """The CLI in-process through its real entry point: (exit code, stdout, stderr)."""
    def run(argv):
        monkeypatch.setattr(sys, "argv", ["ascend", *argv])
        code = 0
        try:
            ascend._run()
        except SystemExit as e:
            code = e.code or 0
        out, err = capsys.readouterr()
        return code, out, err
    return run


def _stop_all(cli):
    cli(["tunnel", "stop", "--all", "--json"])


# --------------------------------------------------------------------------- parser wiring
@pytest.mark.parametrize("verb", ["check", "key", "start", "ls", "stop", "logs", "url"])
def test_every_tunnel_verb_has_help(cli, verb):
    code, out, _ = cli(["tunnel", verb, "--help"])
    assert code == 0 and f"tunnel {verb}" in out and "--json" in out


def test_app_tunnel_keys_is_wired(cli):
    code, out, _ = cli(["app", "tunnel-keys", "--help"])
    assert code == 0 and "--add" in out and "--remove" in out and "--list" in out


def test_the_group_help_says_what_a_tunnel_is_and_is_not(cli):
    code, out, _ = cli(["tunnel", "--help"])
    assert code == 0
    assert "https://<host>.tun.straiker.ai/<path>" in out
    assert "(L4)" in out and "(L7)" in out and "github.com/straiker-ai/ascend-tunnel" in out


def test_ciphertext_is_claimed_for_a_tls_target_only(cli):
    """Behind http:// Straiker relays a plain-HTTP app's bytes as they are, inside the agent's
    TLS link (MEASURED 2026-10-14), and the agent writes them to the target as plain HTTP. So
    "the agent sees only ciphertext" holds for a TLS target only: every sentence that says it,
    in the group help, the module note or a tracked text file, limits it to TLS in the same
    clause and says what a plain-HTTP target's traffic is. The group help, the glossary and the
    module note said it of every target. Only tracked files are read: an untracked virtualenv
    in the checkout is not shipped."""
    code, out, _ = cli(["tunnel", "--help"])
    assert code == 0
    texts = {"ascend tunnel --help": out, "runtime/tunnel.py": T.__doc__}
    tracked = subprocess.run(["git", "ls-files", "-z", "--", "*.md", "*.mdx", "*.html", "*.txt"],
                             cwd=REPO, capture_output=True, text=True, check=True).stdout
    for rel in filter(None, tracked.split("\0")):
        texts[rel] = (REPO / rel).read_text(encoding="utf-8", errors="ignore")
    said = set()
    for name, text in texts.items():
        for sentence in re.split(r"(?<=\.)\s+", " ".join(text.split())):
            if "ciphertext" in sentence:
                said.add(name)
                assert re.search(r"ciphertext (?:for|when|from)\b[^;.]{0,40}\bTLS\b", sentence) \
                    and "plain-HTTP" in sentence, f"{name}: {sentence}"
    # the texts that say it are among those read, so a pass is not a pattern that matched nothing
    assert {"ascend tunnel --help", "runtime/tunnel.py", "docs/GLOSSARY.md"} <= said


def test_check_needs_org_and_the_usage_error_is_an_envelope(cli, agent):
    code, out, err = cli(["tunnel", "check", "--allow", "chat.corp.internal", "--json"])
    assert code == ascend.EXIT_USAGE
    assert json.loads(out)["ok"] is False and "--org" in err
    assert agent.argv() == []


# --------------------------------------------------------------------------- url (offline)
def test_url_json_envelope_and_the_rule(cli):
    code, out, _ = cli(["tunnel", "url", "https://api.corp.internal:8080/v1/chat", "--json"])
    assert code == 0
    env = json.loads(out)
    assert env["ok"] is True
    assert env["data"]["url"] == "https://api.corp.internal.tun.straiker.ai/v1/chat"
    assert env["data"]["allow"] == "api.corp.internal:8080" and env["data"]["port_moved"] is True


def test_url_refuses_an_ip_with_an_envelope(cli):
    code, out, err = cli(["tunnel", "url", "10.0.0.5:8080", "--json"])
    assert code == ascend.EXIT_USAGE
    env = json.loads(out)
    assert env["ok"] is False and env["error"]["code"] == "bad_target"
    assert "Straiker does not route an IP-literal tunnel name" in env["error"]["message"]
    assert "Straiker does not route an IP-literal tunnel name" in err


def test_url_plain_output(cli):
    code, out, _ = cli(["tunnel", "url", "plain.corp.internal:80", "--path", "/chat"])
    assert code == 0
    assert "URL      http://plain.corp.internal.tun.straiker.ai/chat" in out
    assert "allow    --allow plain.corp.internal:80" in out
    assert "no port in the URL" in out and "never an IP address" in out
    assert "any other port is https" not in out, "the old rule, which sent plain HTTP off 80 to https://"


def _scheme_lines(text):
    return [ln for ln in text.splitlines() if ln.lstrip().startswith("scheme ")]


def test_url_keeps_a_plain_http_targets_scheme_on_any_port(cli):
    """MEASURED 2026-10-14 on a live tunnel: a plain-HTTP target on 8089 needs http:// on its
    tunnel name (https:// makes Straiker start TLS with it). This printed https://."""
    code, out, _ = cli(["tunnel", "url", "http://localhost:8089", "--json"])
    assert code == 0
    d = json.loads(out)["data"]
    assert d["url"] == "http://localhost.tun.straiker.ai/<path>" and d["scheme"] == "http"
    assert d["allow"] == "localhost:8089" and d["port_moved"] is True
    assert d["scheme_given"] is True and d["hint"] is None
    code, out, _ = cli(["tunnel", "url", "http://localhost:8089"])
    assert code == 0
    assert "URL      http://localhost.tun.straiker.ai/<path>" in out
    assert "allow    --allow localhost:8089" in out and "https://localhost" not in out
    assert _scheme_lines(out) == []
    code, out, _ = cli(["tunnel", "url", "https://api.corp.internal:8443/v1", "--json"])
    assert json.loads(out)["data"]["url"] == "https://api.corp.internal.tun.straiker.ai/v1"


def test_url_a_bare_host_port_says_the_scheme_is_assumed(cli):
    code, out, _ = cli(["tunnel", "url", "api.corp.internal:8080", "--path", "/v1/chat"])
    assert code == 0
    assert "URL      https://api.corp.internal.tun.straiker.ai/v1/chat" in out      # the default stays
    [line] = _scheme_lines(out)
    assert "https:// is assumed on port 8080" in line
    assert line.endswith("http://api.corp.internal.tun.straiker.ai/v1/chat")
    code, out, _ = cli(["tunnel", "url", "api.corp.internal:8080", "--json"])
    d = json.loads(out)["data"]
    assert d["scheme_given"] is False and d["hint"].endswith("http://api.corp.internal.tun.straiker.ai/<path>")
    for settled in ("chat.corp.internal", "chat.corp.internal:443", "plain.corp.internal:80"):
        code, out, _ = cli(["tunnel", "url", settled])
        assert code == 0 and _scheme_lines(out) == [], settled


def test_check_says_when_an_app_urls_scheme_is_assumed(cli, agent, state):
    """The 0.1.2 agent prints https:// for a plain-HTTP target off 80 and warns of nothing
    (MEASURED 2026-10-14), so the CLI says the scheme is a guess, once per such entry."""
    code, out, err = cli(["tunnel", "check", "--org", "123", "--allow", "chat.corp.internal",
                          "--allow", "localhost:8089", "--env", "dev"])
    assert code == 0, err
    [line] = _scheme_lines(out)
    assert "https:// is assumed on port 8089" in line and line.endswith("http://localhost.tun.straiker.ai/<path>")
    assert out.index("PASS  target localhost:8089 reachable") < out.index(line) < out.index("check passed")


def test_check_with_the_0_1_4_agent_says_the_scheme_it_found(cli, agent, monkeypatch):
    """MEASURED 2026-10-14 with the v0.1.4 release binary on PATH (the runner the CLI picks
    first), against a plain-HTTP server on 127.0.0.1:18089: the agent printed its app line in a
    new form and WARNed `answers plain HTTP, not TLS`, and the CLI went on to print the 0.1.0
    fallback's https:// URL as "the app's URL", call the scheme assumed, and say every line
    passed. The played-back stdout is that agent's, word for word but for its state directory."""
    monkeypatch.setenv("FAKE_TUNNEL_CHECK_OUT",
                       str(REPO / "tests" / "fixtures" / "tunnel_check_0.1.4_plain_http.txt"))
    argv = ["tunnel", "check", "--org", "123", "--allow", "localhost:18089", "--env", "stage"]
    code, out, err = cli(argv)
    assert code == 0, err
    assert "WARN   target    localhost:18089 answers plain HTTP, not TLS" in out   # streamed as is
    mine = out[out.rindex("RESULT PASS"):]               # what the CLI says after the agent's lines
    assert "https://" not in mine
    assert ("app URL for localhost:18089: http://localhost.tun.straiker.ai/<path>   <- the app's "
            "URL, plus its path: the agent found plain HTTP there") in mine
    assert _scheme_lines(out) == []                      # found, so not "assumed"
    assert "every line PASS" not in out
    assert "check passed, but 1 line(s) read WARN: read them above. Run the agent:" in mine
    code, out, _ = cli(argv + ["--json"])
    d = json.loads(out)["data"]
    assert d["app_urls"] == ["http://localhost.tun.straiker.ai"]
    assert d["schemes_found"] == {"localhost:18089": "http"}
    assert d["passed"] is True and d["counts"]["WARN"] == 1


def test_check_reads_every_outcome_of_the_0_1_4_agents_target_probe(cli, agent, monkeypatch):
    """One check over six targets, captured from the published 0.1.4 image (see
    test_tunnel_rules.CHECK_014). Where the agent found the target in the other scheme than the
    port's default, the app's URL is said as found; where it found the port's own, nothing is
    added; where it found none (a target that answered neither clearly, one it could not reach),
    the CLI's "assumed" line stays."""
    monkeypatch.setenv("FAKE_TUNNEL_CHECK_OUT",
                       str(REPO / "tests" / "fixtures" / "tunnel_check_0.1.4_targets.txt"))
    monkeypatch.setenv("FAKE_TUNNEL_CHECK_RC", "1")       # the agent exits 1: one target is down
    allow = ["plain.corp.internal:8089", "tls.corp.internal:8443", "tls80.corp.internal:80",
             "web.corp.internal:80", "raw.corp.internal:9000", "down.corp.internal:9999"]
    argv = ["tunnel", "check", "--org", "123", "--env", "stage"] + [x for a in allow for x in ("--allow", a)]
    code, out, _ = cli(argv)
    assert code == ascend.EXIT_ERROR and "check failed: 1 line(s) read FAIL" in out
    mine = out[out.rindex("RESULT FAIL"):]
    assert ("app URL for plain.corp.internal:8089: http://plain.corp.internal.tun.straiker.ai/<path>"
            "   <- the app's URL, plus its path: the agent found plain HTTP there") in mine
    assert ("app URL for tls80.corp.internal:80: https://tls80.corp.internal.tun.straiker.ai/<path>"
            "   <- the app's URL, plus its path: the agent found TLS there") in mine
    assert "tls.corp.internal" not in mine and "web.corp.internal" not in mine
    raw, down = _scheme_lines(mine)
    assert "https:// is assumed on port 9000" in raw and raw.endswith("http://raw.corp.internal.tun.straiker.ai/<path>")
    assert "https:// is assumed on port 9999" in down
    code, out, _ = cli(argv + ["--json"])
    d = json.loads(out)["data"]
    assert d["app_urls"] == ["http://plain.corp.internal.tun.straiker.ai",
                             "https://tls.corp.internal.tun.straiker.ai",
                             "https://tls80.corp.internal.tun.straiker.ai",
                             "http://web.corp.internal.tun.straiker.ai",
                             "https://raw.corp.internal.tun.straiker.ai",
                             "https://down.corp.internal.tun.straiker.ai"]
    assert d["schemes_found"] == {"plain.corp.internal:8089": "http", "tls.corp.internal:8443": "https",
                                  "tls80.corp.internal:80": "https", "web.corp.internal:80": "http"}
    assert d["passed"] is False and d["failed"] == 1


def test_start_says_when_an_app_urls_scheme_is_assumed(cli, agent, state):
    try:
        code, out, err = cli(["tunnel", "start", "--org", "123", "--allow", "chat.corp.internal",
                              "--allow", "localhost:8089", "--env", "dev"])
        assert code == 0, err
        [line] = _scheme_lines(out)
        assert "https:// is assumed on port 8089" in line and line.endswith("http://localhost.tun.straiker.ai/<path>")
        lines = out.splitlines()
        url_line = next(i for i, ln in enumerate(lines) if "app URL  https://localhost.tun.straiker.ai/<path>" in ln)
        assert lines[url_line + 1] == line, "the hint sits under the app URL it is about"
        code, out, _ = cli(["tunnel", "ls"])                 # where the URL is looked up later
        assert code == 0
        [line] = _scheme_lines(out)
        assert "https:// is assumed on port 8089" in line and line.endswith("http://localhost.tun.straiker.ai/<path>")
    finally:
        _stop_all(cli)


def test_a_foreground_start_says_it_too(cli, agent, state, monkeypatch):
    monkeypatch.setenv("FAKE_TUNNEL_DIE", "1")          # the fake agent exits at once
    code, out, err = cli(["tunnel", "start", "--org", "123", "--allow", "localhost:8089", "--foreground"])
    assert code == 2
    assert "app URL for localhost:8089: https://localhost.tun.straiker.ai/<path>" in err
    [line] = _scheme_lines(err)
    assert "https:// is assumed on port 8089" in line


# --------------------------------------------------------------------------- check
def test_check_streams_the_agents_lines_and_wait_is_exit_0(cli, agent, state):
    code, out, err = cli(["tunnel", "check", "--org", "123", "--allow", "localhost:8080", "--env", "dev"])
    assert code == 0, err
    assert "PASS  relay WebSocket upgraded over HTTPS" in out
    assert "WAIT  no Ascend app lists this agent's key yet" in out
    assert "PASS  target localhost:8080 reachable" in out
    assert "check passed. WAIT on the key line is expected" in out
    assert f"using ascend-tunnel at {agent.bin}" in err
    [argv] = agent.argv()
    assert argv[0] == "check"
    assert argv[argv.index("--org") + 1] == "123"
    assert argv[argv.index("--allow") + 1] == "localhost:8080"
    assert argv[argv.index("--relay") + 1] == "wss://ascendai-bridge.dev.straiker.ai/tunnel"
    assert "--host-key" not in argv                                   # none published for dev
    assert argv[argv.index("--state-dir") + 1] == str(T.agent_state_dir())


def test_check_passes_fanout_and_refuses_it_out_of_range(cli, agent):
    code, out, err = cli(["tunnel", "check", "--org", "123", "--allow", "a.corp", "--fanout", "4", "--json"])
    assert code == 0, err
    [argv] = agent.argv()
    assert argv[argv.index("--fanout") + 1] == "4" and argv[-2:] == ["--fanout", "4"]
    assert json.loads(out)["data"]["fanout"] == 4
    for bad in ("0", "17"):
        code, out, _ = cli(["tunnel", "check", "--org", "123", "--allow", "a.corp", "--fanout", bad, "--json"])
        assert code == ascend.EXIT_USAGE and json.loads(out)["error"]["code"] == "bad_fanout"
        assert "fanout must be 1..16" in json.loads(out)["error"]["message"]
    assert len(agent.argv()) == 1, "nothing spawned for a bad fanout"


def test_check_on_stage_dials_the_real_relay_with_its_key_pinned(cli, agent):
    code, out, err = cli(["tunnel", "check", "--org", "123", "--allow", "a.corp", "--env", "stage"])
    assert code == 0, err
    [argv] = agent.argv()
    assert argv[argv.index("--relay") + 1] == "wss://ascendai-bridge.stage.straiker.ai/tunnel"
    assert argv[argv.index("--host-key") + 1] == T.STAGE_HOST_KEY
    assert "PASS  relay host key matches the pinned key" in out


def test_a_prod_403_at_the_upgrade_says_the_tunnel_is_not_enabled_there(cli, agent, monkeypatch):
    """MEASURED: prod's relay answers 403 at the WebSocket upgrade while the tunnel is off there.
    The generic proxy hint blamed the operator's network; now the check says what it is."""
    monkeypatch.setenv("FAKE_TUNNEL_UPGRADE", "403")
    code, out, err = cli(["tunnel", "check", "--org", "123", "--allow", "a.corp", "--env", "prod"])
    assert code == ascend.EXIT_ERROR
    assert "check failed: the tunnel is not enabled on this environment yet" in out
    assert "--env stage" in out and "Send the lines above" not in out
    code, out, _ = cli(["tunnel", "check", "--org", "123", "--allow", "a.corp", "--env", "prod", "--json"])
    env = json.loads(out)
    assert env["ok"] is False and env["error"]["code"] == "tunnel_not_enabled"
    assert "not enabled on this environment yet" in env["error"]["message"]
    assert env["data"]["relay_status"] == 403 and env["data"]["tunnel_enabled"] is False


@pytest.mark.parametrize("env_name,upgrade,fail", [("dev", "403", None), ("stage", "403", None),
                                                    ("prod", "502", None), ("prod", None, "1")])
def test_any_other_environment_or_failure_keeps_the_generic_hint(cli, agent, monkeypatch, env_name, upgrade, fail):
    if upgrade:
        monkeypatch.setenv("FAKE_TUNNEL_UPGRADE", upgrade)
    if fail:
        monkeypatch.setenv("FAKE_TUNNEL_FAIL", fail)
    code, out, _ = cli(["tunnel", "check", "--org", "123", "--allow", "a.corp", "--env", env_name])
    assert code == ascend.EXIT_ERROR
    assert "Send the lines above to support@straiker.ai" in out and "not enabled" not in out
    code, out, _ = cli(["tunnel", "check", "--org", "123", "--allow", "a.corp", "--env", env_name, "--json"])
    env = json.loads(out)
    assert env["error"]["code"] == "check_failed" and env["data"]["tunnel_enabled"] is True


def test_a_key_the_binary_made_by_hand_is_the_identity_used_and_said(cli, agent, state, tmp_path):
    """A customer ran `ascend-tunnel` per its README first: its key sits in the binary's default
    directory and is what the app lists. The CLI used to pass its own empty directory, mint a
    second identity, and wait forever."""
    default = T.binary_default_state_dir()
    default.mkdir(parents=True)
    (default / "agent.key").write_text(PRIVATE)
    code, out, err = cli(["tunnel", "check", "--org", "123", "--allow", "a.corp"])
    assert code == 0, err
    [argv] = agent.argv()
    assert argv[argv.index("--state-dir") + 1] == str(default)
    assert f"using the identity at {default}" in err and "run by hand" in err
    code, out, _ = cli(["tunnel", "key", "--json"])
    env = json.loads(out)
    assert env["data"]["state_dir"] == str(default) and env["data"]["identity_source"] == "binary-default"
    assert not (state / "tunnel" / "agent" / "agent.key").exists(), "no second identity was minted"


def test_two_identities_keep_the_clis_and_name_the_other(cli, agent, state):
    default = T.binary_default_state_dir()
    default.mkdir(parents=True)
    (default / "agent.key").write_text(PRIVATE)
    cli_dir = state / "tunnel" / "agent"
    cli_dir.mkdir(parents=True)
    (cli_dir / "agent.key").write_text(PRIVATE)
    code, out, err = cli(["tunnel", "check", "--org", "123", "--allow", "a.corp", "--json"])
    assert code == 0
    [argv] = agent.argv()
    assert argv[argv.index("--state-dir") + 1] == str(cli_dir)
    assert f"another identity exists at {default}" in err and f"--state-dir {default}" in err
    assert json.loads(out)["data"]["identity_source"] == "cli"
    code, out, err = cli(["tunnel", "check", "--org", "123", "--allow", "a.corp", "--state-dir", str(default)])
    assert code == 0 and "another identity" not in err
    assert agent.argv()[-1][argv.index("--state-dir") + 1] == str(default)


def test_check_json_envelope(cli, agent):
    code, out, _ = cli(["tunnel", "check", "--org", "123", "--allow", "chat.corp.internal",
                        "--allow", "api.corp.internal:8080", "--json"])
    assert code == 0
    env = json.loads(out)                                             # exactly one object on stdout
    assert env["ok"] is True
    d = env["data"]
    assert d["runner"] == {"kind": "binary", "path": str(agent.bin)}
    assert d["env"] == "prod" and d["endpoint"] == "wss://ascendai-bridge.prod.straiker.ai/tunnel"
    assert d["key"] == KEY_BLOB and d["agent_id"] == KEY_ID
    assert d["app_urls"] == ["https://chat.corp.internal.tun.straiker.ai",
                             "https://api.corp.internal.tun.straiker.ai"]
    assert d["allow"] == ["chat.corp.internal:443", "api.corp.internal:8080"]
    assert d["passed"] is True and d["waiting"] is True and d["listed"] is False
    assert d["counts"]["FAIL"] == 0 and d["exit_code"] == 0
    assert [l["status"] for l in d["lines"]].count("PASS") == 3


def test_check_fail_exits_1_with_the_envelope(cli, agent, monkeypatch):
    monkeypatch.setenv("FAKE_TUNNEL_FAIL", "1")
    code, out, _ = cli(["tunnel", "check", "--org", "123", "--allow", "chat.corp.internal", "--json"])
    assert code == ascend.EXIT_ERROR
    env = json.loads(out)
    assert env["ok"] is False and env["error"]["code"] == "check_failed"
    assert env["data"]["failed"] == 1 and env["data"]["passed"] is False
    code, out, _ = cli(["tunnel", "check", "--org", "123", "--allow", "chat.corp.internal"])
    assert code == ascend.EXIT_ERROR and "check failed: 1 line(s) read FAIL" in out


def test_check_says_every_line_passed_only_when_every_line_did(cli, agent, monkeypatch):
    """This said "every line PASS" over the agent's WARN: prod publishes no host key yet, so
    the agent warns that the relay's key is not pinned."""
    monkeypatch.setenv("FAKE_TUNNEL_LISTED", "1")
    code, out, _ = cli(["tunnel", "check", "--org", "123", "--allow", "chat.corp.internal", "--env", "stage"])
    assert code == 0 and "WARN" not in out and "check passed: every line PASS" in out
    code, out, _ = cli(["tunnel", "check", "--org", "123", "--allow", "chat.corp.internal"])
    assert code == 0 and "WARN  relay host key SHA256:abc is not pinned (set host_key)" in out
    assert "every line PASS" not in out
    assert "check passed, but 1 line(s) read WARN: read them above. Run the agent:  ascend tunnel start" in out
    monkeypatch.delenv("FAKE_TUNNEL_LISTED")             # WAIT as well: both are said
    code, out, _ = cli(["tunnel", "check", "--org", "123", "--allow", "chat.corp.internal"])
    assert code == 0 and "check passed. WAIT on the key line is expected" in out
    assert "  1 line(s) read WARN: read them above." in out and "every line PASS" not in out


def test_check_refuses_a_bad_allow_entry_before_spawning(cli, agent):
    for bad in (["--allow", "10.0.0.5:8080"], ["--allow", "a.corp", "--allow", "a.corp:8080"]):
        code, out, _ = cli(["tunnel", "check", "--org", "123", *bad, "--json"])
        assert code == ascend.EXIT_USAGE
        assert json.loads(out)["error"]["code"] == "bad_allow"
    assert agent.argv() == []                                          # nothing was run


def test_check_passes_an_explicit_endpoint_and_host_key(cli, agent):
    code, _, _ = cli(["tunnel", "check", "--org", "123", "--allow", "a.corp", "--env", "prod",
                      "--relay", "wss://relay.example/tunnel", "--host-key", "ssh-ed25519 AAAAtest"])
    assert code == 0
    [argv] = agent.argv()
    assert argv[argv.index("--relay") + 1] == "wss://relay.example/tunnel"
    assert argv[argv.index("--host-key") + 1] == "ssh-ed25519 AAAAtest"


def test_env_follows_base_when_not_given(cli, agent):
    code, _, _ = cli(["tunnel", "check", "--org", "123", "--allow", "a.corp",
                      "--base", "https://api.dev.straiker.ai/api/v3"])
    assert code == 0
    [argv] = agent.argv()
    assert argv[argv.index("--relay") + 1] == "wss://ascendai-bridge.dev.straiker.ai/tunnel"


def test_check_honours_tunnel_state_dir_and_the_flag(cli, agent, monkeypatch, tmp_path):
    monkeypatch.setenv("TUNNEL_STATE_DIR", str(tmp_path / "byhand"))
    cli(["tunnel", "check", "--org", "1", "--allow", "a.corp"])
    cli(["tunnel", "check", "--org", "1", "--allow", "a.corp", "--state-dir", str(tmp_path / "flag")])
    a, b = agent.argv()
    assert a[a.index("--state-dir") + 1] == str(tmp_path / "byhand")
    assert b[b.index("--state-dir") + 1] == str(tmp_path / "flag")


def test_a_non_wss_endpoint_is_refused_here(cli, agent):
    code, out, _ = cli(["tunnel", "check", "--org", "1", "--allow", "a.corp",
                        "--relay", "https://relay.example", "--json"])
    assert code == ascend.EXIT_USAGE and json.loads(out)["error"]["code"] == "bad_endpoint"
    assert agent.argv() == []


# --------------------------------------------------------------------------- key
def test_key_prints_the_public_key_and_never_the_private_half(cli, agent, state):
    code, out, err = cli(["tunnel", "key"])
    assert code == 0
    assert out == KEY_BLOB + "\n"
    private = (T.agent_state_dir() / "agent.key").read_text()     # the fake agent wrote it
    assert "FAKEPRIVATEHALF" in private
    assert "FAKEPRIVATEHALF" not in out + err and "PRIVATE KEY" not in out + err
    assert f"agent id {KEY_ID}" in err and "ascend app tunnel-keys" in err
    [argv] = agent.argv()
    assert argv == ["key", "--state-dir", str(T.agent_state_dir())]


def test_key_json(cli, agent, state):
    code, out, _ = cli(["tunnel", "key", "--json"])
    assert code == 0
    env = json.loads(out)
    assert env["ok"] is True
    assert env["data"]["key"] == KEY_BLOB and env["data"]["line"] == KEY_LINE
    assert env["data"]["type"] == "ssh-ed25519" and env["data"]["agent_id"] == KEY_ID
    assert env["data"]["state_dir"] == str(T.agent_state_dir())
    assert env["data"]["runner"]["kind"] == "binary"


# --------------------------------------------------------------------------- no runner
def test_neither_binary_nor_docker_names_the_install_paths(cli, monkeypatch, state):
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    monkeypatch.setattr(T, "find_runner",
                        lambda prefer="auto", **kw: (None, ["ascend-tunnel is not on PATH",
                                                            "docker is not installed"]))
    code, out, err = cli(["tunnel", "key", "--json"])
    assert code == ascend.EXIT_ERROR
    env = json.loads(out)
    assert env["ok"] is False and env["error"]["code"] == "no_tunnel_runner"
    assert f"docker pull {T.IMAGE}" in err and "releases" in err
    assert "shasum -a 256 -c checksums.txt" in err and "gh attestation verify" in err
    assert "xattr -d com.apple.quarantine" in err
    assert err.index("ascend-tunnel_<version>_<os>_<arch>.tar.gz") < err.index("brew install")
    assert "brew install straiker-ai/tap/ascend-tunnel        (when published)" in err


# --------------------------------------------------------------------------- start / ls / logs / stop
def test_start_ls_logs_stop_lifecycle(cli, agent, state):
    try:
        code, out, err = cli(["tunnel", "start", "--org", "123", "--allow", "chat.corp.internal",
                              "--allow", "api.corp.internal:8080", "--env", "dev"])
        assert code == 0, err
        assert "started  org 123 (dev)  pid=" in out
        assert f"key      {KEY_BLOB}   (agent id {KEY_ID})" in out
        assert "app URL  https://chat.corp.internal.tun.straiker.ai/<path>" in out
        assert "app URL  https://api.corp.internal.tun.straiker.ai/<path>" in out
        assert f"ascend app tunnel-keys <app> --add '{KEY_BLOB}'" in out
        [argv] = agent.argv()
        assert argv[0] == "run" and argv[argv.index("--relay") + 1] == "wss://ascendai-bridge.dev.straiker.ai/tunnel"
        # the supervisor's files, on the bridge's contract
        d = T.tunnel_dir()
        assert (d / "123-dev.pid").exists() and (d / "123-dev.log").exists() and (d / "123-dev.json").exists()
        pid = int((d / "123-dev.pid").read_text())
        st = json.loads((d / "123-dev.json").read_text())
        assert st["pid"] == pid and st["org"] == "123" and st["env"] == "dev"
        assert st["allow"] == ["chat.corp.internal:443", "api.corp.internal:8080"]
        assert st["identity"]["agent_id"] == KEY_ID and st["runner"]["kind"] == "binary"

        # a second start is refused and names the pid
        code, out, err = cli(["tunnel", "start", "--org", "123", "--allow", "chat.corp.internal",
                              "--env", "dev", "--json"])
        assert code == ascend.EXIT_ERROR
        env = json.loads(out)
        assert env["error"]["code"] == "tunnel_running" and "already running" in env["error"]["message"]
        assert len(agent.argv()) == 1                                 # nothing else was spawned

        code, out, _ = cli(["tunnel", "ls"])
        assert code == 0
        assert "serving" in out and "waiting" in out and "123" in out and "dev" in out
        assert "refused until an app lists its key AND Straiker uses that app once" in out
        assert "Test Connection" in out and KEY_BLOB in out
        assert "it is refused until one does" not in out
        assert st["fanout"] is None and "--fanout" not in argv
        code, out, _ = cli(["tunnel", "ls", "--json"])
        [row] = json.loads(out)["data"]["tunnels"]
        assert row["id"] == "123-dev" and row["state"] == "serving" and row["link"] == "waiting"
        assert row["pid"] == pid and row["key"] == KEY_BLOB and row["agent_id"] == KEY_ID
        assert row["app_urls"] == ["https://chat.corp.internal.tun.straiker.ai",
                                   "https://api.corp.internal.tun.straiker.ai"]

        code, out, _ = cli(["tunnel", "logs", "--json"])
        assert code == 0
        tail = json.loads(out)["data"]["tail"]
        assert '"event": "identity"' in tail and '"event": "waiting"' in tail
        code, out, _ = cli(["tunnel", "logs"])
        assert code == 0 and '"event": "identity"' in out

        code, out, _ = cli(["tunnel", "stop", "--json"])
        assert code == 0
        [r] = json.loads(out)["data"]["results"]
        assert r == {"id": "123-dev", "stopped": True, "pid": pid, "how": "SIGTERM"}
        assert not (d / "123-dev.pid").exists()
        assert not T.pid_alive(pid)
        code, out, _ = cli(["tunnel", "ls", "--json"])
        assert json.loads(out)["data"]["tunnels"] == []
    finally:
        _stop_all(cli)


def test_start_passes_fanout_records_it_and_says_when_the_key_works(cli, agent, state):
    try:
        code, out, err = cli(["tunnel", "start", "--org", "123", "--allow", "chat.corp.internal",
                              "--env", "dev", "--fanout", "8"])
        assert code == 0, err
        [argv] = agent.argv()
        assert argv[argv.index("--fanout") + 1] == "8"
        st = json.loads((T.tunnel_dir() / "123-dev.json").read_text())
        assert st["fanout"] == 8
        assert "becomes usable once the app lists it AND Straiker uses the app once" in out
        code, out, _ = cli(["tunnel", "ls", "--json"])
        [row] = json.loads(out)["data"]["tunnels"]
        assert row["id"] == "123-dev"
        code, out, _ = cli(["tunnel", "start", "--org", "124", "--allow", "chat.corp.internal",
                            "--env", "dev", "--fanout", "99", "--json"])
        assert code == ascend.EXIT_USAGE and json.loads(out)["error"]["code"] == "bad_fanout"
        assert len(agent.argv()) == 1
    finally:
        _stop_all(cli)


def test_start_json_envelope(cli, agent, state):
    try:
        code, out, _ = cli(["tunnel", "start", "--org", "7", "--allow", "a.corp:8443", "--json"])
        assert code == 0
        env = json.loads(out)
        assert env["ok"] is True
        d = env["data"]
        assert d["id"] == "7-prod" and d["pid"] and d["log"].endswith("7-prod.log")
        assert d["key"] == KEY_BLOB and d["agent_id"] == KEY_ID
        assert d["app_urls"] == ["https://a.corp.tun.straiker.ai"] and d["allow"] == ["a.corp:8443"]
        assert d["host_key_pinned"] is False and d["runner"]["kind"] == "binary"
    finally:
        _stop_all(cli)


def test_a_startup_death_is_reported_with_the_exit_code(cli, agent, state, monkeypatch):
    monkeypatch.setenv("FAKE_TUNNEL_DIE", "1")
    code, out, err = cli(["tunnel", "start", "--org", "123", "--allow", "a.corp", "--json"])
    assert code == ascend.EXIT_ERROR
    env = json.loads(out)
    assert env["error"]["code"] == "tunnel_start_failed"
    assert "exited at startup (code 2)" in env["error"]["message"]
    assert "org id) is required" in env["error"]["message"]           # the agent's last line
    assert not (T.tunnel_dir() / "123-prod.pid").exists()


def test_windows_is_refused_before_anything_is_spawned(cli, agent, monkeypatch):
    monkeypatch.setattr(T, "_on_windows", lambda: True)
    code, out, err = cli(["tunnel", "start", "--org", "1", "--allow", "a.corp", "--json"])
    assert code == ascend.EXIT_ERROR
    assert "macOS or Linux" in json.loads(out)["error"]["message"] and "--foreground" in err
    assert agent.argv() == []


def test_stop_and_logs_need_a_choice_among_several(cli, agent):
    try:
        assert cli(["tunnel", "start", "--org", "1", "--allow", "a.corp", "--env", "dev"])[0] == 0
        assert cli(["tunnel", "start", "--org", "2", "--allow", "b.corp", "--env", "dev"])[0] == 0
        code, out, err = cli(["tunnel", "stop", "--json"])
        assert code == ascend.EXIT_USAGE and "2 tunnels are recorded" in err and "--all" in err
        code, _, err = cli(["tunnel", "logs"])
        assert code == ascend.EXIT_USAGE and "--org" in err
        code, out, _ = cli(["tunnel", "logs", "--org", "2", "--json"])
        assert code == 0 and json.loads(out)["data"]["id"] == "2-dev"
        code, out, _ = cli(["tunnel", "stop", "--org", "1", "--env", "dev", "--json"])
        assert code == 0 and [r["id"] for r in json.loads(out)["data"]["results"]] == ["1-dev"]
        code, out, _ = cli(["tunnel", "stop", "--all", "--json"])
        assert code == 0 and [r["id"] for r in json.loads(out)["data"]["results"]] == ["2-dev"]
        code, out, _ = cli(["tunnel", "stop", "--org", "9", "--json"])
        assert code == ascend.EXIT_ERROR and json.loads(out)["error"]["code"] == "no_tunnels"
    finally:
        _stop_all(cli)


def test_ls_shows_a_dead_tunnel_and_stop_reaps_it(cli, agent, state):
    d = T.tunnel_dir()
    (d / "5-prod.pid").write_text("2000000")                           # no such process
    (d / "5-prod.json").write_text(json.dumps({"id": "5-prod", "org": "5", "env": "prod",
                                               "allow": ["a.corp:443"], "runner": {"kind": "binary"}}))
    code, out, _ = cli(["tunnel", "ls"])
    assert code == 0 and "dead" in out and "not running" in out
    code, out, _ = cli(["tunnel", "stop", "--json"])
    [r] = json.loads(out)["data"]["results"]
    assert r["stopped"] is False and "stale pidfile reaped" in r["reason"]
    assert not (d / "5-prod.pid").exists()


# --------------------------------------------------------------------------- the Docker runner
def test_docker_path_end_to_end(cli, docker, state, monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.corp:3128")
    code, out, err = cli(["tunnel", "check", "--org", "123", "--allow", "localhost:8080", "--env", "dev"])
    assert code == 0, err
    assert f"using docker image {T.IMAGE} (ascend-tunnel is not on PATH)" in err
    assert "localhost in --allow is the container's own loopback" in err
    assert "WAIT  no Ascend app lists this agent's key yet" in out
    calls = docker.argv()
    assert calls[0] == ["version", "--format", "{{.Server.Version}}"]
    assert calls[1] == ["image", "inspect", T.IMAGE]
    run = calls[2]
    assert run[:2] == ["run", "--rm"] and "--name" not in run       # check: no container name
    assert f"{T.agent_state_dir()}:{T.CONTAINER_STATE_DIR}" in run
    assert run[run.index("--user") + 1] == f"{os.getuid()}:{os.getgid()}"
    assert "HTTPS_PROXY" in run and "http://proxy.corp:3128" not in run
    assert run[run.index("--state-dir") + 1] == T.CONTAINER_STATE_DIR
    [argv] = docker.agent_argv()
    assert argv[:1] == ["check"] and argv[argv.index("--state-dir") + 1] == str(T.agent_state_dir())
    assert argv[argv.index("--relay") + 1] == "wss://ascendai-bridge.dev.straiker.ai/tunnel"


def test_docker_image_is_pulled_once_when_missing(cli, docker, monkeypatch):
    monkeypatch.setenv("FAKE_DOCKER_NO_IMAGE", "1")
    code, out, err = cli(["tunnel", "key"])
    assert code == 0 and out == KEY_BLOB + "\n"
    assert f"pulled {T.IMAGE} (first use)" in err
    assert ["pull", T.IMAGE] in docker.argv()


def test_docker_start_names_the_container_and_stop_removes_it(cli, docker, state):
    try:
        code, out, err = cli(["tunnel", "start", "--org", "123", "--allow", "chat.corp.internal",
                              "--runner", "docker", "--json"])
        assert code == 0, err
        env = json.loads(out)
        assert env["data"]["runner"]["kind"] == "docker" and env["data"]["container"] == "ascend-tunnel-123-prod"
        assert env["data"]["key"] == KEY_BLOB
        run = [c for c in docker.argv() if c[:1] == ["run"]][-1]
        assert run[run.index("--name") + 1] == "ascend-tunnel-123-prod"
        assert ["rm", "-f", "ascend-tunnel-123-prod"] in docker.argv()   # a stale container is cleared first
        n_rm = docker.argv().count(["rm", "-f", "ascend-tunnel-123-prod"])
        code, out, _ = cli(["tunnel", "stop", "--json"])
        assert code == 0 and json.loads(out)["data"]["results"][0]["stopped"] is True
        assert docker.argv().count(["rm", "-f", "ascend-tunnel-123-prod"]) == n_rm + 1
    finally:
        _stop_all(cli)


# --------------------------------------------------------------------------- app tunnel-keys
APP_ID = "aapp_lab"
TEMPLATE = {"message": "{{PROMPT}}", "_adaptor_src": "c3Jj", "_adaptor_domains": ["x.corp:8443"]}


class Platform:
    """One application, served through the fake HTTP, with the request_template as the wire
    carries it: a JSON string."""

    def __init__(self, *, keys=None, api_type="api", url="https://chat.corp.internal.tun.straiker.ai/v1/chat",
                 lose_patch=False, template=None, jwt="JWT-test"):
        tpl = dict(template if template is not None else TEMPLATE)
        if keys is not None:
            tpl["_tunnel_agent_keys"] = list(keys)
        self.app = {"id": APP_ID, "name": "Support Bot", "api_type": api_type, "url": url,
                    "request_template": json.dumps(tpl), "response_template": '{"reply": "{{RESPONSE}}"}'}
        self.lose_patch = lose_patch
        self.jwt = jwt                      # what the PAT exchange hands back; a real-shaped one pins
        self.patches = []

    def template(self):
        return json.loads(self.app["request_template"])

    def __call__(self, method, url, kwargs):
        path = url.split("/api/v3", 1)[-1].split("?", 1)[0]
        body = kwargs.get("json")
        if url.endswith("/auth/token"):
            return FakeResponse(200, {"access_token": self.jwt})
        if path == "/ascend/applications" and method == "GET":
            return FakeResponse(200, {"object": "list", "data": [self.app], "has_more": False})
        if path == f"/ascend/applications/{APP_ID}":
            if method == "GET":
                return FakeResponse(200, self.app)
            if method == "PATCH":
                self.patches.append(json.loads(json.dumps(body)))
                if not self.lose_patch:
                    self.app = {**self.app, **body}
                return FakeResponse(200, self.app)
        raise AssertionError(f"unexpected {method} {url}")


@pytest.fixture
def platform_factory(monkeypatch, state):
    def make(**kw):
        pf = Platform(**kw)
        pf.rec = install_fake_requests(monkeypatch, pf)
        return pf
    return make


def test_no_keys_says_when_a_listed_key_starts_working(cli, platform_factory):
    """A listed key is accepted once the app lists it AND Straiker has used the app once (Test
    Connection, `adaptor test`, a run start) — not the moment it is listed."""
    platform_factory(keys=[])
    code, out, _ = cli(["app", "tunnel-keys", APP_ID])
    assert code == 0
    assert "refused until its key is here AND Straiker has used the app once" in out
    assert "Test Connection" in out and "ascend adaptor test" in out


def test_list_shows_the_keys_with_agent_ids(cli, platform_factory):
    pf = platform_factory(keys=[KEY_LINE, OTHER_LINE])
    code, out, _ = cli(["app", "tunnel-keys", APP_ID])
    assert code == 0
    assert "_tunnel_agent_keys (2 of 20)" in out and KEY_ID in out and OTHER_ID in out
    assert pf.patches == []
    code, out, _ = cli(["app", "tunnel-keys", "Support Bot", "--list", "--json"])
    env = json.loads(out)
    assert env["ok"] is True and env["data"]["changed"] is False and env["data"]["mode"] == "list"
    assert [k["agent_id"] for k in env["data"]["keys"]] == [KEY_ID, OTHER_ID]
    assert env["data"]["app"] == {"id": APP_ID, "name": "Support Bot",
                                  "url": "https://chat.corp.internal.tun.straiker.ai/v1/chat",
                                  "routed": "tunnel"}


def test_add_keeps_every_other_template_key_and_reads_back(cli, platform_factory):
    pf = platform_factory(keys=[OTHER_LINE])
    code, out, _ = cli(["app", "tunnel-keys", APP_ID, "--add", KEY_LINE, "--json"])
    assert code == 0
    [patch] = pf.patches
    assert list(patch) == ["request_template"] and isinstance(patch["request_template"], str)
    stored = json.loads(patch["request_template"])
    assert stored == {**TEMPLATE, "_tunnel_agent_keys": [OTHER_LINE, KEY_LINE]}
    env = json.loads(out)
    assert env["data"]["changed"] is True
    assert env["data"]["added"] == {"agent_id": KEY_ID, "type": "ssh-ed25519", "line": KEY_LINE,
                                    "already_listed": False}
    assert [k["agent_id"] for k in env["data"]["keys"]] == [OTHER_ID, KEY_ID]   # the record read back


def test_add_accepts_the_bare_paste_form_and_stores_the_full_line(cli, platform_factory):
    pf = platform_factory()
    code, out, _ = cli(["app", "tunnel-keys", APP_ID, "--add", KEY_BLOB])
    assert code == 0
    assert pf.template()["_tunnel_agent_keys"] == [KEY_LINE]
    assert "<- added" in out and KEY_ID in out


def test_add_of_a_listed_key_is_a_no_op(cli, platform_factory):
    pf = platform_factory(keys=[KEY_LINE])
    code, out, err = cli(["app", "tunnel-keys", APP_ID, "--add", KEY_BLOB, "--json"])
    assert code == 0
    env = json.loads(out)
    assert env["data"]["changed"] is False and env["data"]["added"]["already_listed"] is True
    assert pf.patches == []


def test_add_with_no_value_uses_this_machines_key(cli, platform_factory, agent):
    pf = platform_factory()
    code, out, _ = cli(["app", "tunnel-keys", APP_ID, "--add", "--json"])
    assert code == 0
    assert pf.template()["_tunnel_agent_keys"] == [KEY_LINE]
    assert agent.argv() == [["key", "--state-dir", agent.argv()[0][2]]]   # asked the agent for it


def test_add_refuses_a_type_the_engine_does_not_take(cli, platform_factory):
    import base64, struct
    pf = platform_factory()
    rsa = base64.b64encode(struct.pack(">I", 7) + b"ssh-rsa" + b"\x00" * 8).decode()
    code, out, _ = cli(["app", "tunnel-keys", APP_ID, "--add", f"ssh-rsa {rsa}", "--json"])
    assert code == ascend.EXIT_USAGE
    env = json.loads(out)
    assert env["error"]["code"] == "bad_key" and "ssh-rsa keys are not accepted" in env["error"]["message"]
    assert pf.patches == []


def test_the_twenty_first_key_is_refused(cli, platform_factory):
    import base64, struct
    blobs = [base64.b64encode(struct.pack(">I", 11) + b"ssh-ed25519" + bytes([i]) * 32).decode()
             for i in range(20)]
    pf = platform_factory(keys=[f"ssh-ed25519 {b}" for b in blobs])
    code, out, _ = cli(["app", "tunnel-keys", APP_ID, "--add", KEY_LINE, "--json"])
    assert code == ascend.EXIT_ERROR
    assert json.loads(out)["error"]["code"] == "too_many_keys"
    assert pf.patches == []


def test_remove_by_agent_id_and_the_last_key_leaves_no_empty_list(cli, platform_factory):
    pf = platform_factory(keys=[KEY_LINE, OTHER_LINE])
    code, out, _ = cli(["app", "tunnel-keys", APP_ID, "--remove", OTHER_ID, "--json"])
    assert code == 0
    assert pf.template()["_tunnel_agent_keys"] == [KEY_LINE]
    env = json.loads(out)
    assert env["data"]["removed"]["agent_id"] == OTHER_ID and env["data"]["count"] == 1
    code, out, _ = cli(["app", "tunnel-keys", APP_ID, "--remove", KEY_LINE])
    assert code == 0
    assert "_tunnel_agent_keys" not in pf.template() and pf.template()["message"] == "{{PROMPT}}"
    assert "none" in out


def test_remove_of_an_unlisted_key_is_an_error_naming_what_is_listed(cli, platform_factory):
    pf = platform_factory(keys=[KEY_LINE])
    code, out, err = cli(["app", "tunnel-keys", APP_ID, "--remove", OTHER_ID, "--json"])
    assert code == ascend.EXIT_ERROR
    env = json.loads(out)
    assert env["error"]["code"] == "not_listed" and KEY_ID in env["error"]["message"]
    assert pf.patches == []


def test_a_bridge_app_is_refused(cli, platform_factory):
    pf = platform_factory(api_type="thin", url="")
    code, out, _ = cli(["app", "tunnel-keys", APP_ID, "--add", KEY_LINE, "--json"])
    assert code == ascend.EXIT_ERROR and json.loads(out)["error"]["code"] == "bridge_app"
    assert pf.patches == []


def test_a_patch_that_did_not_land_is_not_reported_as_done(cli, platform_factory):
    pf = platform_factory(lose_patch=True)
    code, out, _ = cli(["app", "tunnel-keys", APP_ID, "--add", KEY_LINE, "--json"])
    assert code == ascend.EXIT_ERROR
    env = json.loads(out)
    assert env["ok"] is False and env["error"]["code"] == "store_unverified"
    assert len(pf.patches) == 1


def test_add_and_remove_together_is_a_usage_error(cli, platform_factory):
    pf = platform_factory()
    code, out, _ = cli(["app", "tunnel-keys", APP_ID, "--add", KEY_LINE, "--remove", OTHER_ID, "--json"])
    assert code == ascend.EXIT_USAGE and json.loads(out)["ok"] is False
    assert pf.rec.calls == []                                          # refused before any request


def test_a_url_that_is_not_a_tunnel_name_is_noted(cli, platform_factory):
    platform_factory(url="https://chat.example.com/v1/chat")
    code, out, _ = cli(["app", "tunnel-keys", APP_ID, "--add", KEY_LINE])
    assert code == 0 and "not a tunnel name" in out


def test_a_template_that_is_not_an_object_is_refused(cli, platform_factory):
    pf = platform_factory()
    pf.app["request_template"] = "[1, 2]"
    code, out, _ = cli(["app", "tunnel-keys", APP_ID, "--json"])
    assert code == ascend.EXIT_ERROR and json.loads(out)["error"]["code"] == "bad_template"


# --------------------------------------------------------------------------- the identity and the tenant pin
def _jwt(sid="123", email="ops@example.test"):
    """A PAT-exchange answer with the claims the tenant lock pins on (never verified here)."""
    def b64(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    return (f"{b64({'alg': 'none'})}."
            f"{b64({'iss': 'https://idp.example/pool', 'straikerId': sid, 'email': email, 'role': 'admin', 'exp': int(time.time()) + 600})}.")


def _plant(agent_dir: Path):
    """An identity in the fake agent's own format, as an earlier CLI would have left it:
    (public blob, agent id)."""
    blob = base64.b64encode(struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32)
                            + os.urandom(32)).decode()
    agent_dir.mkdir(parents=True)
    (agent_dir / "agent.key").write_text("-----BEGIN OPENSSH PRIVATE KEY-----\n" + blob
                                         + "\nFAKEPRIVATEHALF\n-----END OPENSSH PRIVATE KEY-----\n")
    return blob, hashlib.sha256(base64.b64decode(blob)).hexdigest()[:8]


@pytest.fixture
def fresh_home(tmp_path, monkeypatch, agent):
    """A home no command has touched, with the single-tenant lock ON (no ASCEND_SKIP_TENANT_CHECK)
    and no $ASCEND_STATE_DIR, so the state dir resolves the way it does on an operator's machine
    and the first platform call pins the tenant. The fake agent mints one identity per state
    directory, as the real one does.

    `tenant` reads ASCEND_HOME at import, so the module's constants are pointed at the home — on
    EVERY live copy of the module: in the full suite `sys.modules["tenant"]` is not always the
    object `tunnel` bound at its own import, and patching only the former sent the first version
    of these tests into the real ~/.ascend. The resolver is asserted to land under the home
    before anything runs."""
    home = tmp_path / "fresh-home"
    monkeypatch.setenv("ASCEND_HOME", str(home))
    copies = {id(m): m for m in list(sys.modules.values())
              if getattr(m, "__name__", "").split(".")[-1] == "tenant"
              and getattr(m, "__file__", None) and Path(m.__file__).name == "tenant.py"}
    copies[id(T._tenant)] = T._tenant
    for m in copies.values():
        monkeypatch.setattr(m, "ASCEND_HOME", home)
        monkeypatch.setattr(m, "TENANT_FILE", home / "tenant.json")
    monkeypatch.delenv("ASCEND_STATE_DIR", raising=False)
    monkeypatch.delenv("ASCEND_SKIP_TENANT_CHECK", raising=False)
    monkeypatch.setenv("FAKE_TUNNEL_MINT", "1")
    assert T._tenant.state_base() == home / "state", "the resolver must never leave tmp_path"
    import tenant as TN
    assert TN.TENANT_FILE == home / "tenant.json"
    return home


@pytest.mark.parametrize("state_dir_override", [False, True],
                         ids=["default state dir", "ASCEND_STATE_DIR set"])
def test_the_identity_is_the_same_before_and_after_the_tenant_pin(cli, fresh_home, platform_factory,
                                                                   monkeypatch, state_dir_override):
    """The sequence measured 2026-10-10: a fresh home, `tunnel check` first (no platform call, so
    no tenant is pinned), then `app tunnel-keys --add` with no value (the PAT exchange pins the
    tenant), then `tunnel key`. All three report one agent id, one key file exists under the
    home, and the key listed on the app is that one."""
    import tenant as TN
    base = fresh_home / "state"
    if state_dir_override:
        base = fresh_home / "elsewhere"
        monkeypatch.setenv("ASCEND_STATE_DIR", str(base))
    pf = platform_factory(jwt=_jwt())
    code, out, err = cli(["tunnel", "check", "--org", "123", "--allow", "localhost:8099", "--json"])
    assert code == 0, err
    first = json.loads(out)["data"]["agent_id"]
    assert TN.load() is None                                   # check asked nothing of the platform
    code, out, err = cli(["app", "tunnel-keys", APP_ID, "--add", "--json"])
    assert code == 0, err
    listed = json.loads(out)["data"]["added"]["agent_id"]
    assert TN.load()["fingerprint"]                            # THIS call pinned the tenant
    code, out, err = cli(["tunnel", "key", "--json"])
    assert code == 0, err
    third = json.loads(out)["data"]
    assert first == listed == third["agent_id"], \
        f"check reported {first}, --add listed {listed}, key printed {third['agent_id']}"
    keys = sorted(str(p.relative_to(fresh_home)) for p in fresh_home.rglob("agent.key"))
    assert keys == [str((base / "tunnel" / "agent" / "agent.key").relative_to(fresh_home))]
    assert third["state_dir"] == str(base / "tunnel" / "agent")
    assert pf.template()["_tunnel_agent_keys"] == [third["line"]]
    assert "another tunnel identity" not in err                # nothing was left anywhere


def test_a_tunnel_started_before_the_pin_is_still_listed_after_it(cli, fresh_home, platform_factory):
    """The other documented order: `start` first, list the key it printed, then look. The pid,
    log and status records live with the identity, so the pin does not lose a running tunnel."""
    pf = platform_factory(jwt=_jwt())
    try:
        code, out, err = cli(["tunnel", "start", "--org", "123", "--allow", "a.corp", "--json"])
        assert code == 0, err
        started = json.loads(out)["data"]
        code, out, err = cli(["app", "tunnel-keys", APP_ID, "--add", started["key"], "--json"])
        assert code == 0, err                                 # pins the tenant
        code, out, _ = cli(["tunnel", "ls", "--json"])
        [row] = json.loads(out)["data"]["tunnels"]
        assert row["pid"] == started["pid"] and row["agent_id"] == started["agent_id"]
        assert row["state"] == "serving"
        code, out, _ = cli(["tunnel", "stop", "--json"])
        assert code == 0 and json.loads(out)["data"]["results"][0]["stopped"] is True
    finally:
        _stop_all(cli)


def test_an_identity_left_under_the_tenant_dir_is_adopted_with_its_records(cli, fresh_home,
                                                                            platform_factory):
    """An earlier CLI kept the key under state/<fp16>/tunnel/agent — the identity `--add` listed
    and `start` ran once the pin existed. It becomes the live identity; its records come along;
    the emptied directory goes; nothing is said, since nothing is ambiguous."""
    import tenant as TN
    platform_factory(jwt=_jwt())
    cli(["app", "tunnel-keys", APP_ID, "--json"])             # pins; a listing touches no tunnel dir
    fp16 = TN.load()["fingerprint"][:16]
    legacy = fresh_home / "state" / fp16 / "tunnel"
    blob, aid = _plant(legacy / "agent")
    (legacy / "9-prod.json").write_text(json.dumps({"id": "9-prod", "org": "9", "env": "prod"}))
    (legacy / "9-prod.log").write_text("")
    code, out, err = cli(["tunnel", "key", "--json"])
    assert code == 0, err
    d = json.loads(out)["data"]
    assert d["agent_id"] == aid and d["key"] == blob
    new = fresh_home / "state" / "tunnel"
    assert (new / "agent" / "agent.key").read_text().splitlines()[1] == blob
    assert (new / "9-prod.json").exists() and (new / "9-prod.log").exists()
    assert not legacy.exists()
    assert "another tunnel identity" not in err
    code, out, _ = cli(["tunnel", "ls", "--json"])
    assert [r["id"] for r in json.loads(out)["data"]["tunnels"]] == []   # no pid: not a tunnel


def test_a_second_legacy_identity_is_kept_beside_the_live_one_and_named(cli, fresh_home,
                                                                         platform_factory):
    """Both the pre-pin (`unpinned`) and the pinned directory hold a key: the measured case. The
    pinned tenant's becomes the live identity; the other is kept as agent-unpinned and named by
    every key-bearing verb, because the CLI cannot tell which one an app lists. An explicit
    --state-dir is the operator's choice, so nothing is said then; removing it ends the note."""
    import tenant as TN
    pf = platform_factory(jwt=_jwt())
    cli(["app", "tunnel-keys", APP_ID, "--json"])
    fp16 = TN.load()["fingerprint"][:16]
    _, old_id = _plant(fresh_home / "state" / "unpinned" / "tunnel" / "agent")
    _, aid = _plant(fresh_home / "state" / fp16 / "tunnel" / "agent")
    live = fresh_home / "state" / "tunnel" / "agent"
    kept = fresh_home / "state" / "tunnel" / "agent-unpinned"

    code, out, err = cli(["tunnel", "key", "--json"])
    assert code == 0 and json.loads(out)["data"]["agent_id"] == aid
    assert (kept / "agent.key").exists() and not (fresh_home / "state" / "unpinned" / "tunnel").exists()
    assert f"another tunnel identity is kept at {kept}" in err and f"this agent uses {live}" in err
    assert "replace" in err and "delete it" in err
    json.loads(out)                                             # stdout stayed one envelope

    for argv in (["tunnel", "check", "--org", "123", "--allow", "a.corp", "--json"],
                 ["app", "tunnel-keys", APP_ID, "--add", "--json"]):
        code, out, err = cli(argv)
        assert code == 0, err
        assert f"another tunnel identity is kept at {kept}" in err, argv
    assert pf.template()["_tunnel_agent_keys"][0].endswith(" " + (live / "agent.key").read_text().splitlines()[1])

    code, out, err = cli(["tunnel", "key", "--state-dir", str(kept), "--json"])
    assert code == 0 and json.loads(out)["data"]["agent_id"] == old_id
    assert "another tunnel identity" not in err

    shutil.rmtree(kept)
    code, _, err = cli(["tunnel", "key", "--json"])
    assert code == 0 and "another tunnel identity" not in err


def test_the_tunnel_dir_resolves_the_same_with_and_without_a_pin(fresh_home, monkeypatch):
    """The resolver itself: pinned or not, with or without $ASCEND_STATE_DIR, the tunnel
    directory is <state base>/tunnel and never under a tenant."""
    import tenant as TN
    assert T.tunnel_dir() == fresh_home / "state" / "tunnel"
    TN.pin("a" * 64, "example.test (admin)")
    assert TN.state_root() == fresh_home / "state" / ("a" * 16)
    assert T.tunnel_dir() == fresh_home / "state" / "tunnel"
    monkeypatch.setenv("ASCEND_STATE_DIR", str(fresh_home / "elsewhere"))
    assert TN.state_root() == fresh_home / "elsewhere" / ("a" * 16)
    assert T.tunnel_dir() == fresh_home / "elsewhere" / "tunnel"
    assert T.agent_state_dir() == fresh_home / "elsewhere" / "tunnel" / "agent"
