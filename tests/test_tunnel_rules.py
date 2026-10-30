"""
test_tunnel_rules — the rules `ascend tunnel` mirrors from the agent, offline.

runtime/tunnel.py re-states what the open-source agent enforces, so a bad allow entry is refused
here, before anything is spawned, in the agent's words. Pins:

  * the agent id this CLI derives from a key — sha256 of the wire blob, first 8 hex — matches the
    agent's own testdata/contract.json, for the full line and for the bare base64 `key` prints;
  * the key types the engine accepts, and the refusals: a type the engine does not take, a prefix
    that contradicts the key material, junk;
  * the allow list: port 443 when omitted, one entry per host, an IP address refused, a name that
    is already a tunnel name refused, the agent's host regex;
  * the URL rule: no port in the URL, http only on 80, wss for a WebSocket app, the port of a real
    URL moved into the allow entry;
  * the environment table and `--base` following, the argv for either runner — the Docker form
    mounts the state directory, runs as this user, and passes the proxy variables by name only
    when they are set — and the runner search order.
"""
import base64
import os
import struct
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
for _p in ("runtime", "control"):
    if str(REPO / _p) not in sys.path:
        sys.path.insert(0, str(REPO / _p))
import tunnel as T  # noqa: E402

# Two vectors from the agent's testdata/contract.json: the public key, its paste form, its id.
VECTORS = [
    ("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOUCMT9hLrSSmTyPYnU+xGO8/gCs7AZy1c9ssMyLd6Mw", "520de864"),
    ("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAOhB7/zzhC+HXDdGOdLwJln5NYwm6UNXx3chmQSVTG4", "95b9aca0"),
]
ED25519_LINE, ED25519_ID = VECTORS[0]
ED25519_BLOB = ED25519_LINE.split()[1]


def _ssh_string(b: bytes) -> bytes:
    return struct.pack(">I", len(b)) + b


def synthetic_blob(key_type: str) -> str:
    """A wire blob whose first string names `key_type` — enough for the type check."""
    return base64.b64encode(_ssh_string(key_type.encode()) + _ssh_string(b"nistp256")
                            + _ssh_string(b"\x04" + b"\x01" * 64)).decode()


# --------------------------------------------------------------------------- key lines
class TestKeyLines:
    @pytest.mark.parametrize("line,agent_id", VECTORS)
    def test_agent_id_matches_the_agents_contract(self, line, agent_id):
        full = T.parse_key_line(line)
        bare = T.parse_key_line(line.split()[1])
        assert full["agent_id"] == bare["agent_id"] == agent_id
        assert full["type"] == bare["type"] == "ssh-ed25519"
        assert full["line"] == bare["line"] == line         # stored self-describing either way

    def test_a_trailing_comment_is_dropped(self):
        rec = T.parse_key_line(ED25519_LINE + " laptop@corp")
        assert rec["line"] == ED25519_LINE and rec["agent_id"] == ED25519_ID

    @pytest.mark.parametrize("key_type", ["ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384"])
    def test_the_other_accepted_types(self, key_type):
        blob = synthetic_blob(key_type)
        assert T.parse_key_line(f"{key_type} {blob}")["type"] == key_type
        assert T.parse_key_line(blob)["type"] == key_type

    def test_a_type_the_engine_does_not_take_is_refused(self):
        with pytest.raises(T.KeyLineError, match="ssh-rsa keys are not accepted"):
            T.parse_key_line("ssh-rsa " + synthetic_blob("ssh-rsa"))

    def test_a_prefix_that_contradicts_the_material_is_refused(self):
        with pytest.raises(T.KeyLineError, match="says ecdsa-sha2-nistp256 but"):
            T.parse_key_line(f"ecdsa-sha2-nistp256 {ED25519_BLOB}")

    @pytest.mark.parametrize("junk", ["", "   ", "ssh-ed25519", "not base64!!", "ssh-ed25519 ????",
                                      base64.b64encode(b"\x00\x00\x00\x99abc").decode()])
    def test_junk_is_refused(self, junk):
        with pytest.raises(T.KeyLineError):
            T.parse_key_line(junk)

    def test_describe_keys_keeps_what_it_cannot_parse(self):
        rows = T.describe_keys([ED25519_LINE, "garbage"])
        assert rows[0]["valid"] and rows[0]["agent_id"] == ED25519_ID
        assert not rows[1]["valid"] and rows[1]["stored"] == "garbage" and rows[1]["problem"]
        assert T.describe_keys("not a list") == []


# --------------------------------------------------------------------------- the allow list
class TestAllowList:
    def test_port_443_when_omitted_and_the_app_url(self):
        f = T.parse_allow(["chat.corp.internal"])[0]
        assert f == {"host": "chat.corp.internal", "port": 443, "entry": "chat.corp.internal:443",
                     "app_url": "https://chat.corp.internal.tun.straiker.ai"}

    def test_host_port_lowercased_and_trailing_dot_dropped(self):
        f = T.parse_allow(["API.Corp.Internal.:8080"])[0]
        assert (f["host"], f["port"], f["entry"]) == ("api.corp.internal", 8080, "api.corp.internal:8080")

    def test_port_80_is_plain_http(self):
        assert T.parse_allow(["plain.corp.internal:80"])[0]["app_url"] == "http://plain.corp.internal.tun.straiker.ai"

    @pytest.mark.parametrize("ip", ["10.0.0.5:8080", "127.0.0.1", "[::1]:443", "fe80::1"])
    def test_an_ip_address_is_refused(self, ip):
        with pytest.raises(T.AllowError, match="is an IP address"):
            T.parse_allow([ip])

    def test_a_tunnel_name_is_refused_naming_the_real_host(self):
        with pytest.raises(T.AllowError, match=r"already a tunnel name.*\(chat\.corp\.internal\)"):
            T.parse_allow(["chat.corp.internal.tun.straiker.ai"])

    def test_one_entry_per_host(self):
        with pytest.raises(T.AllowError, match="one allow entry per host.*ports 443 and 8080"):
            T.parse_allow(["chat.corp.internal", "chat.corp.internal:8080"])

    @pytest.mark.parametrize("bad", ["a_b.corp", "-bad.corp", "bad.corp-", "chat.corp.internal:0",
                                     "chat.corp.internal:70000", "chat.corp.internal:abc", "", "  ",
                                     ":8080", "x" * 98 + ".corp"])
    def test_malformed_entries_are_refused(self, bad):
        with pytest.raises(T.AllowError):
            T.parse_allow([bad])

    def test_an_empty_list_is_refused(self):
        with pytest.raises(T.AllowError, match="at least one target"):
            T.parse_allow([])

    def test_localhost_is_a_name(self):
        assert T.parse_allow(["localhost:8080"])[0]["app_url"] == "https://localhost.tun.straiker.ai"


# --------------------------------------------------------------------------- the URL rule
class TestUrlRule:
    def test_bare_host_and_host_port(self):
        r = T.url_rule("chat.corp.internal")
        assert (r["url"], r["allow"], r["port_moved"]) == \
            ("https://chat.corp.internal.tun.straiker.ai/<path>", "chat.corp.internal:443", False)
        r = T.url_rule("api.corp.internal:8080", path="v1/chat")
        assert r["url"] == "https://api.corp.internal.tun.straiker.ai/v1/chat"
        assert r["allow"] == "api.corp.internal:8080" and r["path"] == "/v1/chat"

    def test_a_real_url_moves_its_port_into_the_allow_entry(self):
        r = T.url_rule("https://api.corp.internal:8080/v1/chat?x=1")
        assert r["url"] == "https://api.corp.internal.tun.straiker.ai/v1/chat?x=1"
        assert r["allow"] == "api.corp.internal:8080" and r["port_moved"] is True
        assert ":8080" not in r["url"]

    def test_http_on_80_stays_http_and_any_other_port_is_https(self):
        assert T.url_rule("http://plain.corp.internal/chat")["url"] == "http://plain.corp.internal.tun.straiker.ai/chat"
        assert T.url_rule("http://plain.corp.internal:8080/chat")["url"] == "https://plain.corp.internal.tun.straiker.ai/chat"

    def test_websocket_apps(self):
        assert T.url_rule("ws://bot.corp.internal:9000/socket")["url"] == "wss://bot.corp.internal.tun.straiker.ai/socket"
        assert T.url_rule("ws://bot.corp.internal/socket")["url"] == "ws://bot.corp.internal.tun.straiker.ai/socket"
        assert T.url_rule("wss://bot.corp.internal/socket")["allow"] == "bot.corp.internal:443"

    def test_path_flag_wins_over_the_urls_path(self):
        assert T.url_rule("https://a.corp/old", path="/new")["url"] == "https://a.corp.tun.straiker.ai/new"

    @pytest.mark.parametrize("bad", ["ftp://a.corp/x", "https://10.0.0.5/x", "https://a.corp:99999/x",
                                     "https://a.corp.tun.straiker.ai/x"])
    def test_refusals_are_the_allow_lists(self, bad):
        with pytest.raises(T.AllowError):
            T.url_rule(bad)

    def test_the_rules_are_stated(self):
        rules = " ".join(T.url_rule("a.corp")["rules"])
        for phrase in ("no port in the URL", "one entry per host", "never an IP address",
                       "key must be listed on the app", "http:// only"):
            assert phrase in rules


# --------------------------------------------------------------------------- environments
class TestEnvironments:
    @pytest.mark.parametrize("base,env", [
        ("https://api.dev.straiker.ai/api/v3", "dev"),
        ("https://api.staging.straiker.ai/api/v3", "stage"),
        ("https://api.stage.straiker.ai/api/v3", "stage"),
        ("https://api.prod.straiker.ai/api/v3", "prod"),
        ("https://api.example.com/v3", "prod"), (None, "prod"), ("", "prod"),
    ])
    def test_default_env_follows_the_control_plane_base(self, base, env):
        assert T.default_env(base) == env

    def test_the_table_and_the_overrides(self):
        for env in ("dev", "stage", "prod"):
            r = T.resolve_endpoint(env)
            assert r["endpoint"].startswith("wss://ascendai-bridge.") and r["endpoint"].endswith("/tunnel")
            assert r["host_key"] == T.ENVIRONMENTS[env]["host_key"]
            assert r["host_key_source"] == "built-in"
        assert T.resolve_endpoint("prod")["endpoint"] == "wss://ascendai-bridge.prod.straiker.ai/tunnel"
        r = T.resolve_endpoint("dev", "wss://relay.example/tunnel", "ssh-ed25519 AAAA")
        assert r == {"env": "dev", "endpoint": "wss://relay.example/tunnel",
                     "host_key": "ssh-ed25519 AAAA", "host_key_source": "flag"}

    def test_a_non_wss_endpoint_and_a_bad_host_key_are_refused(self):
        with pytest.raises(ValueError, match="wss://"):
            T.resolve_endpoint("prod", "https://relay.example/tunnel")
        with pytest.raises(ValueError, match="host-key"):
            T.resolve_endpoint("prod", None, "AAAA")
        with pytest.raises(ValueError, match="unknown environment"):
            T.resolve_endpoint("qa")


# --------------------------------------------------------------------------- the runner
class TestRunner:
    BIN = {"kind": "binary", "path": "/opt/bin/ascend-tunnel", "label": "x"}
    DOCKER = {"kind": "docker", "docker": "/usr/local/bin/docker", "image": T.IMAGE, "label": "x"}
    FWD = [{"entry": "chat.corp.internal:443"}, {"entry": "api.corp.internal:8080"}]

    def test_binary_argv_in_a_fixed_order(self):
        argv = T.build_argv(self.BIN, "check", org="1234", allow=[f["entry"] for f in self.FWD],
                            endpoint="wss://e/tunnel", host_key="ssh-ed25519 AAAA",
                            state_dir="/s/agent", ca_file="/etc/ca.pem")
        assert argv == ["/opt/bin/ascend-tunnel", "check", "--org", "1234",
                        "--allow", "chat.corp.internal:443", "--allow", "api.corp.internal:8080",
                        "--relay", "wss://e/tunnel", "--host-key", "ssh-ed25519 AAAA",
                        "--state-dir", "/s/agent", "--ca-file", "/etc/ca.pem"]
        assert T.build_argv(self.BIN, "key", state_dir="/s/agent") == \
            ["/opt/bin/ascend-tunnel", "key", "--state-dir", "/s/agent"]
        no_pin = T.build_argv(self.BIN, "run", org="1", allow=["a.corp:443"], endpoint="wss://e",
                              state_dir="/s")
        assert "--host-key" not in no_pin and "--ca-file" not in no_pin

    def test_docker_argv_mounts_state_runs_as_this_user_and_passes_proxies_only_when_set(
            self, monkeypatch, tmp_path):
        for v in T.PROXY_VARS:
            monkeypatch.delenv(v, raising=False)
        ca = tmp_path / "ca.pem"
        ca.write_text("x")
        argv = T.build_argv(self.DOCKER, "run", org="1234", allow=["chat.corp.internal:443"],
                            endpoint="wss://e/tunnel", state_dir="/s/agent", ca_file=str(ca),
                            container_name="ascend-tunnel-1234-dev")
        assert argv[:3] == ["/usr/local/bin/docker", "run", "--rm"]
        assert argv[3:5] == ["--name", "ascend-tunnel-1234-dev"]
        assert argv[argv.index("--user") + 1] == f"{os.getuid()}:{os.getgid()}"
        assert "-v" in argv and f"/s/agent:{T.CONTAINER_STATE_DIR}" in argv
        assert f"{ca.resolve()}:{T.CONTAINER_CA_FILE}:ro" in argv
        assert "--add-host=host.docker.internal:host-gateway" in argv
        assert "-e" not in argv                                 # nothing set, nothing passed
        i = argv.index(T.IMAGE)
        assert argv[i + 1:] == ["run", "--org", "1234", "--allow", "chat.corp.internal:443",
                                "--relay", "wss://e/tunnel", "--state-dir", T.CONTAINER_STATE_DIR,
                                "--ca-file", T.CONTAINER_CA_FILE]
        monkeypatch.setenv("HTTPS_PROXY", "http://proxy.corp:3128")
        monkeypatch.setenv("NO_PROXY", "localhost")
        argv = T.build_argv(self.DOCKER, "check", org="1", allow=["a.corp:443"], endpoint="wss://e",
                            state_dir="/s")
        passed = [argv[i + 1] for i, a in enumerate(argv) if a == "-e"]
        assert passed == ["HTTPS_PROXY", "NO_PROXY"]
        assert "http://proxy.corp:3128" not in argv              # by name: the value stays in the env

    def test_runner_search_order(self):
        def which_both(name):
            return {"ascend-tunnel": "/opt/bin/ascend-tunnel", "docker": "/usr/local/bin/docker"}.get(name)

        def which_docker(name):
            return "/usr/local/bin/docker" if name == "docker" else None
        ready = lambda d: (True, "")
        r, notes = T.find_runner("auto", which=which_both, docker_ready=ready)
        assert r["kind"] == "binary" and notes == []
        r, notes = T.find_runner("auto", which=which_docker, docker_ready=ready)
        assert r["kind"] == "docker" and r["image"] == T.IMAGE and notes == ["ascend-tunnel is not on PATH"]
        r, notes = T.find_runner("docker", which=which_both, docker_ready=ready)
        assert r["kind"] == "docker"                              # pinned: PATH is not consulted
        r, notes = T.find_runner("binary", which=which_docker, docker_ready=ready)
        assert r is None and notes == ["ascend-tunnel is not on PATH"]
        r, notes = T.find_runner("auto", which=which_docker,
                                 docker_ready=lambda d: (False, "docker is installed but its daemon is not running"))
        assert r is None and "daemon is not running" in notes[1]
        r, notes = T.find_runner("auto", which=lambda n: None, docker_ready=ready)
        assert r is None and notes == ["ascend-tunnel is not on PATH", "docker is not installed"]
        msg = T.no_runner_message(notes)
        for hint in ("brew install straiker-ai/tap/ascend-tunnel", "winget/Scoop not yet published",
                     "docker pull ghcr.io/straiker-ai/ascend-tunnel", "gh attestation verify"):
            assert hint in msg

    def test_docker_notes(self, monkeypatch):
        for v in T.PROXY_VARS:
            monkeypatch.delenv(v, raising=False)
        assert T.docker_notes(self.BIN, [{"host": "localhost"}]) == []
        notes = T.docker_notes(self.DOCKER, [{"host": "localhost"}])
        assert len(notes) == 1 and "host.docker.internal" in notes[0]
        monkeypatch.setenv("HTTPS_PROXY", "http://user:secret@127.0.0.1:3128")
        notes = T.docker_notes(self.DOCKER, [{"host": "chat.corp.internal"}])
        assert len(notes) == 1 and "127.0.0.1" in notes[0]
        assert T.proxy_in_use() == "http://redacted@127.0.0.1:3128"


# --------------------------------------------------------------------------- the agent's output
CHECK_OUTPUT = f"""INFO  org 1234, agent {ED25519_ID}
INFO  agent key (paste into the app's _tunnel_agent_keys): {ED25519_BLOB}
INFO  app URL for chat.corp.internal:443: https://chat.corp.internal.tun.straiker.ai/... (the Ascend app's URL, with its path)
INFO  app URL for api.corp.internal:8080: https://api.corp.internal.tun.straiker.ai/... (the Ascend app's URL, with its path)
INFO  relay wss://ascendai-bridge.prod.straiker.ai/tunnel, direct (no HTTPS_PROXY)
PASS  relay WebSocket upgraded over HTTPS
INFO  relay TLS certificate issued by "CN=R3" (a TLS-inspecting proxy shows its own CA here; that is fine)
WARN  relay host key SHA256:abc is not pinned (set host_key)
WAIT  no Ascend app lists this agent's key yet: paste it into the app, then test the connection
PASS  target chat.corp.internal:443 reachable
FAIL  target api.corp.internal:8080 not reachable from this machine: dial tcp: connection refused
"""


class TestAgentOutput:
    def test_check_lines_are_read_in_the_agents_format(self):
        p = T.parse_check_lines(CHECK_OUTPUT.splitlines())
        assert p["key"] == ED25519_BLOB and p["agent_id"] == ED25519_ID and p["org"] == "1234"
        assert p["app_urls"] == ["https://chat.corp.internal.tun.straiker.ai",
                                 "https://api.corp.internal.tun.straiker.ai"]
        assert p["counts"] == {"PASS": 2, "FAIL": 1, "WARN": 1, "WAIT": 1, "INFO": 6}
        assert p["failed"] == 1 and p["waiting"] is True and p["listed"] is False
        assert p["lines"][5] == {"status": "PASS", "text": "relay WebSocket upgraded over HTTPS"}

    def test_a_listed_key_reads_as_listed(self):
        p = T.parse_check_lines(["PASS  an Ascend app lists this agent's key: the relay accepts it"])
        assert p["listed"] is True and p["waiting"] is False

    def test_key_output_is_the_first_non_empty_line(self):
        assert T.key_from_output(f"\n{ED25519_BLOB}\n") == ED25519_BLOB
        assert T.key_from_output("") is None

    def test_identity_and_link_state_from_a_log(self, tmp_path):
        log = tmp_path / "t.log"
        log.write_text(
            "Unable to find image locally\n"
            '{"ts":"2026-10-09T00:00:00.000000+00:00","event":"identity","tenant":"1234",'
            f'"agent_id":"{ED25519_ID}","agent_key":"{ED25519_BLOB}",'
            '"app_urls":["https://chat.corp.internal.tun.straiker.ai"],"hint":"..."}\n'
            '{"ts":"...","event":"waiting","link":0,"error":"no Ascend app lists this agent\'s key"}\n'
            '{"ts":"...","event":"connected","relay":"wss://x","link":0,"targets":["chat.corp.internal"]}\n'
            '{"ts":"...","event":"forward","link":0,"socket":"/run/t/x/chat.corp.internal~0"}\n'
            "not json\n")
        ident = T.identity_from_log(log)
        assert ident == {"key": ED25519_BLOB, "agent_id": ED25519_ID, "org": "1234",
                         "app_urls": ["https://chat.corp.internal.tun.straiker.ai"]}
        assert T.last_event(log)["state"] == "up" and T.last_event(log)["event"] == "forward"
        log.write_text(log.read_text() + '{"ts":"...","event":"disconnected","link":0,"error":"EOF"}\n')
        assert T.last_event(log)["state"] == "reconnecting"
        assert T.identity_from_log(tmp_path / "missing.log") is None
        assert T.last_event(tmp_path / "missing.log") is None
