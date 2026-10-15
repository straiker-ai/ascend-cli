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
  * the URL rule: no port in the URL, the port of a real URL moved into the allow entry, and its
    scheme kept on any port (http:// for a plain-HTTP target, ws:// / wss:// for a WebSocket
    one); a bare host[:port] keeps the assumed default (http on 80, https elsewhere) and says so
    where the port does not settle it;
  * the environment table and `--base` following, the argv for either runner — the Docker form
    mounts the state directory, runs as this user, and passes the proxy variables by name only
    when they are set — and the runner search order;
  * the agent's `check` lines in the 0.1.2 and the 0.1.4 forms: each app's URL and, from 0.1.4,
    the scheme each target answered in, which then decides the app's URL.
"""
import base64
import os
import re
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
    def test_an_ip_literal_is_refused_as_straikers_rule(self, ip):
        """The agent itself accepts an IPv4 literal; it is the platform that refuses the tunnel
        name built from one, so the refusal says whose rule it is."""
        with pytest.raises(T.AllowError, match="Straiker does not route an IP-literal tunnel name"):
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

    def test_the_host_cap_is_the_relays_socket_name_85_at_the_default_fanout(self):
        """/run/t/<12 hex>/<host>~0 within sun_path's 107 bytes. MEASURED: the 0.1.2 binary
        refuses an 86-character host; the old cap of 97 let it through to be refused there."""
        assert T.MAX_HOST_LEN == 85 and T.max_host_len() == 85 and T.max_host_len(1) == 85
        ok = "a" * 80 + ".corp"                                           # 85
        assert T.parse_allow([ok])[0]["host"] == ok
        with pytest.raises(T.AllowError, match=r"too long for the tunnel's socket name \(85 characters"):
            T.parse_allow(["a" * 81 + ".corp"])                          # 86

    def test_above_ten_links_the_cap_is_one_shorter(self):
        """`~10` … `~15` cost one more character than `~0` … `~9`."""
        assert [T.max_host_len(n) for n in (2, 10, 11, 16)] == [85, 85, 84, 84]
        host84, host85 = "a" * 79 + ".corp", "a" * 80 + ".corp"
        assert T.parse_allow([host85], fanout=10)[0]["host"] == host85
        assert T.parse_allow([host84], fanout=16)[0]["host"] == host84
        with pytest.raises(T.AllowError, match=r"84 characters at most with --fanout 16"):
            T.parse_allow([host85], fanout=16)

    @pytest.mark.parametrize("value,expected", [(None, None), (1, 1), ("16", 16), (8, 8)])
    def test_fanout_in_range(self, value, expected):
        assert T.check_fanout(value) == expected

    @pytest.mark.parametrize("value", [0, 17, -1, "lots", 1.5])
    def test_fanout_out_of_range_is_the_agents_words(self, value):
        with pytest.raises(ValueError, match=r"fanout must be 1\.\.16"):
            T.check_fanout(value)

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

    @pytest.mark.parametrize("url,expected,allow", [
        # MEASURED 2026-10-14 on a live tunnel: a plain-HTTP target on 8089 behind https:// fails
        # (Straiker starts TLS with it) and behind http:// works. This rule said https for it.
        ("http://plain.corp.internal:8089/chat", "http://plain.corp.internal.tun.straiker.ai/chat", "plain.corp.internal:8089"),
        ("http://plain.corp.internal/chat", "http://plain.corp.internal.tun.straiker.ai/chat", "plain.corp.internal:80"),
        ("https://api.corp.internal:8443/v1", "https://api.corp.internal.tun.straiker.ai/v1", "api.corp.internal:8443"),
        ("https://tls.corp.internal:80/x", "https://tls.corp.internal.tun.straiker.ai/x", "tls.corp.internal:80"),
        ("HTTP://Plain.Corp.Internal:8089/Chat", "http://plain.corp.internal.tun.straiker.ai/Chat", "plain.corp.internal:8089"),
    ])
    def test_a_real_urls_scheme_is_kept_on_any_port(self, url, expected, allow):
        r = T.url_rule(url)
        assert (r["url"], r["allow"]) == (expected, allow)
        assert r["scheme"] == expected.split("://")[0] and r["app_url"] == expected.rsplit("/", 1)[0]
        assert r["scheme_given"] is True and r["hint"] is None

    def test_websocket_apps_keep_their_scheme_too(self):
        assert T.url_rule("ws://bot.corp.internal:9000/socket")["url"] == "ws://bot.corp.internal.tun.straiker.ai/socket"
        assert T.url_rule("wss://bot.corp.internal:9443/socket")["url"] == "wss://bot.corp.internal.tun.straiker.ai/socket"
        assert T.url_rule("ws://bot.corp.internal/socket")["url"] == "ws://bot.corp.internal.tun.straiker.ai/socket"
        r = T.url_rule("wss://bot.corp.internal/socket")
        assert r["allow"] == "bot.corp.internal:443" and r["websocket"] is True
        assert T.url_rule("ws://bot.corp.internal:9000/socket")["allow"] == "bot.corp.internal:9000"

    def test_a_bare_host_port_keeps_the_default_and_says_it_is_assumed(self):
        """No scheme to keep: https is assumed off 80, as before, and the hint names the http://
        URL a plain-HTTP target needs instead (the 0.1.4 agent's `check app` warns the same)."""
        r = T.url_rule("api.corp.internal:8080", path="/v1/chat")
        assert r["url"] == "https://api.corp.internal.tun.straiker.ai/v1/chat" and r["scheme"] == "https"
        assert r["scheme_given"] is False
        assert "https:// is assumed on port 8080" in r["hint"] and "plain HTTP" in r["hint"]
        assert r["hint"].endswith("http://api.corp.internal.tun.straiker.ai/v1/chat")
        assert "\n" not in r["hint"]
        assert T.url_rule("localhost:8089")["hint"].endswith("http://localhost.tun.straiker.ai/<path>")

    @pytest.mark.parametrize("target,url", [
        ("chat.corp.internal", "https://chat.corp.internal.tun.straiker.ai/<path>"),
        ("chat.corp.internal:443", "https://chat.corp.internal.tun.straiker.ai/<path>"),
        ("plain.corp.internal:80", "http://plain.corp.internal.tun.straiker.ai/<path>"),
    ])
    def test_no_hint_where_the_port_settles_the_scheme(self, target, url):
        r = T.url_rule(target)
        assert r["url"] == url and r["hint"] is None and r["scheme_given"] is False

    @pytest.mark.parametrize("port,hinted", [(80, False), (443, False), (8080, True), (8089, True),
                                             (8443, True), (3000, True)])
    def test_scheme_hint_is_said_only_off_80_and_443(self, port, hinted):
        hint = T.scheme_hint("h.corp", port)
        assert (hint is not None) is hinted
        if hinted:
            assert hint.startswith(f"https:// is assumed on port {port}")
            assert hint.endswith("http://h.corp.tun.straiker.ai/<path>")

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
                       "key must be listed on the app", "plain HTTP on any port"):
            assert phrase in rules
        assert "plain HTTP on port 80" not in rules, "the rule that sent a plain-HTTP target to https://"


class TestAppUrl:
    """The contract: a given scheme is the target's own and is kept on any port; without one it
    is assumed from the port, the agent's default (http on 80, https on any other)."""

    @pytest.mark.parametrize("port,scheme,expected", [
        (8089, "http", "http://h.corp.tun.straiker.ai"),
        (8443, "https", "https://h.corp.tun.straiker.ai"),
        (80, "https", "https://h.corp.tun.straiker.ai"),
        (443, "http", "http://h.corp.tun.straiker.ai"),
        (9000, "WS", "ws://h.corp.tun.straiker.ai"),
        (9443, "wss", "wss://h.corp.tun.straiker.ai"),
        (8089, None, "https://h.corp.tun.straiker.ai"),
        (443, None, "https://h.corp.tun.straiker.ai"),
        (80, None, "http://h.corp.tun.straiker.ai"),
    ])
    def test_a_given_scheme_is_kept_and_a_missing_one_assumed(self, port, scheme, expected):
        assert T.app_url("h.corp", port, scheme) == expected

    def test_a_scheme_the_tunnel_does_not_carry_is_refused(self):
        with pytest.raises(T.AllowError, match=r"ftp:// is not an http\(s\) or ws\(s\) URL"):
            T.app_url("h.corp", 21, "ftp")

    def test_an_allow_entry_has_no_scheme_so_it_keeps_the_default(self):
        assert [f["app_url"] for f in T.parse_allow(["a.corp:8089", "b.corp:80", "c.corp"])] == [
            "https://a.corp.tun.straiker.ai", "http://b.corp.tun.straiker.ai", "https://c.corp.tun.straiker.ai"]


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

    def test_the_table_is_exact_per_environment(self):
        """Exact URLs, not a prefix: the prefix test let `ascendai-bridge.staging.straiker.ai`
        through, and that name is NXDOMAIN (MEASURED 2026-10-13); the stage relay is
        `ascendai-bridge.stage.straiker.ai`, and its host key is published, so stage pins it."""
        assert T.resolve_endpoint("dev") == {
            "env": "dev", "endpoint": "wss://ascendai-bridge.dev.straiker.ai/tunnel",
            "host_key": None, "host_key_source": None}
        assert T.resolve_endpoint("stage") == {
            "env": "stage", "endpoint": "wss://ascendai-bridge.stage.straiker.ai/tunnel",
            "host_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILdbcgnXLQ0PX4mltsX+dHYu3iV5dGIrtf3qTLuwswD6",
            "host_key_source": "built-in"}
        assert T.resolve_endpoint("prod") == {
            "env": "prod", "endpoint": "wss://ascendai-bridge.prod.straiker.ai/tunnel",
            "host_key": None, "host_key_source": None}
        assert set(T.ENVIRONMENTS) == {"dev", "stage", "prod"}
        assert "staging" not in " ".join(e["endpoint"] for e in T.ENVIRONMENTS.values())
        parsed = T.parse_key_line(T.STAGE_HOST_KEY)
        assert parsed["type"] == "ssh-ed25519", "the pinned key is a key line the agent can take"

    def test_the_overrides(self):
        r = T.resolve_endpoint("dev", "wss://relay.example/tunnel", "ssh-ed25519 AAAA")
        assert r == {"env": "dev", "endpoint": "wss://relay.example/tunnel",
                     "host_key": "ssh-ed25519 AAAA", "host_key_source": "flag"}
        r = T.resolve_endpoint("stage", None, "ssh-ed25519 BBBB")
        assert r["host_key"] == "ssh-ed25519 BBBB" and r["host_key_source"] == "flag"

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
        assert "--host-key" not in no_pin and "--ca-file" not in no_pin and "--fanout" not in no_pin

    def test_fanout_rides_last_on_both_runners_and_only_when_given(self):
        argv = T.build_argv(self.BIN, "check", org="1", allow=["a.corp:443"], endpoint="wss://e",
                            state_dir="/s", fanout=4)
        assert argv[-2:] == ["--fanout", "4"]
        argv = T.build_argv(self.DOCKER, "run", org="1", allow=["a.corp:443"], endpoint="wss://e",
                            state_dir="/s", fanout=16)
        assert argv[-2:] == ["--fanout", "16"] and argv[argv.index(T.IMAGE) + 1] == "run"
        assert "--fanout" not in T.build_argv(self.BIN, "key", state_dir="/s", fanout=4)

    def test_the_image_is_0_1_2_pinned_by_digest(self):
        """A re-pushed tag cannot change what runs: the reference carries the index digest
        (MEASURED with `docker buildx imagetools inspect`), and the tag stays for a human."""
        assert T.IMAGE == f"ghcr.io/straiker-ai/ascend-tunnel:{T.IMAGE_VERSION}@{T.IMAGE_DIGEST}"
        assert T.IMAGE_VERSION == "0.1.2"
        assert re.fullmatch(r"sha256:[0-9a-f]{64}", T.IMAGE_DIGEST)
        assert "0.1.0" not in T.IMAGE

    def test_the_install_hints_lead_with_what_exists(self):
        """MEASURED: the brew tap, winget manifest and scoop bucket do not exist yet; the Releases
        archive, the Docker image and the deb/rpm do. The macOS archive is ad-hoc signed."""
        hints = T.INSTALL_HINTS
        text = "\n".join(hints)
        order = [next(i for i, h in enumerate(hints) if h.lstrip().startswith(word))
                 for word in ("archive", "Docker", "Linux", "brew", "winget", "scoop")]
        assert order == sorted(order), "archive, Docker, deb/rpm, then the unpublished channels"
        assert "shasum -a 256 -c checksums.txt" in text and "gh attestation verify" in text
        assert "xattr -d com.apple.quarantine" in text and "ad-hoc signed" in text
        assert f"docker pull {T.IMAGE}" in text
        for word in ("brew", "winget", "scoop"):
            line = next(h for h in hints if h.lstrip().startswith(word))
            assert "(when published)" in line, word
        assert T.no_runner_message(["x"]).index("archive") < T.no_runner_message(["x"]).index("brew")

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
        for hint in ("brew install straiker-ai/tap/ascend-tunnel", "winget install Straiker.AscendTunnel",
                     "docker pull ghcr.io/straiker-ai/ascend-tunnel", "gh attestation verify"):
            assert hint in msg

    def test_docker_notes(self, monkeypatch):
        for v in T.PROXY_VARS:
            monkeypatch.delenv(v, raising=False)
        assert T.docker_notes(self.BIN, [{"host": "localhost"}]) == []
        notes = T.docker_notes(self.DOCKER, [{"host": "localhost"}])
        assert len(notes) == 1 and "host.docker.internal" in notes[0]
        # an app on this machine is often plain HTTP on a dev port: the note names both schemes
        assert "https://host.docker.internal.tun.straiker.ai/<path>" in notes[0]
        assert "http://host.docker.internal.tun.straiker.ai/<path> for a target that speaks plain HTTP" in notes[0]
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

# MEASURED 2026-10-14: the 0.1.4 agent's `check`, word for word. The published image
# (ghcr.io/straiker-ai/ascend-tunnel:0.1.4) ran it once over six targets in a Docker network:
# plain HTTP on 8089 and on 80, TLS on 8443 and on 80, a socket that accepts and closes on 9000,
# nothing listening on 9999. The 0.1.2 and 0.1.3 images, over the same six, print the form above.
CHECK_014 = (REPO / "tests" / "fixtures" / "tunnel_check_0.1.4_targets.txt").read_text()


PROD_403 = ("FAIL  relay WebSocket: relay wss://ascendai-bridge.prod.straiker.ai/tunnel: failed to "
            "WebSocket dial: expected handshake response status code 101 but got 403 (allow outbound "
            "HTTPS to it; set HTTPS_PROXY if you use a proxy)")
TIMEOUT = "FAIL  relay WebSocket: dial tcp: i/o timeout (allow outbound HTTPS to it; set HTTPS_PROXY if you use a proxy)"


class TestRelayRefusal:
    """MEASURED 2026-10-13 with the 0.1.2 agent: prod answers 403 at the WebSocket upgrade."""

    def test_the_status_is_read_off_the_measured_line(self):
        assert T.relay_refusal([PROD_403]) == 403
        assert T.relay_refusal(["INFO  x", PROD_403.replace("403", "502")]) == 502
        assert T.relay_refusal([TIMEOUT]) is None
        assert T.relay_refusal(["PASS  relay WebSocket upgraded over HTTPS"]) is None
        assert T.relay_refusal([]) is None
        assert T.relay_refusal(["WARN  relay WebSocket: expected handshake response status code 101 but got 403"]) is None

    def test_prod_403_means_not_enabled_and_nothing_else_does(self):
        msg = T.relay_not_enabled("prod", [PROD_403])
        assert msg and msg.startswith("the tunnel is not enabled on this environment yet")
        assert "--env stage" in msg and "support@straiker.ai" in msg
        assert T.relay_not_enabled("dev", [PROD_403]) is None
        assert T.relay_not_enabled("stage", [PROD_403]) is None
        assert T.relay_not_enabled("prod", [TIMEOUT]) is None
        assert T.relay_not_enabled("prod", [PROD_403.replace("403", "502")]) is None


class TestIdentityDirectory:
    """Which key the agent runs with. The CLI always passed its own directory; a customer who had
    run the binary by hand had a key at the binary's default directory, listed THAT, and a tunnel
    from the CLI ran as a second identity and stayed waiting."""

    @pytest.fixture
    def dirs(self, tmp_path, monkeypatch):
        cli, default = tmp_path / "state" / "tunnel", tmp_path / "Library" / "ascend-tunnel"
        monkeypatch.setattr(T, "tunnel_dir", lambda: cli)
        monkeypatch.setattr(T, "binary_default_state_dir", lambda: default)
        monkeypatch.delenv("TUNNEL_STATE_DIR", raising=False)
        return cli / "agent", default

    def test_nothing_anywhere_means_the_clis_own_directory(self, dirs):
        cli, _ = dirs
        r = T.resolve_identity()
        assert r == {"dir": cli, "source": "cli", "other": None, "note": None}
        assert T.agent_state_dir() == cli

    def test_a_key_the_binary_made_is_adopted_and_said(self, dirs):
        cli, default = dirs
        default.mkdir(parents=True)
        (default / "agent.key").write_text("k")
        r = T.resolve_identity()
        assert r["dir"] == default and r["source"] == "binary-default" and r["other"] is None
        assert "using the identity at" in r["note"] and str(default) in r["note"]
        assert T.agent_state_dir() == default

    def test_two_keys_keep_the_clis_and_name_the_other(self, dirs):
        cli, default = dirs
        for d in (cli, default):
            d.mkdir(parents=True)
            (d / "agent.key").write_text("k")
        r = T.resolve_identity()
        assert r["dir"] == cli and r["source"] == "cli" and r["other"] == default
        assert "another identity exists at" in r["note"] and f"--state-dir {default}" in r["note"]

    def test_the_flag_and_the_agents_variable_win_silently(self, dirs, monkeypatch, tmp_path):
        cli, default = dirs
        default.mkdir(parents=True)
        (default / "agent.key").write_text("k")
        r = T.resolve_identity(str(tmp_path / "mine"))
        assert r == {"dir": tmp_path / "mine", "source": "flag", "other": None, "note": None}
        monkeypatch.setenv("TUNNEL_STATE_DIR", str(tmp_path / "byhand"))
        r = T.resolve_identity()
        assert r["dir"] == tmp_path / "byhand" and r["source"] == "env" and r["note"] is None

    def test_a_directory_without_the_key_file_counts_for_nothing(self, dirs):
        cli, default = dirs
        default.mkdir(parents=True)                      # the directory, no agent.key
        assert T.resolve_identity()["source"] == "cli"

    def test_the_binarys_default_directory_per_platform(self, monkeypatch):
        monkeypatch.setattr(T.os, "name", "posix")
        monkeypatch.setattr(T.sys, "platform", "darwin")
        monkeypatch.setenv("HOME", "/h/x")
        assert T.binary_default_state_dir() == Path("/h/x/Library/Application Support/Straiker/ascend-tunnel")
        monkeypatch.setattr(T.sys, "platform", "linux")
        monkeypatch.setattr(T.os, "geteuid", lambda: 1000, raising=False)
        monkeypatch.delenv("XDG_STATE_HOME", raising=False)
        assert T.binary_default_state_dir() == Path("/h/x/.local/state/ascend-tunnel")
        monkeypatch.setenv("XDG_STATE_HOME", "/xdg")
        assert T.binary_default_state_dir() == Path("/xdg/ascend-tunnel")
        monkeypatch.setattr(T.os, "geteuid", lambda: 0, raising=False)
        assert T.binary_default_state_dir() == Path("/var/lib/straiker-tunnel")
        # Windows (%LOCALAPPDATA%\Straiker\ascend-tunnel) cannot be asserted here: pathlib refuses
        # to build a WindowsPath on a POSIX host.


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

    def test_the_0_1_2_agent_names_each_app_url_and_no_scheme(self):
        p = T.parse_check_lines(CHECK_OUTPUT.splitlines())
        assert p["app_url_for"] == {"chat.corp.internal:443": "https://chat.corp.internal.tun.straiker.ai",
                                    "api.corp.internal:8080": "https://api.corp.internal.tun.straiker.ai"}
        assert p["schemes_found"] == {}           # `target … reachable` says nothing of the scheme

    def test_the_0_1_4_agents_app_lines_and_the_scheme_each_target_answered_in(self):
        """0.1.4 names an app's URL as `app  host:port is reached at …` (0.1.2: `app URL for
        host:port: …`) and says which scheme each target answered in. Neither was read, so with
        0.1.4 `tunnel check` printed the 0.1.0 fallback's https:// line after the agent had
        warned that the target answers plain HTTP."""
        p = T.parse_check_lines(CHECK_014.splitlines())
        assert p["app_url_for"] == {
            "plain.corp.internal:8089": "https://plain.corp.internal.tun.straiker.ai",
            "tls.corp.internal:8443": "https://tls.corp.internal.tun.straiker.ai",
            "tls80.corp.internal:80": "http://tls80.corp.internal.tun.straiker.ai",
            "web.corp.internal:80": "http://web.corp.internal.tun.straiker.ai",
            "raw.corp.internal:9000": "https://raw.corp.internal.tun.straiker.ai",
            "down.corp.internal:9999": "https://down.corp.internal.tun.straiker.ai"}
        assert p["app_urls"] == list(p["app_url_for"].values())
        assert p["schemes_found"] == {
            "plain.corp.internal:8089": "http",       # WARN  answers plain HTTP, not TLS
            "tls.corp.internal:8443": "https",        # PASS  reachable (TLS)
            "tls80.corp.internal:80": "https",        # WARN  answers TLS on port 80
            "web.corp.internal:80": "http"}           # PASS  reachable (plain HTTP)
        # raw.corp.internal answered neither clearly and down.corp.internal was not reached:
        # nothing settles their scheme
        assert p["counts"] == {"PASS": 9, "FAIL": 1, "WARN": 2, "WAIT": 0, "INFO": 9}
        assert p["failed"] == 1

    def test_the_app_url_after_a_check_is_in_the_scheme_the_agent_found(self):
        allow = T.parse_allow(["plain.corp.internal:8089", "tls.corp.internal:8443",
                               "tls80.corp.internal:80", "web.corp.internal:80",
                               "raw.corp.internal:9000", "down.corp.internal:9999"])
        assert T.checked_app_urls(T.parse_check_lines(CHECK_014.splitlines()), allow) == [
            "http://plain.corp.internal.tun.straiker.ai", "https://tls.corp.internal.tun.straiker.ai",
            "https://tls80.corp.internal.tun.straiker.ai", "http://web.corp.internal.tun.straiker.ai",
            "https://raw.corp.internal.tun.straiker.ai", "https://down.corp.internal.tun.straiker.ai"]
        # nothing found (0.1.2): the URL the agent printed; nothing printed (0.1.0): the rule's
        allow = T.parse_allow(["chat.corp.internal", "api.corp.internal:8080"])
        assert T.checked_app_urls(T.parse_check_lines(CHECK_OUTPUT.splitlines()), allow) == [
            "https://chat.corp.internal.tun.straiker.ai", "https://api.corp.internal.tun.straiker.ai"]
        assert T.checked_app_urls(T.parse_check_lines([]), allow) == [f["app_url"] for f in allow]

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
