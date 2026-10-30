"""Offline contracts for the released tunnel; PATH binaries remain operator-owned."""
import pytest

import tunnel as T


RELEASE_IMAGE = (
    "ghcr.io/straiker-ai/ascend-tunnel:0.1.6@sha256:"
    "892b4aec63af03877b78bc1ca3208133451493c328c229e1efbca4e2cc6e8051"
)


def test_docker_fallback_is_the_verified_multiarch_release():
    assert T.IMAGE == RELEASE_IMAGE
    runner, notes = T.find_runner(
        "docker", which=lambda name: "/bin/docker" if name == "docker" else None,
        docker_ready=lambda _: (True, ""),
    )
    assert not notes and runner["image"] == RELEASE_IMAGE
    argv = T.build_argv(runner, "check", org="1234", allow=["target.example:443"],
                        endpoint="wss://relay.example/tunnel", state_dir="/state")
    assert argv[argv.index(RELEASE_IMAGE) + 1:] == [
        "check", "--org", "1234", "--allow", "target.example:443",
        "--relay", "wss://relay.example/tunnel", "--state-dir", T.CONTAINER_STATE_DIR,
    ]


@pytest.mark.parametrize("prefer", ["auto", "binary"])
def test_custom_path_binary_is_not_probed_replaced_or_routed_to_docker(prefer):
    def forbidden(*args):
        pytest.fail("PATH selection must not probe Docker or a custom binary's version")

    runner, notes = T.find_runner(
        prefer, which=lambda name: "/custom/ascend-tunnel" if name == T.BINARY else forbidden(),
        docker_ready=forbidden,
    )
    assert not notes
    assert runner == {"kind": "binary", "path": "/custom/ascend-tunnel",
                      "label": "ascend-tunnel at /custom/ascend-tunnel"}
    assert T.build_argv(runner, "key", state_dir="/existing/identity") == [
        "/custom/ascend-tunnel", "key", "--state-dir", "/existing/identity",
    ]


def test_relay_defaults_match_release_and_custom_relay_gets_no_unrelated_pin():
    stage = T.resolve_endpoint("stage")
    assert stage["endpoint"] == "wss://ascendai-bridge.stage.straiker.ai/tunnel"
    assert stage["host_key_source"] == "built-in"
    for env in ("dev", "stage", "prod"):
        assert T.resolve_endpoint(env)["host_key"].startswith("ssh-ed25519 ")
        custom = T.resolve_endpoint(env, "wss://custom.example/tunnel")
        assert custom["host_key"] is None and custom["host_key_source"] is None
        explicit = T.resolve_endpoint(env, "wss://custom.example/tunnel", "ssh-ed25519 TEST")
        assert explicit["host_key"] == "ssh-ed25519 TEST"
        assert explicit["host_key_source"] == "flag"
    override = T.resolve_endpoint("prod", stage["endpoint"])
    assert override["host_key"] == stage["host_key"]


@pytest.mark.parametrize("env", ["dev", "stage", "prod"])
@pytest.mark.parametrize("blank", [" ", " \t ", "\r\n"])
def test_blank_host_key_preserves_published_pin_for_older_path_binary(env, blank):
    resolved = T.resolve_endpoint(env, host_key=blank)
    assert resolved["host_key"] == T.ENVIRONMENTS[env]["host_key"]
    assert resolved["host_key_source"] == "built-in"
    argv = T.build_argv(
        {"kind": "binary", "path": "/custom/old-tunnel"}, "check",
        org="1234", allow=["target.example:443"], endpoint=resolved["endpoint"],
        host_key=resolved["host_key"], state_dir="/existing/identity",
    )
    assert argv[argv.index("--host-key") + 1] == T.ENVIRONMENTS[env]["host_key"]


@pytest.mark.parametrize("blank", [" ", " \t ", "\r\n"])
def test_blank_host_key_does_not_assign_a_pin_to_a_custom_relay(blank):
    resolved = T.resolve_endpoint("prod", "wss://custom.example/tunnel", blank)
    assert resolved["host_key"] is None and resolved["host_key_source"] is None


@pytest.mark.parametrize("endpoint", [None, "wss://custom.example/tunnel"])
def test_padded_explicit_valid_pin_keeps_precedence(endpoint):
    explicit = T.ENVIRONMENTS["dev"]["host_key"]
    resolved = T.resolve_endpoint("prod", endpoint, " \t" + explicit + "\r\n")
    assert resolved["host_key"] == explicit and resolved["host_key_source"] == "flag"


@pytest.mark.parametrize("modern", [False, True])
def test_old_and_new_check_identity_and_urls_have_the_same_contract(modern):
    if modern:
        lines = [
            "== Tunnel: this machine -> Straiker",
            "INFO   agent     org 1234, agent 00112233",
            "INFO   agent     key (paste into each app's _tunnel_agent_keys): synthetic-public-key",
            "PASS   login     an Ascend app lists this agent's key: the relay accepts it",
            "RESULT PASS: this machine reaches Straiker, and an app lists this agent",
            "== Apps: this machine -> your apps",
            "INFO   app       target.example:443 is reached at https://target.example.tun.straiker.ai/... (the Ascend app's URL, with its path)",
            "PASS   target    target.example:443 reachable (TLS)",
        ]
    else:
        lines = [
            "INFO  org 1234, agent 00112233",
            "INFO  agent key (paste into the app's _tunnel_agent_keys): synthetic-public-key",
            "PASS  an Ascend app lists this agent's key: the relay accepts it",
            "INFO  app URL for target.example:443: https://target.example.tun.straiker.ai/... (the Ascend app's URL, with its path)",
            "PASS  target target.example:443 reachable",
        ]
    got = T.parse_check_lines(lines)
    assert (got["org"], got["agent_id"], got["key"]) == ("1234", "00112233", "synthetic-public-key")
    assert got["app_urls"] == ["https://target.example.tun.straiker.ai"]
    assert got["listed"] and not got["waiting"] and not got["failed"]
    assert got["counts"] == {"PASS": 2, "FAIL": 0, "WARN": 0, "WAIT": 0, "INFO": 3}


def test_new_check_without_an_identity_does_not_invent_key_or_authorization():
    got = T.parse_check_lines([
        "INFO   agent     org 1234; no agent key yet in /synthetic/state: the agent creates it when it first runs (this check creates nothing)",
        "PASS   tunnel    relay host key matches the pinned key",
        "INFO   login     not checked: the agent has no key yet (it creates one when it first runs)",
        "RESULT PASS: this machine reaches Straiker",
    ])
    assert got["key"] is None and got["agent_id"] is None
    assert not got["listed"] and not got["waiting"]


@pytest.mark.parametrize("status", ["WAIT", "FAIL"])
def test_new_check_does_not_hide_wait_or_failure_behind_section_results(status):
    text = f"{status}   login     no Ascend app lists this agent's key yet"
    got = T.parse_check_lines([text, "RESULT PASS: this machine reaches every app"])
    assert not got["listed"]
    assert got["waiting"] is (status == "WAIT")
    assert got["failed"] == (1 if status == "FAIL" else 0)
    assert got["lines"] == [{"status": status, "text": text.split(None, 1)[1]}]
