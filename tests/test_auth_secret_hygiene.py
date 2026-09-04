"""
test_auth_secret_hygiene.py — a credential given on the command line never lands in a config file
when it is written as an env: reference; the plaintext ones are warned about; the first request of
an onboarding is guarded against link-local/metadata hosts; printed configs are redacted.

Before: `_target_auth` baked every flag as a literal header (only HAR-derived auth ever used
`env:`), `probe.build_config` recorded `inline_secret_headers` and nothing printed it, `target add`
had no egress guard while `adapter build` did, two prints showed configs with credentials, and the
one warning about withheld credential-shaped headers crashed on arity (`_warn(args, msg)`).
"""
import inspect
import json
import re
import sys
import types
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
for p in ("shells/cli", "runtime", "control"):
    if str(REPO / p) not in sys.path:
        sys.path.insert(0, str(REPO / p))
import ascend  # noqa: E402

SRC = (REPO / "shells" / "cli" / "ascend.py").read_text()


def ns(**kw):
    base = dict(header=None, bearer=None, token_file=None, api_key=None, basic=None, cookie=None,
                allow_internal=False, _login_auth=None)
    base.update(kw)
    return types.SimpleNamespace(**base)


class TestEnvReferencesResolveForTheProbeAndAreRecorded:
    def test_bearer(self, monkeypatch):
        monkeypatch.setenv("T_TOK", "s3cret-token")
        a = ns(bearer="env:T_TOK")
        headers, query = ascend._target_auth(a)
        assert headers["Authorization"] == "Bearer s3cret-token"
        block, strip = a._static_auth
        assert block == {"type": "static", "mode": "bearer", "value_ref": "env:T_TOK"} and strip == ("header", "Authorization")

    def test_api_key_header_and_query(self, monkeypatch):
        monkeypatch.setenv("T_KEY", "k-123")
        a = ns(api_key="X-API-Key:env:T_KEY")
        headers, _ = ascend._target_auth(a)
        assert headers["X-API-Key"] == "k-123" and a._static_auth[0]["in"] == "header"
        b = ns(api_key="key:env:T_KEY:in=query")
        _, query = ascend._target_auth(b)
        assert query == {"key": "k-123"} and b._static_auth == (
            {"type": "static", "mode": "api_key", "name": "key", "in": "query", "value_ref": "env:T_KEY"}, ("query", "key"))

    def test_basic_keeps_the_user_literal_and_references_the_password(self, monkeypatch):
        monkeypatch.setenv("T_PW", "hunter2")
        a = ns(basic="demo:env:T_PW")
        headers, _ = ascend._target_auth(a)
        assert headers["Authorization"].startswith("Basic ")
        assert a._static_auth[0] == {"type": "static", "mode": "basic", "username_ref": "literal:demo", "password_ref": "env:T_PW"}

    def test_cookie_and_custom_header(self, monkeypatch):
        monkeypatch.setenv("T_S", "sess-1")
        a = ns(cookie="session=env:T_S")
        headers, _ = ascend._target_auth(a)
        assert headers["Cookie"] == "session=sess-1" and a._static_auth[0]["mode"] == "cookie"
        b = ns(header=["X-Auth-Token: env:T_S"])
        headers, _ = ascend._target_auth(b)
        assert headers["X-Auth-Token"] == "sess-1"
        assert b._static_auth[0] == {"type": "static", "mode": "custom", "name": "X-Auth-Token", "value_ref": "env:T_S", "template": "{{VALUE}}"}

    def test_literals_still_work_and_record_nothing(self):
        a = ns(bearer="plain-token", header=["X-Extra: 1"])
        headers, _ = ascend._target_auth(a)
        assert headers == {"X-Extra": "1", "Authorization": "Bearer plain-token"} and a._static_auth is None

    def test_an_unset_variable_is_named_and_refused(self, monkeypatch, capsys):
        monkeypatch.delenv("T_MISSING", raising=False)
        with pytest.raises(SystemExit):
            ascend._target_auth(ns(bearer="env:T_MISSING"))
        assert "T_MISSING" in capsys.readouterr().err

    def test_two_referenced_credentials_are_refused(self, monkeypatch, capsys):
        monkeypatch.setenv("A1", "x"); monkeypatch.setenv("A2", "y")
        with pytest.raises(SystemExit):
            ascend._target_auth(ns(bearer="env:A1", cookie="s=env:A2"))
        assert "one environment-referenced credential" in capsys.readouterr().err


class TestFinalizeWritesTheReferenceNotTheValue:
    def test_header_literal_is_replaced_by_the_block(self, monkeypatch, capsys):
        monkeypatch.setenv("T_KEY", "k-123")
        a = ns(api_key="X-API-Key:env:T_KEY")
        headers, _ = ascend._target_auth(a)
        cfg = {"adapter": "direct_api", "endpoint": "http://h/chat", "headers": {**headers, "X-Other": "1"},
               "_probe": {"inline_secret_headers": ["X-API-Key"]}}
        out = ascend._finalize_target_auth(cfg, a)
        assert "k-123" not in json.dumps(out), "the secret must not be in what gets written"
        assert out["auth"]["value_ref"] == "env:T_KEY" and out["headers"] == {"X-Other": "1"}
        err = capsys.readouterr().err
        assert "referenced as env:T_KEY" in err and "plaintext" not in err

    def test_query_key_is_stripped_from_the_url(self, monkeypatch):
        monkeypatch.setenv("T_KEY", "k-123")
        a = ns(api_key="key:env:T_KEY:in=query")
        ascend._target_auth(a)
        out = ascend._finalize_target_auth({"endpoint": "http://h/chat?key=k-123&v=2"}, a)
        assert out["endpoint"] == "http://h/chat?v=2" and out["auth"]["in"] == "query"

    def test_a_plaintext_credential_header_is_warned_about(self, capsys):
        cfg = {"headers": {"X-API-Key": "sk-live"}, "_probe": {"inline_secret_headers": ["X-API-Key"]}}
        ascend._finalize_target_auth(cfg, ns())
        err = capsys.readouterr().err
        assert "plaintext" in err and "X-API-Key" in err and "env:" in err

    def test_login_and_env_credential_together_are_refused(self, monkeypatch):
        monkeypatch.setenv("T", "x")
        a = ns(bearer="env:T", _login_auth={"type": "derived_multihop"})
        ascend._target_auth(a)
        with pytest.raises(SystemExit):
            ascend._finalize_target_auth({}, a)

    @pytest.mark.parametrize("fn", ["cmd_onboard", "_finish_discovery"])
    def test_every_writer_finalizes(self, fn):
        assert "_finalize_target_auth(" in inspect.getsource(getattr(ascend, fn))


class TestEgressGuard:
    def test_metadata_host_is_refused_before_any_request(self, capsys):
        with pytest.raises(SystemExit) as ei:
            ascend._guard_egress("http://169.254.169.254/latest/meta-data/", ns())
        assert ei.value.code == ascend.EXIT_USAGE and "SSRF" in capsys.readouterr().err

    def test_allow_internal_and_loopback_pass(self):
        assert ascend._guard_egress("http://169.254.169.254/x", ns(allow_internal=True)) is None
        assert ascend._guard_egress("http://127.0.0.1:8920/chat", ns()) is None
        assert ascend._guard_egress(None, ns()) is None

    def test_onboard_guards_every_source_before_its_first_request(self):
        src = inspect.getsource(ascend.cmd_onboard)
        assert src.count("_guard_egress(") >= 5
        # api: the guard precedes the probe call
        assert src.index("_guard_egress(args.api, args)") < src.index("res = probe_api(")
        assert src.index("_guard_egress(args.url, args)") < src.index("ev = capture_url(")

    def test_finish_discovery_uses_the_shared_guard(self):
        src = inspect.getsource(ascend._finish_discovery)
        assert "_guard_egress(" in src and "check_egress(" not in src

    def test_target_add_takes_allow_internal(self):
        import subprocess
        r = subprocess.run([sys.executable, str(REPO / "shells/cli/ascend.py"), "target", "add", "--help"],
                           capture_output=True, text=True)
        assert "--allow-internal" in r.stdout


class TestPrintsAndWarnings:
    def test_warn_is_never_called_with_args(self):
        assert not re.search(r"_warn\(args\b", SRC), "_warn(msg) takes one argument; this crashed the withheld-headers path"

    def test_printed_configs_are_redacted(self):
        fd = inspect.getsource(ascend._finish_discovery)
        assert '"config": _redact(cfg)' in fd and "json.dumps(_redact(cfg)" in fd
        assert not re.search(r"json\.dumps\(cfg\b", fd)
        fb = inspect.getsource(ascend._finish_browser_adapter)
        assert '"config": manual_redact(cfg)' in fb

    @pytest.mark.parametrize("name", ["Authorization", "Cookie", "X-API-Key", "x-api-key", "X-Auth-Token",
                                      "Set-Cookie", "X-CSRF-Token", "Proxy-Authorization", "X-Goog-Api-Key"])
    def test_redact_hides_every_credential_header_name(self, name):
        """Keys were normalised (`-` -> `_`) and then compared against a set written WITH dashes, so
        only the two dash-less names ever matched. Seen live: `adapter build --json` printed
        `X-API-Key: sk-…` in clear."""
        import manual
        out = manual.redact({"headers": {name: "sk-live-123", "X-Other": "1"}})
        assert out["headers"]["X-Other"] == "1"
        assert "sk-live-123" not in json.dumps(out), name


class TestQueryParamsReachTheWire:
    """`mode: api_key, in: query` materialised into `params`, and no adapter reads `params`."""

    def test_material_params_fold_into_the_endpoint(self):
        from layers.auth import AuthMaterial
        m = AuthMaterial(params={"key": "k-1"})
        assert m.merge_into_config({"endpoint": "http://h/chat"})["endpoint"] == "http://h/chat?key=k-1"
        assert m.merge_into_config({"url": "http://h/chat?v=2&key=old"})["url"] == "http://h/chat?v=2&key=k-1"
        assert m.merge_into_config({"headers": {}}).get("params") == {"key": "k-1"}

    def test_static_query_key_end_to_end_through_merge_auth(self, monkeypatch):
        monkeypatch.setenv("T_QK", "k-9")
        import dispatch
        cfg = {"endpoint": "http://h/chat", "auth": {"type": "static", "mode": "api_key", "name": "key",
                                                    "in": "query", "value_ref": "env:T_QK"}}
        merged = dispatch.merge_auth(cfg)
        assert merged["endpoint"] == "http://h/chat?key=k-9" and "_auth_error" not in merged
