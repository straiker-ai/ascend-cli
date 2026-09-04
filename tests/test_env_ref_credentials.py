"""
test_env_ref_credentials.py — an `env:` reference must resolve, or fail loudly.

Both defects here were found by driving real onboardings against gated targets, and both ended the
same way: the operator gave up on `env:` and put the literal secret in the config or on the command
line. A credential-hygiene feature that pushes you back to plaintext is worse than none.

  1. `--login-body 'client_id=env:DEMO_ID&...'` POSTed the LITERAL string "env:DEMO_ID". The refs
     were recorded into the runtime auth block correctly; the CLI's own onboarding-time login call
     never resolved them, so the exchange 401'd.

  2. A relay inherits os.environ. Started from a shell that does not export the variable the config
     references, it came up healthy and was then refused by the target on every probe — which
     scores as no findings, the exact false pass the design exists to prevent.
"""
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
for p in ("shells/cli", "runtime", "control"):
    if str(REPO / p) not in sys.path:
        sys.path.insert(0, str(REPO / p))
import ascend  # noqa: E402
import supervisor  # noqa: E402


class TestLoginBodyRefs:
    def test_a_set_variable_is_substituted(self, monkeypatch):
        monkeypatch.setenv("DEMO_ID", "real-client-id")
        got = ascend._resolve_login_refs({"client_id": "env:DEMO_ID", "grant_type": "cc"},
                                         "--login-body")
        assert got == {"client_id": "real-client-id", "grant_type": "cc"}

    def test_the_literal_ref_never_reaches_the_wire(self, monkeypatch):
        monkeypatch.setenv("DEMO_ID", "real-client-id")
        got = ascend._resolve_login_refs({"client_id": "env:DEMO_ID"}, "--login-body")
        assert "env:" not in got["client_id"], "the ref itself must not be POSTed"

    def test_an_unset_variable_fails_loudly_naming_it(self, monkeypatch):
        monkeypatch.delenv("DEMO_MISSING", raising=False)
        with pytest.raises(SystemExit):
            ascend._resolve_login_refs({"client_id": "env:DEMO_MISSING"}, "--login-body")

    def test_non_ref_values_pass_through_untouched(self):
        body = {"grant_type": "client_credentials", "scope": "read write"}
        assert ascend._resolve_login_refs(body, "--login-body") == body

    def test_a_form_body_of_none_is_not_mangled(self):
        assert ascend._resolve_login_refs(None, "--login-body") is None


class TestRelayRefusesUnresolvableRefs:
    def _cfg(self, tmp_path, monkeypatch, text):
        cfg = tmp_path / "gated.json"
        cfg.write_text(text, encoding="utf-8")
        monkeypatch.setattr(supervisor, "_unresolved_env_refs",
                            supervisor._unresolved_env_refs)  # keep the real one
        import configs
        monkeypatch.setattr(configs, "resolve_config_path", lambda ref: cfg)
        return cfg

    def test_start_refuses_and_names_the_variable(self, tmp_path, monkeypatch):
        self._cfg(tmp_path, monkeypatch,
                  '{"endpoint":"http://x/chat","headers":{"X-Key":"env:ACME_KEY"}}')
        monkeypatch.delenv("ACME_KEY", raising=False)
        monkeypatch.setattr(supervisor, "is_running", lambda a: False)
        r = supervisor.start("aapp_1", config="gated", adapter=None, api_key="k")
        assert "error" in r and "ACME_KEY" in r["error"]
        assert r["missing_env"] == ["ACME_KEY"]

    def test_it_says_why_this_matters(self, tmp_path, monkeypatch):
        self._cfg(tmp_path, monkeypatch,
                  '{"endpoint":"http://x","headers":{"X-Key":"env:ACME_KEY"}}')
        monkeypatch.delenv("ACME_KEY", raising=False)
        monkeypatch.setattr(supervisor, "is_running", lambda a: False)
        r = supervisor.start("aapp_1", config="gated", adapter=None, api_key="k")
        assert "measured nothing" in r["error"], "must name the false-pass consequence"

    def test_a_set_variable_does_not_block_start(self, tmp_path, monkeypatch):
        self._cfg(tmp_path, monkeypatch,
                  '{"endpoint":"http://x","headers":{"X-Key":"env:ACME_KEY"}}')
        monkeypatch.setenv("ACME_KEY", "s3cret")
        assert supervisor._unresolved_env_refs("gated") == []

    def test_a_config_with_no_refs_is_unaffected(self, tmp_path, monkeypatch):
        self._cfg(tmp_path, monkeypatch, '{"endpoint":"http://x","headers":{"X":"plain"}}')
        assert supervisor._unresolved_env_refs("gated") == []

    def test_every_missing_variable_is_listed(self, tmp_path, monkeypatch):
        self._cfg(tmp_path, monkeypatch,
                  '{"headers":{"A":"env:ONE","B":"env:TWO"},"body":{"c":"env:ONE"}}')
        for n in ("ONE", "TWO"):
            monkeypatch.delenv(n, raising=False)
        assert supervisor._unresolved_env_refs("gated") == ["ONE", "TWO"]


def test_the_login_exchange_actually_calls_the_resolver():
    """Source discipline: a helper nobody calls is the bug, not the fix.

    The unit tests above pass whether or not `_login_for_token` uses the resolver, so the wiring
    needs its own assertion — this is the drift pattern that produced the original defect, where
    `_login_for_token` and `_apply_login_auth` each existed and neither reached the other.
    """
    import inspect
    src = inspect.getsource(ascend._login_for_token)
    assert '_resolve_login_refs(body, "--login-body")' in src
    assert '_resolve_login_refs(form, "--login-body")' in src, (
        "a form-encoded client_credentials body is the common OAuth2 case and must resolve too")


def test_the_supervisor_actually_checks_before_spawning():
    import inspect
    src = inspect.getsource(supervisor.start)
    assert "_unresolved_env_refs(config)" in src
    assert src.index("_unresolved_env_refs") < src.index("subprocess.Popen"), (
        "the check must run BEFORE the relay is spawned")
