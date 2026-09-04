"""
test_cdp_and_app_type_guard.py — two auth gaps that no flag could reach, plus a UX wart.

1. **`--cdp`: attach to a browser you are already signed into.** An Entra / SAML / WS-Fed gated
   target has no credential a CLI can be handed; the session lives in the operator's browser.
   `runtime/adapters/browser.py` has supported `cdp_url` all along — but the CAPTURE
   (`capture_url`) launched its own Chromium, which stopped at the login wall and never saw the
   widget, so no config could be derived. The flag now reaches the capture, which attaches with
   `connect_over_cdp`, reuses the signed-in context, and never closes the operator's browser; every
   browser config that gets written carries `cdp_url` through ONE helper, `_stamp_cdp`, so the
   assessment attaches the same way the capture proved.

2. **`app create --type api` silently dropped a dynamic auth block.** `_spec_from_config` borrowed
   url/headers/body and never `auth`; an `api`-type app can only carry static headers, because the
   platform calls the target directly. An OAuth2 target registered that way 401'd on every probe,
   unwarned. It is now refused — BEFORE `_client()`, because a local check on a local file must not
   require a credential to run (it used to print "no token" instead of the real problem).

3. `target add --login-url` printed `wrote <config>` twice (the second write attaches the recipe).
"""
import re
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
for p in ("shells/cli", "runtime", "control"):
    sys.path.insert(0, str(REPO / p))
import ascend  # noqa: E402

SRC = (REPO / "shells" / "cli" / "ascend.py").read_text()
CAP = (REPO / "runtime" / "discovery" / "capture.py").read_text()


def _body(fn):
    m = re.search(rf"^def {fn}\(.*?(?=^def )", SRC, re.S | re.M)
    assert m, f"{fn} not found"
    return m.group(0)


class TestCdpReachesTheCapture:
    def test_the_flag_is_on_every_onboarding_parser(self):
        import argparse
        p = ascend.build_parser()
        def leaf(path):
            n = p
            for seg in path:
                n = [a for a in n._actions if isinstance(a, argparse._SubParsersAction)][0].choices[seg]
            return {o for a in n._actions for o in (a.option_strings or [])}
        for path in (("target", "add"), ("onboard",), ("adapter", "build"), ("map",), ("discover",)):
            assert "--cdp" in leaf(path), f"--cdp missing on {' '.join(path)}"

    def test_the_capture_attaches_instead_of_launching(self):
        assert "connect_over_cdp(endpoint)" in CAP
        assert 'for channel in ([] if browser else _browser_channels(browser_channel))' in CAP, (
            "an attached browser must skip the launch loop, or the capture launches a second, "
            "signed-out browser anyway")

    def test_the_signed_in_context_is_reused(self):
        assert "ctx = browser.contexts[0]" in CAP, (
            "a new_context() is a clean profile with no cookies — that defeats attaching at all")

    def test_the_operators_browser_is_never_closed(self):
        closes = re.findall(r"^([ \t]+)await browser\.close\(\)", CAP, re.M)
        assert closes, "no close sites found"
        guarded = re.findall(r"^([ \t]+)if not cdp:[^\n]*\n\1    await browser\.close\(\)", CAP, re.M)
        assert len(guarded) == len(closes), (
            f"{len(closes)} browser.close() sites, {len(guarded)} guarded — an unguarded one kills "
            f"the operator's real Chrome when the capture ends")

    @pytest.mark.parametrize("fn", ["cmd_onboard", "cmd_discover"])
    def test_both_commands_pass_the_flag_through(self, fn):
        assert 'cdp=getattr(args, "cdp", None)' in _body(fn), f"{fn} captures without --cdp"


class TestEveryBrowserConfigWriteIsStamped:
    """Three places write a browser config. One rule, three call sites — the drift guard."""

    @pytest.mark.parametrize("fn", ["cmd_onboard", "_finish_discovery", "_finish_browser_adapter"])
    def test_it_calls_the_shared_stamp(self, fn):
        assert "_stamp_cdp(" in _body(fn), (
            f"{fn} writes a config without stamping cdp_url — the capture attached to the "
            f"signed-in browser, but the assessment will launch a signed-out one")

    def test_the_stamp_only_touches_browser_configs(self):
        class A:
            cdp = "http://127.0.0.1:9222"
        assert ascend._stamp_cdp({"adapter": "direct_api"}, A()) == {"adapter": "direct_api"}
        assert ascend._stamp_cdp({"adapter": "browser"}, A())["cdp_url"] == "http://127.0.0.1:9222"

    def test_no_flag_means_no_stamp(self):
        class A:
            cdp = None
        assert "cdp_url" not in ascend._stamp_cdp({"adapter": "browser"}, A())

    def test_the_default_endpoint_is_the_chrome_default(self):
        """`--cdp` with no value must mean the port `chrome --remote-debugging-port=9222` opens."""
        p = ascend.build_parser()
        import argparse
        n = p
        for seg in ("target", "add"):
            n = [a for a in n._actions if isinstance(a, argparse._SubParsersAction)][0].choices[seg]
        act = next(a for a in n._actions if "--cdp" in (a.option_strings or []))
        assert act.nargs == "?" and act.const == "http://127.0.0.1:9222"


class TestApiTypeRefusesADynamicAuthBlock:
    def _guard_pos(self):
        body = _body("cmd_app_create")
        return body.index("auth_kind_unsupported_by_app_type"), body.index("c = _client(args)")

    def test_the_guard_runs_before_the_platform_client(self):
        guard, client = self._guard_pos()
        assert guard < client, (
            "the guard sat after _client(); without a PAT the operator saw 'no token' instead of "
            "the actual problem with their config")

    @pytest.mark.parametrize("kind", ["oauth2", "csrf", "derived_multihop"])
    def test_each_dynamic_kind_is_refused_for_api(self, kind, tmp_path, monkeypatch, capsys):
        cfg = tmp_path / "dyn.json"
        cfg.write_text('{"adapter":"direct_api","url":"https://x/chat","auth":{"type":"%s"}}' % kind)
        class Args:
            type, name, config = "api", "X", str(cfg)
            json = False; verbose = False; token = None; base = None
        monkeypatch.delenv("STRAIKER_PAT", raising=False)
        with pytest.raises(SystemExit):
            ascend.cmd_app_create(Args())
        # `SystemExit` alone is not evidence: with the guard bypassed, cmd_app_create falls through
        # to _client(), which exits on the missing PAT with the SAME code. A first draft of this
        # test asserted only the exit and passed with oauth2 removed from the guard. The refusal
        # has to be THIS refusal.
        err = capsys.readouterr().err
        assert "handshake" in err and kind in err, (
            f"exited, but not because of the guard: {err.strip().splitlines()[-1][:100]!r}")
        assert "no token" not in err, "died on the missing PAT — the guard did not run first"

    def test_the_borrow_surfaces_the_auth_kind(self, tmp_path):
        cfg = tmp_path / "s.json"
        cfg.write_text('{"url":"https://x","auth":{"type":"oauth2"}}')
        class Args:
            config = str(cfg)
        import api
        out = ascend._spec_from_config(Args(), api)
        assert out.get("_auth_type") == "oauth2"

    def test_a_static_config_is_not_refused(self, tmp_path):
        """A bearer header IS something an api-type app can carry. Do not over-refuse."""
        cfg = tmp_path / "st.json"
        cfg.write_text('{"url":"https://x","headers":{"Authorization":"Bearer t"},"auth":{"type":"static"}}')
        class Args:
            config = str(cfg)
        import api
        assert ascend._spec_from_config(Args(), api).get("_auth_type") == "static"
        body = _body("cmd_app_create")
        assert '"static"' not in body.split("auth_kind_unsupported_by_app_type")[0].split("_auth_kind in")[1]


class TestTheConfigIsAnnouncedOnce:
    def test_the_recipe_rewrite_is_quiet(self):
        assert "_write_named_config(cfg, cfg_name, exact=True, quiet=True)" in _body("cmd_onboard")

    def test_quiet_suppresses_only_the_announcement(self):
        m = re.search(r"^def _write_named_config\(.*?(?=^def )", SRC, re.S | re.M)
        assert 'if not quiet:\n        _ok(f"wrote {path}")' in m.group(0)
