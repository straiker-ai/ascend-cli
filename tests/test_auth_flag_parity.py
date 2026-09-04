"""
test_auth_flag_parity.py — `target add` must be able to onboard a target that is behind a login.

Driven against a factory of auth-gated agents, **4 of 8 schemes could not be onboarded at all**
through `ascend target add`. Not because the runtime lacked the capability — `runtime/layers/auth.py`
has implemented `static`/`oauth2`/`csrf`/`derived_multihop` plus four lifecycles all along, and
`call_target.TargetCaller` re-authenticates before every probe — but because nothing on the primary
command could *describe* a handshake to it.

Three defects, each a seam that was built and never joined:

1. **The login flow was orphaned.** `_login_for_token` computed a proper `derived_multihop` block;
   `_apply_login_auth` wrote one onto a config. `_login_for_token` had exactly one caller
   (`cmd_discover`) and `_apply_login_auth` exactly one other (`cmd_onboard`), and neither path ran
   both. So `adapter build --login-url` shipped a FROZEN `Authorization: Bearer <token>` and no
   auth block — precisely the failure its own comment says the mechanism exists to prevent. A
   60-second token was dead 70 seconds later in field testing.

2. **`target add` lacked the flags its own error recommends.** `probe.py` answers a 401 by naming
   `--basic`, `--cookie`, `--login-url`; `_add_onboard_args` registered none of them. Following the
   CLI's printed advice returned `unrecognized arguments`.

3. **`--login-body` was JSON-only**, so RFC 6749 `client_credentials` — form-encoded, and the most
   common enterprise flow there is — could not be expressed on any command. The runtime's own
   OAuth2 materializer has always POSTed form-encoded; only this helper disagreed.

Measured after: 8 of 8 gated schemes onboard with a real answer (api-key header/query, basic,
access-code, token-ttl, oauth2, cookie-gate, csrf); hmac and nonce are refused and routed to
`--scaffold`, which is correct — a per-request signature is not static config.
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
PROBE = (REPO / "runtime" / "discovery" / "probe.py").read_text()

AUTH_FLAGS = ["--bearer", "--api-key", "--header", "--basic", "--cookie", "--token-file",
              "--body-field", "--login-url", "--login-body", "--token-path", "--login-method",
              "--token-regex", "--token-header", "--insecure", "--ca-bundle", "--client-cert",
              "--client-key", "--proxy"]


def _flags(*path):
    p = ascend.build_parser()
    node = [a for a in p._actions if getattr(a, "choices", None)][0].choices[path[0]]
    for seg in path[1:]:
        node = [a for a in node._actions if getattr(a, "choices", None)][0].choices[seg]
    return {o for a in node._actions for o in (a.option_strings or [])}


class TestEveryOnboardingCommandCanDescribeAuth:
    @pytest.mark.parametrize("flag", AUTH_FLAGS)
    def test_target_add_has_it(self, flag):
        assert flag in _flags("target", "add"), (
            f"`target add` cannot express {flag} — it is the command the docs make step one, and "
            f"it was strictly less capable for auth than the `adapter build` 1.1.2 demoted")

    @pytest.mark.parametrize("flag", AUTH_FLAGS)
    def test_adapter_build_still_has_it(self, flag):
        """Back-compat: the demoted command must not lose anything in the shuffle."""
        assert flag in _flags("adapter", "build")

    def test_onboard_matches_target_add_on_auth(self):
        """`onboard` is the pre-1.1 spelling of the same command and shares the parser helper.

        Compared on AUTH flags only: `target add` also owns `--run`, which chains straight into an
        assessment and has nothing to do with credentials.
        """
        ta, ob = _flags("target", "add"), _flags("onboard")
        assert {f for f in AUTH_FLAGS if f in ta} == {f for f in AUTH_FLAGS if f in ob}

    def test_the_flags_are_declared_once(self):
        """A second copy is how these two parsers diverged in the first place."""
        assert len(re.findall(r"^def _add_target_auth_args\(", SRC, re.M)) == 1
        for fn in ("_add_onboard_args", "_add_build_args"):
            body = re.search(rf"^def {fn}\(.*?(?=^def )", SRC, re.S | re.M).group(0)
            assert "_add_target_auth_args(s)" in body, f"{fn} does not use the shared block"
            assert '"--login-url"' not in body, f"{fn} re-declares an auth flag of its own"


class TestTheErrorOnlyNamesFlagsThatExist:
    """The hint told operators to use flags the command did not have — a dead end printed by the
    tool itself, on the commonest failure there is."""

    def test_every_flag_in_the_auth_hint_is_real(self):
        hint = re.search(r'return \("auth_required",(.*?)\n\n', PROBE, re.S)
        assert hint, "the auth_required diagnosis moved"
        named = set(re.findall(r"--[a-z][a-z0-9-]+", hint.group(1)))
        missing = sorted(named - _flags("target", "add"))
        assert not missing, (
            f"the auth error recommends {missing}, which `target add` does not accept — typing "
            f"the CLI's own advice returns `unrecognized arguments`")

    def test_it_routes_computed_credentials_to_a_custom_adapter(self):
        """HMAC/nonce are not static config. Saying so beats letting someone hunt for a flag."""
        assert "--scaffold" in PROBE and "HMAC" in PROBE


class TestLoginBodyAcceptsWhatOAuth2ActuallySends:
    @pytest.mark.parametrize("raw,as_json,as_form", [
        ('{"code":"1234"}', {"code": "1234"}, None),
        ("grant_type=client_credentials&client_id=cid",
         None, {"grant_type": "client_credentials", "client_id": "cid"}),
        ("", {}, None),
        (None, {}, None),
    ])
    def test_shape_decides(self, raw, as_json, as_form):
        body, form = ascend._parse_login_body(raw)
        assert body == as_json and form == as_form

    def test_the_rfc6749_grant_parses(self):
        """The exact string every IdP's docs print. It died with 'not valid JSON' before."""
        _, form = ascend._parse_login_body(
            "grant_type=client_credentials&client_id=cid&client_secret=s3cret")
        assert form["grant_type"] == "client_credentials" and form["client_secret"] == "s3cret"

    def test_nonsense_is_refused(self):
        with pytest.raises(SystemExit):
            ascend._parse_login_body("not json and not a query string {{{")


class TestBothHalvesOfTheLoginRunOnOnePath:
    """The drift guard, and the actual bug: each half had exactly one caller, and they differed."""

    def _body(self, fn):
        m = re.search(rf"^def {fn}\(.*?(?=^def )", SRC, re.S | re.M)
        assert m, f"{fn} not found"
        return m.group(0)

    @pytest.mark.parametrize("fn", ["cmd_onboard", "cmd_discover"])
    def test_the_command_runs_the_exchange_through_the_shared_helper(self, fn):
        assert "_prepare_target_auth(" in self._body(fn), (
            f"{fn} does not run the login exchange through the shared helper")

    @pytest.mark.parametrize("fn", ["cmd_onboard", "_finish_discovery"])
    def test_the_write_path_attaches_the_recipe(self, fn):
        assert "_apply_login_auth(" in self._body(fn), (
            f"{fn} writes a config without attaching the login recipe — the token it minted will "
            f"be frozen into a header and every probe after it expires will 401")

    def test_only_the_shared_helper_invokes_the_exchange(self):
        """A second caller means a second path that can forget the other half."""
        assert len(re.findall(r"_login_for_token\(", SRC)) == 2, (
            "the login exchange is invoked from somewhere other than _prepare_target_auth")


class TestTheMintedCredentialDoesNotLandInTheFile:
    class _Args:
        _login_auth = {"auth": {"type": "derived_multihop", "steps": [], "attach": {}},
                       "auth_lifecycle": {"type": "reauth_on_401"}}
        _login_minted_headers = {"Authorization"}

    def test_the_one_shot_header_is_stripped(self):
        cfg = {"headers": {"Authorization": "Bearer live-token-value", "X-Tenant": "acme"}}
        out = ascend._apply_login_auth(cfg, self._Args())
        assert "Authorization" not in out.get("headers", {}), (
            "the minted token stays in the config: it pins a credential that is already expiring, "
            "shadows the freshly minted one, and writes a live secret into a file")

    def test_an_operator_supplied_header_survives(self):
        cfg = {"headers": {"Authorization": "Bearer x", "X-Tenant": "acme"}}
        assert ascend._apply_login_auth(cfg, self._Args())["headers"]["X-Tenant"] == "acme"

    def test_the_recipe_is_what_replaces_it(self):
        out = ascend._apply_login_auth({"headers": {"Authorization": "Bearer x"}}, self._Args())
        assert out["auth"]["type"] == "derived_multihop"
        assert out["auth_lifecycle"]["type"] == "reauth_on_401"

    def test_a_run_with_no_login_is_untouched(self):
        class Bare:
            pass
        cfg = {"headers": {"Authorization": "Bearer mine"}}
        assert ascend._apply_login_auth(dict(cfg), Bare()) == cfg


class TestTheRecipeReplaysTheWayTheExchangeSucceeded:
    """Recording the wrong verb/header/extractor produces a config that onboards green and then
    re-authenticates into a 403 — the worst possible time to discover it."""

    def test_it_records_the_verb(self):
        assert re.search(r'step = \{"method": _method', SRC), (
            "the recipe hardcodes POST; a GET bootstrap would replay as a POST")

    def test_a_get_bootstrap_carries_no_body(self):
        assert 'if _method != "GET":' in SRC

    def test_it_records_the_target_header(self):
        assert 'attach = {"headers": {hdr: "{{TOKEN}}"} if hdr' in SRC, (
            "a CSRF token would be replayed as Authorization: Bearer, authenticating nothing")

    def test_it_records_regex_extraction_when_that_is_how_it_was_found(self):
        assert '"regex": args.token_regex' in SRC, (
            "a token found by regex would replay with a dot-path extractor and come back empty")
