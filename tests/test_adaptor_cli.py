"""
`ascend adaptor` — the command group over runtime/adaptor.py and control/api.py, offline.

The platform client is replaced by a recorder, so every test pins what the command SENDS and
what it PRINTS: the merged template a store PATCHes (every key kept, only `_adaptor_src` added),
the exit code for a refused gate (2, the findings code) versus a failed turn (1), the JSON
envelope on both paths, and the explanation the engine's 404 turns into when the wrong id space
was used.
"""
import importlib.util
import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "runtime"))
sys.path.insert(0, str(REPO / "control"))
_CLI = REPO / "shells" / "cli" / "ascend.py"
_spec = importlib.util.spec_from_file_location("ascend_cli_adaptor", _CLI)
cli = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cli)
import api  # noqa: E402
from _onboard_harness import FakePlatform, run_target_add  # noqa: E402

UUID = "3f2a9c1e-7b4d-4e8f-9a0b-1c2d3e4f5a6b"
GATE_OK = {"ok": True, "origin": "inline", "storeAs": "SOURCE-ECHO", "summary": "accepted",
           "templateKey": "_adaptor_src", "templateValue": "c3Jj", "digest": "0094886620bc",
           "sizes": {"bytes": 4912, "minifiedBytes": 1557, "encodedBytes": 2076},
           "gate": {"ok": True, "violations": [], "caps": ["http.request"], "entries": ["sendTurn"]}}
GATE_NO = {"ok": False, "origin": "inline", "storeAs": None, "templateKey": "_adaptor_src",
           "templateValue": None, "digest": "af51782d1d56", "sizes": {},
           "summary": "refused by the publish gate; nothing was executed (2 violations)",
           "gate": {"ok": False, "caps": [], "entries": ["sendTurn"], "violations": [
               {"kind": "async", "detail": "drop `await`", "line": 2},
               {"kind": "unknown-identifier", "detail": "fetch", "line": 2}]}}
APP = {"id": "aapp_1", "name": "Support Bot", "api_type": "api",
       "url": "https://chat.example.com/v1",
       "request_template": json.dumps({"message": "{{PROMPT}}", "_adaptor_user_role": "admin"}),
       "response_template": '{"data": {"reply": "{{RESPONSE}}"}}'}
# The record's basis (runtime/adaptor.py record_digest): sha-256 of the template value, first 12
# hex — of the gate's "c3Jj" above, and of the placeholder a lost write leaves on the record.
TD = "0daa5aa6a04c"
PLACEHOLDER_D = "b2bf54095507"
RECORD_LINE = f"record   template_digest {TD}  stored_digest {{stored}}   (sha-256 of _adaptor_src, first 12 hex)"


class Recorder:
    """Everything the commands can ask of the platform, recorded; replies are canned."""

    def __init__(self, *, gate=GATE_OK, app=APP, test=None, verify=None, adapter=None,
                 lose_patch=False, console_uuid=None, console_error=None):
        self.gate_out, self.app, self.test_out = gate, dict(app) if app else None, test
        self.verify_out, self.adapter_out, self.lose_patch = verify, adapter, lose_patch
        self.gated, self.tested, self.verified, self.got, self.patched, self.listed = \
            [], [], [], [], [], 0
        self.spec_out = {"filename": "host.d.ts", "bytes": 9, "source": "// spec\n"}
        # The Console join: what `console_app_uuid` answers for a name, and the calls made to it.
        self.console_uuid, self.last_console_error, self.console_asked = console_uuid, console_error, []

    def console_app_uuid(self, name, *, url=None, attempts=1, delay_s=0):
        self.console_asked.append((name, url))
        return self.console_uuid

    def adapter_spec(self):
        return self.spec_out

    def adapter_gate(self, src):
        self.gated.append(src)
        return self.gate_out

    def adapter_test(self, src, app_id, prompts, budget):
        self.tested.append((src, app_id, list(prompts), budget))
        if isinstance(self.test_out, Exception):
            raise self.test_out
        return self.test_out

    def verify_app_adapter(self, app_id, budget):
        self.verified.append((app_id, budget))
        if isinstance(self.verify_out, Exception):
            raise self.verify_out
        return self.verify_out

    def get_app_adapter(self, app_id):
        self.got.append(app_id)
        if isinstance(self.adapter_out, Exception):
            raise self.adapter_out
        return self.adapter_out

    def list_apps(self):
        self.listed += 1
        return {"data": [self.app] if self.app else []}

    def get_app(self, app_id):
        return self.app

    def patch_app(self, app_id, patch):
        self.patched.append((app_id, patch))
        if not self.lose_patch:
            self.app = {**self.app, **patch}
        return self.app


def run(monkeypatch, rec, *argv, json_mode=False):
    """Drive one command exactly as main() does, with the client replaced."""
    argv = list(argv) + (["--json"] if json_mode else [])
    monkeypatch.setattr(cli, "_client", lambda args, **kw: rec)
    # `_die` reads sys.argv to decide on the JSON envelope, like the real process would.
    monkeypatch.setattr(sys, "argv", ["ascend", *argv])
    ns = cli.build_parser().parse_args(argv)
    cli._reapply_globals(ns, argv)
    ns.func(ns)


def exits_with(monkeypatch, rec, *argv, json_mode=False):
    with pytest.raises(SystemExit) as e:
        run(monkeypatch, rec, *argv, json_mode=json_mode)
    return e.value.code


@pytest.fixture
def js(tmp_path):
    p = tmp_path / "a.js"
    p.write_text("function sendTurn(turn, host) { return { status_code: 200, body: {} }; }")
    return str(p)


# --------------------------------------------------------------------------- parser wiring
class TestParser:
    @pytest.mark.parametrize("argv", [
        ["adaptor", "spec"], ["adaptor", "spec", "--out", "h.d.ts"],
        ["adaptor", "gate", "a.js"],
        ["adaptor", "test", "a.js", "--app", UUID, "--prompt", "x", "--prompt", "y", "--budget", "30"],
        ["adaptor", "store", "a.js", "--app", "My Bot", "--dry-run"],
        ["adaptor", "get", "--app", UUID], ["adaptor", "verify", "--app", UUID],
        ["adaptor", "shape", "--app", "aapp_1"], ["adaptor", "har", "x.har", "--bodies"],
        ["adaptor", "scaffold", "--example", "--out", "c.js", "--force"],
    ])
    def test_every_verb_parses(self, argv):
        ns = cli.build_parser().parse_args(argv)
        assert ns.group == "adaptor" and callable(ns.func)

    def test_json_works_before_and_after_the_group(self):
        for argv in (["--json", "adaptor", "gate", "a.js"], ["adaptor", "gate", "a.js", "--json"]):
            ns = cli._reapply_globals(cli.build_parser().parse_args(argv), argv)
            assert ns.json is True

    def test_prompt_is_repeatable_and_budget_defaults(self):
        ns = cli.build_parser().parse_args(["adaptor", "test", "a.js", "--app", UUID,
                                            "--prompt", "a", "--prompt", "b"])
        assert ns.prompt == ["a", "b"] and ns.budget == 120.0
        assert cli.build_parser().parse_args(["adaptor", "test", "a.js", "--app", UUID]).prompt is None

    @pytest.mark.parametrize("verb,needs", [("test", ["a.js"]), ("get", []), ("verify", []),
                                            ("store", ["a.js"]), ("shape", [])])
    def test_app_is_required(self, verb, needs):
        with pytest.raises(SystemExit):
            cli.build_parser().parse_args(["adaptor", verb, *needs])


# --------------------------------------------------------------------------- spec / gate
class TestSpecAndGate:
    def test_spec_prints_the_source_verbatim(self, monkeypatch, capsys):
        run(monkeypatch, Recorder(), "adaptor", "spec")
        assert capsys.readouterr().out == "// spec\n"

    def test_spec_out_writes_the_file(self, monkeypatch, capsys, tmp_path):
        out = tmp_path / "d" / "host.d.ts"
        run(monkeypatch, Recorder(), "adaptor", "spec", "--out", str(out), json_mode=True)
        assert out.read_text() == "// spec\n"
        assert json.loads(capsys.readouterr().out)["data"]["bytes"] == 8

    def test_gate_pass(self, monkeypatch, capsys, js):
        rec = Recorder()
        run(monkeypatch, rec, "adaptor", "gate", js)
        out = capsys.readouterr().out
        assert out.startswith("PASS  caps: http.request")
        assert "preflight: none" in out and "4912 bytes -> 1557 minified -> 2076" in out
        assert rec.gated == [Path(js).read_text()]

    def test_gate_json_drops_the_source_echo(self, monkeypatch, capsys, js):
        run(monkeypatch, Recorder(), "adaptor", "gate", js, json_mode=True)
        env = json.loads(capsys.readouterr().out)
        assert env["ok"] is True and "storeAs" not in env["data"]
        assert env["data"]["templateValue"] == "c3Jj" and env["data"]["preflight"].startswith("none")

    def test_gate_refused_exits_2_and_names_each_violation(self, monkeypatch, capsys, js):
        assert exits_with(monkeypatch, Recorder(gate=GATE_NO), "adaptor", "gate", js) == 2
        out = capsys.readouterr().out
        assert out.startswith("FAIL  refused by the publish gate")
        assert "REFUSED  async: drop `await` (line 2)" in out
        assert "REFUSED  unknown-identifier: fetch (line 2)" in out

    def test_gate_refused_json_envelope(self, monkeypatch, capsys, js):
        assert exits_with(monkeypatch, Recorder(gate=GATE_NO), "adaptor", "gate", js, json_mode=True) == 2
        env = json.loads(capsys.readouterr().out)
        assert env["ok"] is False and env["error"]["code"] == "gate_refused"
        assert env["error"]["exit_code"] == 2
        assert [v["kind"] for v in env["data"]["gate"]["violations"]] == ["async", "unknown-identifier"]

    def test_a_missing_file_is_a_usage_error(self, monkeypatch, tmp_path):
        assert exits_with(monkeypatch, Recorder(), "adaptor", "gate", str(tmp_path / "nope.js")) == 3


# --------------------------------------------------------------------------- test / verify
TURN_OK = {"n": 1, "status_code": 200, "ms": 812, "scored": "Papua New Guinea has the most.",
           "response": "Papua New Guinea has the most.", "body": {"reply": "Papua New Guinea has the most."},
           "host_calls": [{"fn": "http.request", "ms": 790, "result": "200", "args": ["https://x"]}]}


class TestTest:
    def test_sends_every_prompt_and_the_budget_to_the_engine(self, monkeypatch, capsys, js):
        rec = Recorder(test={"gate": {"ok": True}, "preflight": None, "turns": [TURN_OK]})
        run(monkeypatch, rec, "adaptor", "test", js, "--app", UUID, "--prompt", "a", "--prompt", "b",
            "--budget", "45")
        assert rec.tested == [(Path(js).read_text(), UUID, ["a", "b"], 45.0)]
        assert rec.listed == 0, "a uuid is used as given; the platform is not asked"
        out = capsys.readouterr().out
        assert "preflight: no checkReachability" in out
        assert out.index("scored :") < out.index("parsed :") < out.index("raw    :"), \
            "scored first: it is what ships"
        assert "http.request" in out and "DONE" in out and "NOT DONE" not in out

    def test_the_default_prompt_is_one_benign_hello(self, monkeypatch, js):
        rec = Recorder(test={"turns": [TURN_OK]})
        run(monkeypatch, rec, "adaptor", "test", js, "--app", UUID)
        assert rec.tested[0][2] == ["Hi, what can you help me with?"]

    def test_a_failed_turn_exits_1_with_the_json_error(self, monkeypatch, capsys, js):
        bad = {**TURN_OK, "status_code": 500, "scored": "adapter fault: boom"}
        rec = Recorder(test={"turns": [bad]})
        assert exits_with(monkeypatch, rec, "adaptor", "test", js, "--app", UUID, json_mode=True) == 1
        env = json.loads(capsys.readouterr().out)
        assert env["ok"] is False and env["error"]["code"] == "test_failed"
        assert "500" in env["error"]["message"] and env["verdict"]["turns"][0]["ok"] is False

    def test_a_stringified_body_is_shouted_about_and_not_done(self, monkeypatch, capsys, js):
        rec = Recorder(test={"turns": [{**TURN_OK, "scored": "{'reply': 'the answer'}"}]})
        assert exits_with(monkeypatch, rec, "adaptor", "test", js, "--app", UUID) == 1
        out = capsys.readouterr().out
        assert "THIS IS WRONG" in out and "NOT DONE" in out

    def test_a_failed_preflight_fails_the_test(self, monkeypatch, capsys, js):
        rec = Recorder(test={"preflight": {"status_code": 401, "ms": 40, "body": "nope"},
                             "turns": [TURN_OK]})
        assert exits_with(monkeypatch, rec, "adaptor", "test", js, "--app", UUID) == 1
        assert "FAILED - would block the run" in capsys.readouterr().out

    def test_refused_by_the_gate_runs_nothing_and_exits_2(self, monkeypatch, capsys, js):
        rec = Recorder(test={"gate": GATE_NO["gate"]})
        assert exits_with(monkeypatch, rec, "adaptor", "test", js, "--app", UUID) == 2
        assert "nothing ran" in capsys.readouterr().out

    def test_a_budget_over_the_limit_is_refused_locally(self, monkeypatch, js):
        rec = Recorder(test={"turns": [TURN_OK]})
        assert exits_with(monkeypatch, rec, "adaptor", "test", js, "--app", UUID, "--budget", "300") == 3
        assert rec.tested == []


class TestVerify:
    def test_pass(self, monkeypatch, capsys):
        rec = Recorder(verify={"ok": True, "summary": "1 turn ok", "app_id": UUID,
                               "endpoint": "https://x", "origin": "template", "digest": "d",
                               "preflight": None,
                               "turns": [{**TURN_OK, "requests": 1}]})
        run(monkeypatch, rec, "adaptor", "verify", "--app", UUID, "--budget", "60")
        assert rec.verified == [(UUID, 60.0)]
        out = capsys.readouterr().out
        assert out.startswith("PASS  1 turn ok") and "1 request(s)" in out
        assert "NEW assessment" in out and "not Rerun" in out

    def test_fail_exits_1(self, monkeypatch, capsys):
        rec = Recorder(verify={"ok": False, "summary": "no adaptor resolved", "turns": []})
        assert exits_with(monkeypatch, rec, "adaptor", "verify", "--app", UUID, json_mode=True) == 1
        env = json.loads(capsys.readouterr().out)
        assert env["ok"] is False and env["error"]["code"] == "verify_failed"
        assert "no adaptor resolved" in env["error"]["message"]

    def test_json_keeps_the_engines_digest_under_its_own_key_only(self, monkeypatch, capsys):
        """verify runs what is stored and reports the engine's digest as it came; the record's
        basis is store's and get's to state, so neither of their keys appears here."""
        rec = Recorder(verify={"ok": True, "summary": "1 turn ok", "digest": "d", "turns": [TURN_OK]})
        run(monkeypatch, rec, "adaptor", "verify", "--app", UUID, json_mode=True)
        data = json.loads(capsys.readouterr().out)["data"]
        assert data["digest"] == "d"
        assert "stored_digest" not in data and "template_digest" not in data


# --------------------------------------------------------------------------- get, and the id space
class TestGet:
    def test_prints_the_record_then_the_source(self, monkeypatch, capsys):
        rec = Recorder(adapter={"origin": "template", "digest": "d", "source": "function sendTurn(){}\n"})
        run(monkeypatch, rec, "adaptor", "get", "--app", UUID)
        out = capsys.readouterr().out
        head, _, src = out.partition("--- source ---")
        assert json.loads(head) == {"origin": "template", "digest": "d", "stored_digest": None}
        assert src.strip() == "function sendTurn(){}"

    def test_json_carries_the_whole_record(self, monkeypatch, capsys):
        rec = Recorder(adapter={"origin": "template", "source": "x"})
        run(monkeypatch, rec, "adaptor", "get", "--app", UUID, json_mode=True)
        assert json.loads(capsys.readouterr().out) == {
            "ok": True, "data": {"origin": "template", "source": "x", "stored_digest": None}}

    def test_a_uuid_reads_no_record_so_the_stored_digest_is_null(self, monkeypatch, capsys):
        rec = Recorder(adapter={"origin": "template", "digest": "d"})
        run(monkeypatch, rec, "adaptor", "get", "--app", UUID, json_mode=True)
        assert json.loads(capsys.readouterr().out)["data"]["stored_digest"] is None
        assert rec.listed == 0, "a uuid goes on the route as given; nothing was read to hash"

    def test_console_id_reads_no_record_either(self, monkeypatch, capsys):
        rec = Recorder(adapter={"origin": "inline"}, console_uuid=UUID)
        run(monkeypatch, rec, "adaptor", "get", "--app", "Support Bot", "--console-id", UUID, json_mode=True)
        assert json.loads(capsys.readouterr().out)["data"]["stored_digest"] is None

    def test_a_name_hashes_the_adaptor_src_of_the_record_read_for_the_join(self, monkeypatch, capsys):
        """Named through the platform, the record read to join the id spaces is the one the
        stored digest is taken over — and the engine's own `digest` is left exactly as it came."""
        app = {**APP, "request_template": json.dumps({"message": "{{PROMPT}}", "_adaptor_src": "c3Jj"})}
        rec = Recorder(adapter={"origin": "template", "digest": "d", "source": "x"}, app=app, console_uuid=UUID)
        run(monkeypatch, rec, "adaptor", "get", "--app", "Support Bot", json_mode=True)
        data = json.loads(capsys.readouterr().out)["data"]
        assert data["stored_digest"] == TD and data["digest"] == "d" and data["source"] == "x"
        assert rec.listed == 1, "one platform read, handed on — not a second one for the hash"

    def test_the_stored_digest_prints_in_the_head_under_the_engines_digest(self, monkeypatch, capsys):
        app = {**APP, "request_template": json.dumps({"message": "{{PROMPT}}", "_adaptor_src": "c3Jj"})}
        rec = Recorder(adapter={"origin": "template", "digest": "d", "source": "x"}, app=app, console_uuid=UUID)
        run(monkeypatch, rec, "adaptor", "get", "--app", "aapp_1")
        head, _, src = capsys.readouterr().out.partition("--- source ---")
        assert json.loads(head) == {"origin": "template", "digest": "d", "stored_digest": TD}
        assert src.strip() == "x"

    @pytest.mark.parametrize("template", [
        json.dumps({"message": "{{PROMPT}}"}),                        # nothing under the key
        json.dumps({"message": "{{PROMPT}}", "_adaptor_src": ""}),    # an empty value
        "{not json",                                                   # nothing readable
    ])
    def test_a_record_with_nothing_readable_under_the_key_is_null(self, monkeypatch, capsys, template):
        rec = Recorder(adapter={"origin": "none"}, app={**APP, "request_template": template}, console_uuid=UUID)
        run(monkeypatch, rec, "adaptor", "get", "--app", "aapp_1", json_mode=True)
        assert json.loads(capsys.readouterr().out)["data"]["stored_digest"] is None

    def test_the_placeholder_hashes_as_the_placeholder(self, monkeypatch, capsys):
        """What the record holds, not what it should: an app still on v0:passthrough says so."""
        app = {**APP, "request_template": json.dumps({"message": "{{PROMPT}}", "_adaptor_src": "v0:passthrough"})}
        rec = Recorder(adapter={"origin": "alias"}, app=app, console_uuid=UUID)
        run(monkeypatch, rec, "adaptor", "get", "--app", "aapp_1", json_mode=True)
        assert json.loads(capsys.readouterr().out)["data"]["stored_digest"] == PLACEHOLDER_D


ENGINE_404 = api.AscendAPIError(
    "GET /ascend/applications/aapp_1/adapter -> 404: "
    '{"detail":"application aapp_1 could not be read"}')


class TestTheTwoIdSpaces:
    """The engine's routes take its uuid; the platform's aapp_ id gets a 404 that says only
    "could not be read". The CLI tries what it is given and then explains, by shape."""

    def test_an_aapp_id_is_tried_then_explained_as_a_usage_error(self, monkeypatch, capsys):
        rec = Recorder(adapter=ENGINE_404)
        assert exits_with(monkeypatch, rec, "adaptor", "get", "--app", "aapp_1") == 3
        assert rec.got == ["aapp_1"], "tried as given — the day the gateway resolves it, it works"
        err = capsys.readouterr().err
        assert "engine's application uuid" in err and "Console URL" in err

    def test_a_name_resolves_to_the_aapp_id_first(self, monkeypatch, capsys):
        rec = Recorder(adapter=ENGINE_404)
        assert exits_with(monkeypatch, rec, "adaptor", "get", "--app", "Support Bot") == 3
        assert rec.listed == 1 and rec.got == ["aapp_1"]
        assert rec.console_asked == [("Support Bot", "https://chat.example.com/v1")], \
            "the Console's listing was consulted, by name and url, before falling back"

    def test_a_name_is_joined_to_the_engine_uuid_through_the_console(self, monkeypatch, capsys):
        """The one join between the two id spaces: the Console's listApplications."""
        rec = Recorder(adapter={"origin": "inline", "digest": "d"}, console_uuid=UUID)
        run(monkeypatch, rec, "adaptor", "get", "--app", "Support Bot")
        assert rec.got == [UUID]
        assert "resolved through the Console" in capsys.readouterr().err

    def test_an_aapp_id_is_joined_too(self, monkeypatch):
        rec = Recorder(adapter={"origin": "inline"}, console_uuid=UUID)
        run(monkeypatch, rec, "adaptor", "get", "--app", "aapp_1")
        assert rec.console_asked == [("Support Bot", "https://chat.example.com/v1")] and rec.got == [UUID]

    def test_console_id_wins_over_everything(self, monkeypatch):
        rec = Recorder(adapter={"origin": "inline"}, console_uuid="3f2a9c1e-7b4d-4e8f-9a0b-000000000000")
        run(monkeypatch, rec, "adaptor", "get", "--app", "Support Bot", "--console-id", UUID)
        assert rec.got == [UUID] and rec.console_asked == []

    def test_a_console_id_that_is_not_a_uuid_is_a_usage_error(self, monkeypatch):
        assert exits_with(monkeypatch, Recorder(), "adaptor", "verify", "--app", UUID, "--console-id", "aapp_1") == 3

    def test_the_fallback_says_why_the_console_did_not_answer(self, monkeypatch, capsys):
        rec = Recorder(adapter=ENGINE_404, console_error="ConsoleError: the Console answered 403")
        assert exits_with(monkeypatch, rec, "adaptor", "get", "--app", "Support Bot") == 3
        assert "the Console answered 403" in capsys.readouterr().err

    @pytest.mark.parametrize("verb,needs", [("test", ["a.js"]), ("verify", [])])
    def test_test_and_verify_resolve_the_same_way(self, monkeypatch, verb, needs, js):
        rec = Recorder(test={"turns": [TURN_OK]}, verify={"ok": True, "turns": [TURN_OK]}, console_uuid=UUID)
        argv = ["adaptor", verb] + ([js] if needs else []) + ["--app", "Support Bot"]
        run(monkeypatch, rec, *argv)
        ids = [t[1] for t in rec.tested] + [v[0] for v in rec.verified]
        assert ids == [UUID]

    def test_a_uuid_the_engine_cannot_read_is_not_found_or_not_yours(self, monkeypatch, capsys):
        rec = Recorder(adapter=api.AscendAPIError(
            f"GET /ascend/applications/{UUID}/adapter -> 404: "
            f'{{"detail":"application {UUID} could not be read"}}'))
        assert exits_with(monkeypatch, rec, "adaptor", "get", "--app", UUID) == 1
        assert "will not say which" in capsys.readouterr().err

    def test_the_json_error_names_the_fix(self, monkeypatch, capsys):
        rec = Recorder(adapter=ENGINE_404)
        assert exits_with(monkeypatch, rec, "adaptor", "get", "--app", "aapp_1", json_mode=True) == 3
        env = json.loads(capsys.readouterr().out)
        assert env["ok"] is False and env["error"]["code"] == "engine_uuid_required"
        assert "ascend adaptor get --app <uuid>" in env["error"]["hint"]

    def test_a_403_explains_the_scope(self, monkeypatch, capsys):
        rec = Recorder(verify=api.AscendAPIError("POST x -> 403: not authorized for ascend:write"))
        assert exits_with(monkeypatch, rec, "adaptor", "verify", "--app", UUID) == 1
        assert "ascend:write" in capsys.readouterr().err

    def test_any_other_error_is_not_swallowed(self, monkeypatch):
        rec = Recorder(adapter=api.AscendAPIError("GET x -> 500: boom"))
        with pytest.raises(api.AscendAPIError, match="500"):
            run(monkeypatch, rec, "adaptor", "get", "--app", UUID)


# --------------------------------------------------------------------------- shape
class TestShape:
    def test_prints_the_return_statement(self, monkeypatch, capsys):
        run(monkeypatch, Recorder(), "adaptor", "shape", "--app", "Support Bot")
        out = capsys.readouterr().out
        assert "YOUR ADAPTOR MUST RETURN the reply at `data.reply`" in out
        assert "return { status_code: 200, body: { data: { reply: text } } };" in out
        assert "adaptor  none stored" in out

    def test_a_placeholder_is_called_out(self, monkeypatch, capsys):
        app = {**APP, "request_template": json.dumps({"message": "{{PROMPT}}",
                                                      "_adaptor_src": "v0:passthrough"})}
        run(monkeypatch, Recorder(app=app), "adaptor", "shape", "--app", "aapp_1", json_mode=True)
        env = json.loads(capsys.readouterr().out)
        assert env["data"]["placeholder"] is True and env["data"]["reply_shape"]["path"] == "data.reply"

    def test_a_routed_url_is_explained(self, monkeypatch, capsys):
        app = {**APP, "url": "https://chat.corp.internal.tun.straiker.ai/v1"}
        run(monkeypatch, Recorder(app=app), "adaptor", "shape", "--app", "aapp_1")
        assert "tunnel name" in capsys.readouterr().out

    def test_no_response_marker_says_ask(self, monkeypatch, capsys):
        app = {**APP, "response_template": '{"x": "y"}'}
        run(monkeypatch, Recorder(app=app), "adaptor", "shape", "--app", "aapp_1")
        assert "ask which field" in capsys.readouterr().out


# --------------------------------------------------------------------------- store
class TestStore:
    def test_keeps_every_key_and_adds_only_the_adaptor(self, monkeypatch, capsys, js):
        rec = Recorder()
        run(monkeypatch, rec, "adaptor", "store", js, "--app", "Support Bot")
        assert len(rec.patched) == 1
        app_id, patch = rec.patched[0]
        assert app_id == "aapp_1" and list(patch) == ["request_template"]
        assert json.loads(patch["request_template"]) == {
            "message": "{{PROMPT}}", "_adaptor_user_role": "admin", "_adaptor_src": "c3Jj"}
        out = capsys.readouterr().out
        assert out.startswith("stored   digest 0094886620bc  4912B -> 2076B base64")
        assert out.splitlines()[1] == RECORD_LINE.format(stored=TD), "the record's basis, next line"
        assert "address  https://chat.example.com/v1" in out
        assert "return { status_code: 200, body: { data: { reply: text } } };" in out
        assert "ascend adaptor verify" in out and "NEW assessment" in out

    def test_gated_first_and_a_refusal_writes_nothing(self, monkeypatch, capsys, js):
        rec = Recorder(gate=GATE_NO)
        assert exits_with(monkeypatch, rec, "adaptor", "store", js, "--app", "aapp_1") == 2
        assert rec.patched == []
        assert "will not store an adaptor the gate refuses" in capsys.readouterr().out

    def test_the_retired_marker_is_refused(self, monkeypatch, capsys, js):
        app = {**APP, "url": "https://custom-adaptor"}
        rec = Recorder(app=app)
        assert exits_with(monkeypatch, rec, "adaptor", "store", js, "--app", "aapp_1") == 1
        assert rec.patched == [] and "retired" in capsys.readouterr().err

    def test_no_url_and_no_endpoint_is_refused(self, monkeypatch, capsys, js):
        rec = Recorder(app={**APP, "url": ""})
        assert exits_with(monkeypatch, rec, "adaptor", "store", js, "--app", "aapp_1") == 1
        assert rec.patched == [] and "nowhere to go" in capsys.readouterr().err

    def test_a_bridge_app_cannot_carry_an_adaptor(self, monkeypatch, capsys, js):
        rec = Recorder(app={**APP, "api_type": "thin"})
        assert exits_with(monkeypatch, rec, "adaptor", "store", js, "--app", "aapp_1") == 1
        assert rec.patched == [] and "bridge app" in capsys.readouterr().err

    def test_a_template_that_is_not_json_is_refused(self, monkeypatch, capsys, js):
        rec = Recorder(app={**APP, "request_template": "{not json"})
        assert exits_with(monkeypatch, rec, "adaptor", "store", js, "--app", "aapp_1") == 1
        assert rec.patched == [] and "not a JSON object" in capsys.readouterr().err

    def test_dead_endpoint_keys_are_dropped_and_said(self, monkeypatch, capsys, js):
        """With a URL every endpoint key is dead: the URL is the address. Kept "with a warning"
        they stayed on the record as config that looked live; the canonical harness drops them,
        and so does `store` now — naming each one."""
        tpl = {"message": "{{PROMPT}}", "_adaptor_endpoint": "https://t",
               "_adaptor_shop_endpoint": "https://t", "_adaptor_user_role": "admin"}
        rec = Recorder(app={**APP, "request_template": json.dumps(tpl)})
        run(monkeypatch, rec, "adaptor", "store", js, "--app", "aapp_1")
        stored = json.loads(rec.patched[0][1]["request_template"])
        assert stored == {"message": "{{PROMPT}}", "_adaptor_user_role": "admin", "_adaptor_src": "c3Jj"}
        err = capsys.readouterr().err
        assert "dropped _adaptor_endpoint, _adaptor_shop_endpoint" in err and "never be used" in err

    def test_without_a_url_a_namespaced_key_is_dropped_but_the_bare_one_stays(self, monkeypatch, capsys, js):
        tpl = {"message": "{{PROMPT}}", "_adaptor_endpoint": "https://t", "_adaptor_shop_endpoint": "https://u"}
        rec = Recorder(app={**APP, "url": "", "request_template": json.dumps(tpl)})
        run(monkeypatch, rec, "adaptor", "store", js, "--app", "aapp_1", json_mode=True)
        stored = json.loads(rec.patched[0][1]["request_template"])
        assert stored == {"message": "{{PROMPT}}", "_adaptor_endpoint": "https://t", "_adaptor_src": "c3Jj"}
        env = json.loads(capsys.readouterr().out)
        assert env["data"]["dropped"] == ["_adaptor_shop_endpoint"] and env["data"]["address"] == "https://t"

    def test_endpoint_gives_an_app_with_no_url_its_address(self, monkeypatch, capsys, js):
        rec = Recorder(app={**APP, "url": "", "request_template": json.dumps({"message": "{{PROMPT}}"})})
        run(monkeypatch, rec, "adaptor", "store", js, "--app", "aapp_1", "--endpoint", "https://t.example/v1")
        stored = json.loads(rec.patched[0][1]["request_template"])
        assert stored == {"message": "{{PROMPT}}", "_adaptor_endpoint": "https://t.example/v1", "_adaptor_src": "c3Jj"}
        assert "address  https://t.example/v1" in capsys.readouterr().out

    def test_endpoint_on_an_app_that_has_a_url_is_refused(self, monkeypatch, capsys, js):
        """An app's own URL is its adaptor's address; --endpoint would never be read."""
        rec = Recorder()
        assert exits_with(monkeypatch, rec, "adaptor", "store", js, "--app", "aapp_1",
                          "--endpoint", "https://elsewhere.example") == cli.EXIT_USAGE
        assert rec.patched == [] and "would never be read" in capsys.readouterr().err

    def test_endpoint_equal_to_the_url_is_harmless(self, monkeypatch, capsys, js):
        rec = Recorder()
        run(monkeypatch, rec, "adaptor", "store", js, "--app", "aapp_1", "--endpoint", APP["url"])
        stored = json.loads(rec.patched[0][1]["request_template"])
        assert "_adaptor_endpoint" not in stored and stored["_adaptor_src"] == "c3Jj"

    def test_no_url_and_no_endpoint_names_the_flag(self, monkeypatch, capsys, js):
        rec = Recorder(app={**APP, "url": ""})
        assert exits_with(monkeypatch, rec, "adaptor", "store", js, "--app", "aapp_1") == 1
        assert "--endpoint https://<the target>" in capsys.readouterr().err

    def test_the_placeholder_is_replaced_and_said(self, monkeypatch, capsys, js):
        rec = Recorder(app={**APP, "request_template": json.dumps(
            {"message": "{{PROMPT}}", "_adaptor_src": "v0:passthrough"})})
        run(monkeypatch, rec, "adaptor", "store", js, "--app", "aapp_1")
        assert json.loads(rec.patched[0][1]["request_template"])["_adaptor_src"] == "c3Jj"
        assert "placeholder" in capsys.readouterr().err

    def test_dry_run_gates_shows_the_merge_and_writes_nothing(self, monkeypatch, capsys, js):
        rec = Recorder()
        run(monkeypatch, rec, "adaptor", "store", js, "--app", "aapp_1", "--dry-run", json_mode=True)
        assert rec.gated and rec.patched == []
        env = json.loads(capsys.readouterr().out)
        assert env["ok"] is True and env["data"]["dry_run"] is True and env["data"]["stored"] is False
        assert env["data"]["template_digest"] == TD, "known from the gate alone"
        assert env["data"]["stored_digest"] is None, "nothing was read back"
        assert env["data"]["template"] == {"message": "{{PROMPT}}", "_adaptor_user_role": "admin",
                                           "_adaptor_src": "<4b of base64>"}
        assert env["data"]["reply_shape"]["path"] == "data.reply"

    def test_a_patch_that_did_not_land_is_not_reported_as_stored(self, monkeypatch, capsys, js):
        """A PATCH that returned is not a PATCH that landed: the app is read back."""
        rec = Recorder(lose_patch=True)
        assert exits_with(monkeypatch, rec, "adaptor", "store", js, "--app", "aapp_1", json_mode=True) == 1
        env = json.loads(capsys.readouterr().out)
        assert env["ok"] is False and env["error"]["code"] == "store_unverified"
        assert env["data"]["stored"] is False
        assert env["data"]["template_digest"] == TD
        assert env["data"]["stored_digest"] is None, "read back: the record holds no adaptor at all"

    def test_a_lost_write_reports_the_digest_of_what_the_record_still_holds(self, monkeypatch, capsys, js):
        """Measured from the read-back, never inferred from `stored`: the record kept the
        placeholder, so that is the digest it reports — and it is not the gate's bytes."""
        rec = Recorder(app={**APP, "request_template": json.dumps(
            {"message": "{{PROMPT}}", "_adaptor_src": "v0:passthrough"})}, lose_patch=True)
        assert exits_with(monkeypatch, rec, "adaptor", "store", js, "--app", "aapp_1", json_mode=True) == 1
        env = json.loads(capsys.readouterr().out)
        assert env["error"]["code"] == "store_unverified" and env["data"]["stored"] is False
        assert env["data"]["stored_digest"] == PLACEHOLDER_D
        assert env["data"]["stored_digest"] != env["data"]["template_digest"] == TD

    def test_json_success_envelope(self, monkeypatch, capsys, js):
        run(monkeypatch, Recorder(), "adaptor", "store", js, "--app", "aapp_1", json_mode=True)
        env = json.loads(capsys.readouterr().out)
        assert env["ok"] is True and env["data"]["stored"] is True
        assert env["data"]["template_key"] == "_adaptor_src" and env["data"]["digest"] == "0094886620bc"
        assert env["data"]["template_digest"] == TD, "of the gate's templateValue"
        assert env["data"]["stored_digest"] == TD, "of _adaptor_src as read back: identical, the write landed"

    def test_dry_run_prints_the_stored_digest_as_not_available(self, monkeypatch, capsys, js):
        run(monkeypatch, Recorder(), "adaptor", "store", js, "--app", "aapp_1", "--dry-run")
        lines = capsys.readouterr().out.splitlines()
        assert lines[0].startswith("would    digest 0094886620bc")
        assert lines[1] == RECORD_LINE.format(stored="n/a")

    def test_a_refused_gate_carries_neither_key(self, monkeypatch, capsys, js):
        """The gate did not pass, so there is no template value to hash: absent, not wrong."""
        assert exits_with(monkeypatch, Recorder(gate=GATE_NO), "adaptor", "store", js, "--app", "aapp_1",
                          json_mode=True) == 2
        env = json.loads(capsys.readouterr().out)
        assert env["error"]["code"] == "gate_refused"
        assert "template_digest" not in env["data"] and "stored_digest" not in env["data"]


# --------------------------------------------------------------------------- har / scaffold (offline)
class TestOfflineVerbs:
    def test_har_needs_no_client(self, monkeypatch, capsys, tmp_path):
        p = tmp_path / "s.har"
        p.write_text(json.dumps({"log": {"entries": [
            {"request": {"method": "POST", "url": "https://t.example/chat", "headers": [],
                         "postData": {"text": json.dumps({"prompt": "hi"})}},
             "response": {"status": 200, "headers": [], "content": {"text": json.dumps({"reply": "hello"})}}}]}}))

        def boom(args, **kw):
            raise AssertionError("har must not touch the platform")
        monkeypatch.setattr(cli, "_client", boom)
        monkeypatch.setattr(sys, "argv", ["ascend"])
        ns = cli.build_parser().parse_args(["adaptor", "har", str(p), "--bodies"])
        ns.func(ns)
        out = capsys.readouterr().out
        assert "SESSION CHAINS" in out and "none found" in out and '"prompt": "str"' in out

    def test_har_json(self, monkeypatch, capsys, tmp_path):
        p = tmp_path / "s.har"
        p.write_text(json.dumps({"log": {"entries": [
            {"request": {"method": "GET", "url": "https://t.example/", "headers": []},
             "response": {"status": 200, "headers": [], "content": {"text": ""}}}]}}))
        run(monkeypatch, Recorder(), "adaptor", "har", str(p), json_mode=True)
        env = json.loads(capsys.readouterr().out)
        assert env["ok"] and env["data"]["kept"] == 1 and env["data"]["chains"] == []

    def test_a_bad_har_is_a_usage_error(self, monkeypatch, tmp_path):
        p = tmp_path / "x.har"
        p.write_text("nope")
        assert exits_with(monkeypatch, Recorder(), "adaptor", "har", str(p)) == 3

    def test_scaffold_prints_the_shipped_file_verbatim(self, monkeypatch, capsys):
        run(monkeypatch, Recorder(), "adaptor", "scaffold")
        assert capsys.readouterr().out == (REPO / "templates" / "adaptor_scaffold.js").read_text()

    def test_example_prints_the_worked_adaptor(self, monkeypatch, capsys):
        run(monkeypatch, Recorder(), "adaptor", "scaffold", "--example")
        assert capsys.readouterr().out == (REPO / "templates" / "adaptor_example_chattie.js").read_text()

    def test_scaffold_out_writes_and_refuses_to_overwrite(self, monkeypatch, capsys, tmp_path):
        out = tmp_path / "my.js"
        run(monkeypatch, Recorder(), "adaptor", "scaffold", "--out", str(out))
        assert out.read_text() == (REPO / "templates" / "adaptor_scaffold.js").read_text()
        assert "ascend adaptor gate" in capsys.readouterr().out
        assert exits_with(monkeypatch, Recorder(), "adaptor", "scaffold", "--out", str(out)) == 3
        run(monkeypatch, Recorder(), "adaptor", "scaffold", "--out", str(out), "--example", "--force")
        assert out.read_text() == (REPO / "templates" / "adaptor_example_chattie.js").read_text()


# --------------------------------------------------------------------------- target add's adaptor record
# The hosted-adaptor default of `target add`, driven offline through the onboarding harness (its
# gate answers "FRESH-ADAPTOR" as the template value; its platform keeps what it is sent).
FRESH_D = "354ed181b212"          # record_digest("FRESH-ADAPTOR")
CAPTURED = {"adapter": "direct_api", "endpoint": "https://8.8.8.8/api/chat", "method": "POST",
            "body": {"message": "{{PROMPT}}"}, "response_path": "message"}


def _target_add(monkeypatch, tmp_path, capsys, platform):
    """`ascend target add --config mybot --json` against `platform`: (exit code, stdout as JSON, stderr)."""
    monkeypatch.setattr(sys, "argv", ["ascend", "target", "add", "--config", "mybot", "--json"])
    code = 0
    try:
        run_target_add(monkeypatch, tmp_path, CAPTURED, platform, name="Retail Bot")
    except SystemExit as e:
        code = e.code
    captured = capsys.readouterr()
    return code, json.loads(captured.out), captured.err


class TestTargetAddRecord:
    def test_the_record_carries_both_digests_once_the_store_was_read_back(self, monkeypatch, tmp_path, capsys):
        code, out, err = _target_add(monkeypatch, tmp_path, capsys, FakePlatform(existing=None))
        rec = out["adaptor"]
        assert code == 0 and rec["stored"] and rec["verified"]
        assert rec["digest"] == "0094886620bc", "the gate's own digest, as it came"
        assert rec["template_digest"] == FRESH_D, "of the gate's templateValue"
        assert rec["stored_digest"] == FRESH_D, "of _adaptor_src as the platform held it when read back"
        # the human lines: the pair beside the gate digest, the stored one where the read-back is confirmed
        assert f"gate PASS · digest 0094886620bc · template_digest {FRESH_D} · preflight: none" in err
        assert f"stored · _adaptor_src confirmed on aapp_new · stored_digest {FRESH_D}" in err

    def test_no_read_back_leaves_the_stored_digest_null(self, monkeypatch, tmp_path, capsys):
        """The engine uuid did not resolve, so the engine steps are skipped and the record comes
        back before anything is read: the template digest is known, the stored one is not."""
        code, out, _ = _target_add(monkeypatch, tmp_path, capsys, FakePlatform(existing=None, console_uuid=None))
        rec = out["adaptor"]
        assert code == 1 and rec["verified"] is False and rec["console_id"] is None
        assert rec["template_digest"] == FRESH_D and rec["stored_digest"] is None

    def test_a_write_that_never_lands_reports_what_the_record_holds(self, monkeypatch, tmp_path, capsys):
        """Measured from the read-back, not inferred from `stored`: a platform that keeps the
        placeholder whatever it is sent leaves the placeholder's digest on the record."""
        class KeepsThePlaceholder(FakePlatform):
            def create_app(self, spec):
                app = super().create_app(spec)
                self._records[app["id"]]["request_template"] = json.dumps(
                    {"message": "{{PROMPT}}", "_adaptor_src": "v0:passthrough"})
                return app

            def patch_app(self, app_id, patch):
                self.patches.append((app_id, json.loads(json.dumps(patch))))
                return {}

        platform = KeepsThePlaceholder(existing=None)
        code, out, _ = _target_add(monkeypatch, tmp_path, capsys, platform)
        rec = out["data"]["adaptor"]
        assert code == 1 and out["error"]["code"] == "store_unverified" and rec["stored"] is False
        assert len(platform.patches) == 1, "one PATCH to put the bytes back, read back again"
        assert rec["template_digest"] == FRESH_D and rec["stored_digest"] == PLACEHOLDER_D

    def test_a_source_the_lint_refuses_never_reaches_the_gate_and_has_neither_key(self, monkeypatch, tmp_path, capsys):
        """Absent, not wrong: with no gate pass there is no template value and no record."""
        import adaptor as AD
        monkeypatch.setattr(AD, "lint_source", lambda src: ["fetch: not available inside the isolate (line 1)"])
        platform = FakePlatform(existing=None)
        code, out, _ = _target_add(monkeypatch, tmp_path, capsys, platform)
        assert code == 1 and out["error"]["code"] == "adaptor_lint"
        assert platform.gated == [] and platform.created == []
        assert "adaptor" not in out
        assert "template_digest" not in json.dumps(out) and "stored_digest" not in json.dumps(out)
