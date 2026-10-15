"""
runtime/adaptor.py — the rules of the custom-adaptor loop, with no network and no CLI.

Ported from the SE toolkit's own tests (its store-address and reply-shape suites) and extended
for what the CLI adds: a store that keeps every template key, one verdict over a test/verify
payload, and the run budget the engine would refuse.
"""
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "runtime"))
import adaptor as AD  # noqa: E402


class TestIds:
    @pytest.mark.parametrize("ref,expected", [
        ("3f2a9c1e-7b4d-4e8f-9a0b-1c2d3e4f5a6b", True),
        ("3F2A9C1E-7B4D-4E8F-9A0B-1C2D3E4F5A6B", True),
        (" 3f2a9c1e-7b4d-4e8f-9a0b-1c2d3e4f5a6b ", True),
        ("aapp_6Q7PYEESZsD67DdvfHCF3u", False),
        ("My Bot", False),
        ("", False),
        (None, False),
    ])
    def test_the_engine_uuid_is_told_by_shape(self, ref, expected):
        assert AD.is_engine_uuid(ref) is expected


class TestBudget:
    def test_the_default(self):
        assert AD.check_budget(None) == (AD.DEFAULT_BUDGET_S, None)

    @pytest.mark.parametrize("value", [1, 60, 240, "90", 1.5])
    def test_in_range(self, value):
        budget, why = AD.check_budget(value)
        assert why is None and budget == float(value)

    @pytest.mark.parametrize("value", [0, -5, 241, 1000, 0.5, 0.99])
    def test_out_of_range_names_the_limit(self, value):
        """Checked locally so the error says 1 and 240, not a bare 422 from the engine — which
        requires a whole second at least; 0.5 used to pass here and be refused remotely."""
        budget, why = AD.check_budget(value)
        assert budget is None and "240" in why and "between 1 and" in why

    def test_not_a_number(self):
        budget, why = AD.check_budget("soon")
        assert budget is None and "number" in why


class TestTemplate:
    def test_the_platforms_json_string(self):
        assert AD.parse_template('{"message": "{{PROMPT}}"}') == {"message": "{{PROMPT}}"}

    def test_a_dict_is_copied_not_shared(self):
        d = {"a": 1}
        out = AD.parse_template(d)
        assert out == d and out is not d

    @pytest.mark.parametrize("raw", [None, "", "   "])
    def test_empty_is_an_empty_template(self, raw):
        assert AD.parse_template(raw) == {}

    @pytest.mark.parametrize("raw", ["not json", "[1, 2]", '"a string"', 42])
    def test_anything_but_an_object_raises(self, raw):
        """Silently replacing a non-object template would drop the prompt key."""
        with pytest.raises(ValueError):
            AD.parse_template(raw)

    def test_display_collapses_only_the_adaptor(self):
        tpl = {"message": "{{PROMPT}}", "_adaptor_src": "c3Jj" * 100, "_adaptor_user_role": "admin"}
        shown = AD.template_for_display(tpl)
        assert shown == {"message": "{{PROMPT}}", "_adaptor_src": "<400b of base64>",
                         "_adaptor_user_role": "admin"}

    def test_display_keeps_an_alias_readable(self):
        assert AD.template_for_display({"_adaptor_src": "v0:passthrough"}) == {
            "_adaptor_src": "v0:passthrough"}

    def test_inline_versus_alias(self):
        assert AD.is_inline_source("function sendTurn() {}")
        assert not AD.is_inline_source("  v0:shop_build")


class TestMergeKeepsEveryKey:
    def test_only_the_adaptor_key_changes(self):
        tpl = {"message": "{{PROMPT}}", "user": "straiker", "_adaptor_user_role": "admin"}
        before = dict(tpl)
        merged, notes = AD.merge_source(tpl, "_adaptor_src", "c3Jj")
        assert merged == {**before, "_adaptor_src": "c3Jj"}
        assert notes == []
        assert tpl == before, "the input template must not be mutated"

    def test_the_placeholder_is_replaced_and_said(self):
        merged, notes = AD.merge_source({"message": "{{PROMPT}}", "_adaptor_src": AD.PLACEHOLDER},
                                        "_adaptor_src", "c3Jj")
        assert merged["_adaptor_src"] == "c3Jj"
        assert any("placeholder" in n for n in notes)

    def test_replacing_a_stored_adaptor_is_said(self):
        _, notes = AD.merge_source({"message": "{{PROMPT}}", "_adaptor_src": "b2xk"},
                                   "_adaptor_src", "c3Jj")
        assert any("already stored" in n for n in notes)

    def test_storing_the_same_bytes_again_is_quiet(self):
        _, notes = AD.merge_source({"message": "{{PROMPT}}", "_adaptor_src": "c3Jj"},
                                   "_adaptor_src", "c3Jj")
        assert notes == []

    def test_a_template_with_no_prompt_key_is_flagged(self):
        """The Console refuses to save the app's form until there is one."""
        _, notes = AD.merge_source({"_adaptor_endpoint": "https://t"}, "_adaptor_src", "c3Jj")
        assert any("{{PROMPT}}" in n for n in notes)

    def test_the_key_falls_back_when_the_gate_names_none(self):
        merged, _ = AD.merge_source({}, "", "c3Jj")
        assert merged == {"_adaptor_src": "c3Jj"}


class TestAddress:
    def test_the_apps_url_is_the_address(self):
        assert AD.address_problem("https://chat.example.com/v1", {}) is None

    def test_the_retired_marker_is_refused(self):
        why = AD.address_problem("https://custom-adaptor", {"_adaptor_endpoint": "https://t"})
        assert "retired" in why

    def test_no_url_and_no_endpoint_is_refused(self):
        assert "nowhere to go" in AD.address_problem("", {"message": "{{PROMPT}}"})

    def test_no_url_but_an_endpoint_is_fine(self):
        assert AD.address_problem("", {"_adaptor_endpoint": "https://t"}) is None


class TestDeadEndpointKeysAreReportedNotDropped:
    def test_with_a_url_every_endpoint_key_is_dead(self):
        tpl = {"message": "{{PROMPT}}", "_adaptor_endpoint": "https://t",
               "_adaptor_shop_endpoint": "https://t"}
        dead, why = AD.dead_endpoint_keys(tpl, "https://chat.example.com/v1", inline=True)
        assert sorted(dead) == ["_adaptor_endpoint", "_adaptor_shop_endpoint"]
        assert "URL" in why

    def test_without_a_url_inline_source_reads_only_the_bare_key(self):
        tpl = {"_adaptor_endpoint": "https://t", "_adaptor_shop_endpoint": "https://t"}
        dead, why = AD.dead_endpoint_keys(tpl, "", inline=True)
        assert dead == ["_adaptor_shop_endpoint"] and "alias" in why

    def test_an_alias_reads_its_namespaced_key(self):
        assert AD.dead_endpoint_keys({"_adaptor_shop_endpoint": "https://t"}, "", inline=False) \
            == ([], "")

    def test_nothing_to_report(self):
        assert AD.dead_endpoint_keys({"message": "{{PROMPT}}"}, "", inline=True) == ([], "")

    def test_merge_never_drops_them(self):
        """`store` only ever ADDS `_adaptor_src`. A dead key is the operator's to remove."""
        merged, _ = AD.merge_source({"message": "{{PROMPT}}", "_adaptor_endpoint": "https://t"},
                                    "_adaptor_src", "c3Jj")
        assert merged["_adaptor_endpoint"] == "https://t"


class TestReplyShape:
    @pytest.mark.parametrize("tpl,path,statement", [
        ('{"response": "{{ RESPONSE }}"}', "response",
         "return { status_code: 200, body: { response: text } };"),
        ('{"reply": "{{RESPONSE}}"}', "reply",
         "return { status_code: 200, body: { reply: text } };"),
        ('{"data": {"reply": "{{RESPONSE}}"}}', "data.reply",
         "return { status_code: 200, body: { data: { reply: text } } };"),
        ({"answer": "{{RESPONSE}}"}, "answer",
         "return { status_code: 200, body: { answer: text } };"),
        ('"{{RESPONSE}}"', "", "return { status_code: 200, body: text };"),
    ])
    def test_the_statement_to_write(self, tpl, path, statement):
        assert AD.reply_shape(tpl) == {"path": path, "statement": statement}

    @pytest.mark.parametrize("tpl", [None, "", "{}", '{"x": "y"}', "not json"])
    def test_no_response_marker_means_ask(self, tpl):
        assert AD.reply_shape(tpl) is None


class TestWhatADetectorSees:
    """`test`/`verify` must shout when the scored text is the whole body stringified."""

    @pytest.mark.parametrize("scored,flagged", [
        ("{'response': 'the answer'}", True),
        ('{"response": "the answer"}', True),
        ("[{'a': 1}]", True),
        ("Papua New Guinea has the most languages.", False),
        ("", False),
        ("{not actually a dict", False),
    ])
    def test_the_dict_repr_signature(self, scored, flagged):
        assert AD.looks_unextracted(scored) is flagged

    def test_the_problem_names(self):
        assert AD.scored_problem({"scored": "{'response': 'x'}"}) == "unextracted"
        assert AD.scored_problem({"scored": "   "}) == "empty"
        assert AD.scored_problem({"scored": "a real answer"}) is None

    def test_an_older_engine_sends_no_scored_field(self):
        """Nothing to judge, so no complaint — the caller falls back to `parsed`."""
        assert AD.scored_problem({}) is None
        assert AD.scored_problem({"scored": None}) is None


class TestVerdict:
    def test_a_clean_run(self):
        v = AD.summarize_run({"preflight": None, "turns": [
            {"n": 1, "status_code": 200, "ms": 10, "scored": "hello there friend"}]})
        assert v["ok"] and v["problems"] == []
        assert v["preflight"] == {"defined": False}
        assert v["turns"] == [{"n": 1, "status_code": 200, "ms": 10, "ok": True,
                               "scored_problem": None}]

    def test_a_refused_gate_runs_nothing(self):
        v = AD.summarize_run({"gate": {"ok": False, "violations": [{"kind": "async"}]}})
        assert not v["ok"] and "refused" in v["problems"][0] and v["turns"] == []

    def test_a_failed_preflight_blocks_the_run(self):
        v = AD.summarize_run({"preflight": {"status_code": 401, "ms": 5}, "turns": [
            {"n": 1, "status_code": 200, "scored": "an answer here"}]})
        assert not v["ok"]
        assert v["preflight"] == {"defined": True, "ok": False, "status_code": 401, "ms": 5}
        assert "401" in v["problems"][0]

    def test_a_non_200_turn(self):
        v = AD.summarize_run({"turns": [{"n": 1, "status_code": 500, "scored": "adapter fault"}]})
        assert not v["ok"] and "500" in v["problems"][0]

    def test_a_stringified_body_is_not_done(self):
        """A 200 that a detector would score verbatim is the failure that does not look like one."""
        v = AD.summarize_run({"turns": [{"n": 1, "status_code": 200, "scored": "{'response': 'x'}"}]})
        assert not v["ok"] and v["turns"][0]["scored_problem"] == "unextracted"

    def test_an_empty_scored_text_is_not_done(self):
        v = AD.summarize_run({"turns": [{"n": 1, "status_code": 200, "scored": ""}]})
        assert not v["ok"] and "NOTHING" in v["problems"][0]

    def test_no_turns_is_not_a_pass(self):
        assert AD.summarize_run({"turns": []})["ok"] is False
        assert AD.summarize_run({})["ok"] is False

    def test_the_engines_own_verify_verdict_wins(self):
        v = AD.summarize_run({"ok": False, "summary": "no adaptor resolved", "turns": []})
        assert not v["ok"] and v["problems"] == ["no adaptor resolved"]
        # ...even when every turn looked healthy
        v2 = AD.summarize_run({"ok": False, "summary": "budget", "turns": [
            {"n": 1, "status_code": 200, "scored": "a fine answer"}]})
        assert not v2["ok"] and "budget" in v2["problems"]
        assert AD.summarize_run({"ok": True, "turns": []})["ok"] is True


class TestGateText:
    def test_violation_lines_name_kind_detail_and_line(self):
        g = {"violations": [{"kind": "async", "detail": "no await", "line": 2},
                            {"kind": "unknown-identifier", "detail": "fetch"}]}
        assert AD.violation_lines(g) == ["REFUSED  async: no await (line 2)",
                                         "REFUSED  unknown-identifier: fetch"]

    def test_preflight_note(self):
        assert AD.preflight_note({"entries": ["sendTurn"]}).startswith("none")
        assert AD.preflight_note({"entries": ["sendTurn", "checkReachability"]}) == "checkReachability"
        assert AD.preflight_note({}) is None, "an older engine reports no entries"


class TestShippedJavaScript:
    def test_the_two_templates_ship(self):
        assert "function sendTurn(turn, host)" in AD.template_js("scaffold")
        assert "function sendTurn(turn, host)" in AD.template_js("example")

    def test_an_unknown_kind_is_refused(self):
        with pytest.raises(ValueError):
            AD.template_js("nope")


class TestRecordDigest:
    """The record's basis: sha-256 of a template value as the record holds it, first 12 hex. The
    one hashing site every verb goes through for `template_digest` and `stored_digest`."""

    def test_the_recipe_is_pinned_to_known_vectors(self):
        assert AD.record_digest("c3Jj") == "0daa5aa6a04c"
        assert AD.record_digest("FRESH-ADAPTOR") == "354ed181b212"
        assert AD.record_digest("v0:passthrough") == "b2bf54095507"

    def test_twelve_hex_characters_of_sha256(self):
        import hashlib
        value = "ZnVuY3Rpb24gc2VuZFR1cm4oKSB7fQ=="
        assert AD.record_digest(value) == hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]
        assert len(AD.record_digest(value)) == 12

    @pytest.mark.parametrize("value", [None, "", 0, 42, {}, [], b"c3Jj"])
    def test_anything_but_a_non_empty_string_is_none_not_a_hash(self, value):
        assert AD.record_digest(value) is None

    def test_the_value_is_hashed_as_held_not_trimmed(self):
        assert AD.record_digest("c3Jj\n") != AD.record_digest("c3Jj")
        assert AD.record_digest(" c3Jj") != AD.record_digest("c3Jj")

    def test_the_cli_hashes_nowhere_else(self):
        """One hashing site (docs/CHANGE_CONTROL.md: test the call sites, not just the helper).
        Every value the CLI puts under either key is `None` or comes out of record_digest, and the
        CLI never imports hashlib for its own recipe."""
        import re
        src = (REPO / "shells" / "cli" / "ascend.py").read_text(encoding="utf-8")
        assert "hashlib" not in src
        sites = re.findall(r'(template_digest|stored_digest)["\'\]]*\s*[:=]\s*([^,}\n]+)', src)
        assert len(sites) >= 5, sites            # store x2, target add x2, get x1
        for key, value in sites:
            assert value.strip() == "None" or value.strip().startswith("AD.record_digest("), (key, value)
