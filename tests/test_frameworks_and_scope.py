"""Response-shape recognition names a reply path (advisory), and capability->scope proposes the
right controls with a reason. Both are read-only and additive."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "runtime"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from discovery.frameworks import recognize  # noqa: E402
from scope import propose  # noqa: E402


def _ev(body):
    import json
    return {"prompt_sent": "hi", "pairs": [{"request": {"raw_body": '{"message":"hi"}'},
            "response": {"raw_body": json.dumps(body), "content_type": "application/json"}}]}


def test_recognises_the_common_envelopes():
    assert recognize(_ev({"choices": [{"message": {"role": "assistant", "content": "hello"}}]}))["response_path"] == "choices.0.message.content"
    assert recognize(_ev({"content": [{"type": "text", "text": "hi"}]}))["response_path"] == "content.*.text"
    assert recognize(_ev([{"recipient_id": "u", "text": "hi"}]))["response_path"] == "*.text"
    assert recognize(_ev({"messages": [{"role": "user", "content": "hi"}, {"role": "assistant", "content": "hello"}]}))["response_path"] == "messages.-1.content"
    assert recognize(_ev({"reply": "hello"}))["response_path"] == "reply"
    assert recognize(_ev({"result": {"answer": "hello"}}))["response_path"] == "result.answer"
    assert recognize(_ev({"data": '{"reply":"x"}'}))["response_path"] == "data~json"


def test_unknown_shape_and_no_body_are_none_not_a_guess():
    assert recognize(_ev({"foo": {"bar": 1}}))["framework"] is None
    assert recognize({"pairs": []})["framework"] is None


def test_scope_maps_capabilities_to_controls_with_reasons():
    p = propose({"rag": True, "tools": True, "code_interpreter": False})
    controls = [x["control"] for x in p["scope"]]
    assert "app_grounding" in controls and "data_leak" in controls and "agentic_tmu" in controls
    assert "agentic_rce" not in controls
    assert all(x["why"] for x in p["scope"])
    assert [b["control"] for b in p["baseline"]] == ["sys_prompt_leak", "jailbreak"]
    assert "rag" in p["matched"] and "tools" in p["matched"]


def test_scope_accepts_a_flat_capability_list_and_dedupes():
    p = propose(["retrieval knowledge base", "user PII records", "sub-agent orchestrator"])
    controls = [x["control"] for x in p["scope"]]
    assert controls.count("data_leak") == 1                 # rag + user_data both imply it, listed once
    assert "agentic_data_exfil" in controls and "agentic_tmu" in controls


def test_no_capabilities_recommends_only_the_baseline_and_says_so():
    p = propose({})
    assert p["scope"] == [] and p["matched"] == []
    assert any("no agentic capabilities" in n for n in p["notes"])


# --------------------------------------------------------------------------- resolve against a live catalog
# Shaped like the live `/ascend/controls` payload (see test_controls_catalog.py): two lists,
# categories carrying their members, controls carrying `deprecated`.
_CATALOG = {
    "controls": [
        {"id": "sys_prompt_leak", "name": "System Prompt Leak", "category_id": "sys_prompt_leak"},
        {"id": "indirect_prompt_injection", "name": "Indirect Prompt Injection", "category_id": "llm_evasion"},
        {"id": "agentic_tmu", "name": "Agentic Tool Misuse", "category_id": "agent_vulnerabilities", "agentic": True},
        {"id": "agentic_data_exfil", "name": "Agentic Data Exfiltration", "category_id": "agent_vulnerabilities", "agentic": True},
        {"id": "tool_misuse", "name": "Tool Misuse", "category_id": "agent_vulnerabilities", "deprecated": True},
        {"id": "email_address", "name": "Email Address", "category_id": "data_leak"},
        {"id": "phone_number", "name": "Phone Number", "category_id": "data_leak"},
        {"id": "business_risk", "name": "Business Risk", "category_id": "business_risk"},
    ],
    "categories": [
        {"id": "sys_prompt_leak", "name": "System Prompt Leak", "tag": "Security"},
        {"id": "llm_evasion", "name": "LLM Evasion", "tag": "Security"},
        {"id": "agent_vulnerabilities", "name": "Agentic Risks", "tag": "Security"},
        {"id": "data_leak", "name": "Data Leakage", "tag": "Security"},
        {"id": "business_risk", "name": "Business Risk", "tag": "Trust"},
    ],
}


def test_resolve_keeps_exact_ids_expands_categories_and_names_unknowns():
    from scope import resolve
    r = resolve(["sys_prompt_leak", "data_leak", "agentic_tmu", "no_such_control"], _CATALOG)
    assert r["catalog_seen"]
    assert "sys_prompt_leak" in r["controls"] and "agentic_tmu" in r["controls"]
    assert {"email_address", "phone_number"} <= set(r["controls"])      # the category expanded
    assert "tool_misuse" not in r["controls"]                           # deprecated never selected
    assert r["unknown"] == ["no_such_control"]
    kinds = {x["proposed"]: x["kind"] for x in r["resolved"]}
    assert kinds == {"sys_prompt_leak": "control", "data_leak": "category", "agentic_tmu": "control",
                     "no_such_control": "unknown"}


def test_resolve_maps_the_proposal_vocabulary_through_aliases():
    from scope import resolve
    r = resolve(["jailbreak", "app_grounding"], _CATALOG)
    via = {x["proposed"]: (x["kind"], x["ids"]) for x in r["resolved"]}
    assert via["jailbreak"] == ("alias", ["indirect_prompt_injection"])        # stem prompt_injection
    assert via["app_grounding"] == ("alias", ["business_risk"])
    assert r["unknown"] == []


def test_resolve_without_a_catalog_passes_names_through_and_says_so():
    from scope import resolve
    r = resolve(["data_leak"], None)
    assert r["controls"] == ["data_leak"] and not r["catalog_seen"] and "unchanged" in r["note"]
    r2 = resolve(["data_leak"], {"ok": True, "result": {"controls": [], "categories": []}})
    assert not r2["catalog_seen"]


def test_resolve_dedupes_across_proposals_and_reads_a_wrapped_result():
    from scope import resolve
    wrapped = {"ok": True, "result": _CATALOG}
    r = resolve(["data_leak", "email_address"], wrapped)
    assert r["controls"].count("email_address") == 1
