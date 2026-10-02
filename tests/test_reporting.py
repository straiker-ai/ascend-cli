"""
test_reporting.py — findings export (JSON/CSV/SARIF/Markdown) and the CI gate.

These wrap an engagement in the controls a program office expects around an
authorized offensive test. Every module is pure/local (stdlib only, no network,
no wall-clock reads inside the library), which makes the safety-critical
behaviours deterministically testable:

  * roe.check_target — host-glob allowlist enforcement (in/out of scope);
  * roe blackout windows, kill switch, attestation refusals;
  * ledger side-effect budget accounting (deny once a cap is spent) + 0600 file;
  * audit SHA-256 hash-chain verify + tamper localization + 0600 file;
  * export.to_sarif — valid SARIF 2.1.0; JSON/CSV/Markdown exports;
  * ci.gate exit codes + baseline diff (new/resolved/regressions) + JUnit XML.

Skips cleanly if the package is ever removed.
"""
import json
import os
import stat

import pytest

reporting = pytest.importorskip("reporting",
                                 reason="reporting package not present")
export = reporting.export
ci = reporting.ci


# ===========================================================================
# roe — target scope enforcement
# ===========================================================================
IN_SCOPE = [
    ("https://api.example.com/chat", ["*.example.com"]),
    ("https://api.example.com/v1/x", ["api.example.com"]),
    ("https://bot.example.com/socket", ["*.example.com"]),
    ("https://api.example.com/chat", ["*"]),
    ("http://10.0.0.5/api", ["10.0.*"]),
]
OUT_OF_SCOPE = [
    ("https://evil.other.com/chat", ["*.example.com"]),
    ("https://example.com.attacker.net/x", ["example.com"]),
    ("https://prod.example.com/x", ["*.staging.example.com"]),
    ("https://api.example.com/x", []),  # empty allowlist => nothing in scope
]


@pytest.mark.parametrize("url,allow", IN_SCOPE)




























def sample_assessment():
    return {
        "status": "completed", "score": 42, "severity": "high",
        "category_summary": [
            {"category": "prompt-injection", "failed": 2, "total": 10, "status": "fail",
             "controls": [
                 {"id": "sys_prompt_leak", "status": "fail", "severity": "high",
                  "failed": 2, "total": 4,
                  "keyfindings": ["leaked system prompt on turn 3"]},
                 {"id": "instruction_manipulation", "status": "fail", "severity": "medium",
                  "failed": 1, "total": 6, "keyfindings": []},
             ]},
            {"category": "toxicity", "failed": 0, "total": 5, "status": "pass",
             "controls": [
                 {"id": "sexism", "status": "pass", "severity": "low",
                  "failed": 0, "total": 5}]},
        ],
    }


def test_iter_findings_only_failed():
    findings = export.iter_findings(sample_assessment())
    ids = {f["control_id"] for f in findings}
    assert ids == {"sys_prompt_leak", "instruction_manipulation"}  # passing control excluded


def test_iter_findings_empty_when_all_pass():
    a = {"category_summary": [{"category": "c", "controls": [
        {"id": "x", "status": "pass", "failed": 0, "total": 3}]}]}
    assert export.iter_findings(a) == []


def test_to_json_valid():
    doc = json.loads(export.to_json(sample_assessment()))
    assert doc["finding_count"] == 2
    assert doc["tool"] == "Straiker Ascend"
    assert len(doc["findings"]) == 2


def test_to_csv_rows():
    csv_text = export.to_csv(sample_assessment())
    lines = [l for l in csv_text.splitlines() if l.strip()]
    assert lines[0].startswith("control_id,")
    assert len(lines) == 3  # header + 2 findings
    assert "leaked system prompt on turn 3" in csv_text


def test_to_markdown_contains_findings():
    md = export.to_markdown(sample_assessment())
    assert "# Ascend Assessment Findings" in md
    assert "sys_prompt_leak" in md
    assert "instruction_manipulation" in md


def test_to_markdown_no_findings():
    md = export.to_markdown({"status": "completed", "category_summary": []})
    assert "No failed controls" in md


def test_to_sarif_valid_2_1_0():
    doc = json.loads(export.to_sarif(sample_assessment()))
    assert doc["version"] == "2.1.0"
    assert "$schema" in doc
    assert isinstance(doc["runs"], list) and doc["runs"]
    run0 = doc["runs"][0]
    driver = run0["tool"]["driver"]
    assert driver["name"] == "Straiker Ascend"
    # one rule per distinct failed control id
    rule_ids = {r["id"] for r in driver["rules"]}
    assert rule_ids == {"sys_prompt_leak", "instruction_manipulation"}
    # results reference valid rule indices and SARIF levels
    levels = {r["level"] for r in run0["results"]}
    assert levels <= {"error", "warning", "note", "none"}
    for res in run0["results"]:
        assert res["ruleId"] in rule_ids
        assert 0 <= res["ruleIndex"] < len(driver["rules"])
        assert "message" in res and "text" in res["message"]


def test_to_sarif_severity_maps_to_level():
    doc = json.loads(export.to_sarif(sample_assessment()))
    results = {r["ruleId"]: r["level"] for r in doc["runs"][0]["results"]}
    assert results["sys_prompt_leak"] == "error"       # high -> error
    assert results["instruction_manipulation"] == "warning"  # medium -> warning


def test_to_sarif_empty_findings():
    doc = json.loads(export.to_sarif({"status": "completed", "category_summary": []}))
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["results"] == []


# ===========================================================================
# ci — gate + baseline diff + JUnit
# ===========================================================================
def _assessment_with(controls):
    return {"status": "completed",
            "category_summary": [{"category": "c", "controls": controls}]}


# exit_code is the PROCESS exit code: 0 clean · 1 could not read/trust · 2 findings gate failed.
@pytest.mark.parametrize("severity,threshold,expect_code", [
    ("high", "high", 2),      # at threshold → findings gate fails
    ("critical", "high", 2),  # above threshold → findings gate fails
    ("medium", "high", 0),    # below threshold → pass
    ("low", "high", 0),
])
def test_ci_gate_severity_threshold(severity, threshold, expect_code):
    a = _assessment_with([{"id": "x", "status": "fail", "severity": severity,
                           "failed": 1, "total": 3}])
    result = ci.gate(a, baseline=None, fail_on_severity=threshold, fail_on_new=False)
    assert result["exit_code"] == expect_code


def test_ci_gate_clean_passes():
    a = _assessment_with([{"id": "x", "status": "pass", "severity": "low",
                           "failed": 0, "total": 3}])
    result = ci.gate(a, fail_on_severity="high", fail_on_new=True)
    assert result["exit_code"] == 0
    assert result["reasons"] == []


def test_ci_gate_new_finding_fails():
    baseline = _assessment_with([{"id": "old", "status": "fail", "severity": "low",
                                  "failed": 1, "total": 3}])
    current = _assessment_with([
        {"id": "old", "status": "fail", "severity": "low", "failed": 1, "total": 3},
        {"id": "new", "status": "fail", "severity": "low", "failed": 1, "total": 3}])
    result = ci.gate(current, baseline=baseline, fail_on_severity="critical",
                     fail_on_new=True)
    assert result["exit_code"] == 2
    assert any("new finding" in r for r in result["reasons"])


def test_ci_compare_new_resolved_regression():
    """`b` is RE-RUN here — it appears in the current run's control table, passing.

    It used to be omitted from `current` entirely and still counted as resolved, which is the
    false green test_ci_resolved_vs_not_retested.py exists for: `resolved` is proof a control was
    re-tested, so a control that was re-tested has to be present to earn it.
    """
    baseline = _assessment_with([
        {"id": "a", "status": "fail", "severity": "medium", "failed": 1, "total": 3},
        {"id": "b", "status": "fail", "severity": "low", "failed": 1, "total": 3}])
    current = _assessment_with([
        {"id": "a", "status": "fail", "severity": "critical", "failed": 2, "total": 3},  # worse
        {"id": "b", "status": "pass", "severity": "low", "failed": 0, "total": 3},       # fixed
        {"id": "c", "status": "fail", "severity": "high", "failed": 1, "total": 3}])      # new
    diff = ci.compare(baseline, current)
    new_ids = {f["control_id"] for f in diff["new_findings"]}
    resolved_ids = {f["control_id"] for f in diff["resolved"]}
    regressed_ids = {r["control_id"] for r in diff["regressions"]}
    assert new_ids == {"c"}
    assert resolved_ids == {"b"}
    assert diff["not_retested"] == []
    assert regressed_ids == {"a"}


def test_ci_compare_no_baseline_all_new():
    current = _assessment_with([{"id": "a", "status": "fail", "severity": "high",
                                 "failed": 1, "total": 3}])
    diff = ci.compare(None, current)
    assert {f["control_id"] for f in diff["new_findings"]} == {"a"}
    assert diff["resolved"] == []


def test_ci_to_junit_valid_xml():
    import xml.dom.minidom as minidom
    a = _assessment_with([{"id": "sys_prompt_leak", "status": "fail", "severity": "high",
                           "failed": 2, "total": 4, "keyfindings": ["leak"]}])
    xml = ci.to_junit(a)
    doc = minidom.parseString(xml)  # must parse
    suite = doc.getElementsByTagName("testsuite")[0]
    assert suite.getAttribute("failures") == "1"
    assert doc.getElementsByTagName("failure")


def test_ci_to_junit_clean_run():
    import xml.dom.minidom as minidom
    a = _assessment_with([{"id": "x", "status": "pass", "failed": 0, "total": 3}])
    xml = ci.to_junit(a)
    doc = minidom.parseString(xml)
    suite = doc.getElementsByTagName("testsuite")[0]
    assert suite.getAttribute("failures") == "0"
