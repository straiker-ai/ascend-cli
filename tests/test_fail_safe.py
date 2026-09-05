"""
test_fail_safe — the round-5 P0 contract: nothing may FAIL OPEN.

Each case here was a real bug that exited 0 (or looked clean) while hiding something:
  * a completed assessment we cannot read passed a CI pipeline;
  * a missing per-control severity was silently rewritten to "medium", which could turn a
    critical finding into one that clears `--fail-on-severity high`;
  * an unrecognized severity sorted as *least* severe, so it never breached the gate;
  * SARIF softened an unrankable finding to "warning".

The CI exit-code contract these pin: 0 = clean · 1 = could not read results · 2 = findings gate.
"""
import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from reporting import ci as CI                      # noqa: E402
from reporting.export import iter_findings, to_sarif  # noqa: E402


def _assessment(controls, **kw):
    a = {"status": "complete", "category_summary": [
        {"id": "cat", "name": "Cat", "controls": controls}]}
    a.update(kw)
    return a


# --------------------------------------------------------------- unreadable results
def test_completed_but_no_category_data_is_never_a_pass():
    res = CI.gate({"status": "complete", "score": 0, "severity": "low"})
    assert res["exit_code"] != 0
    assert res["unreadable"] is True
    assert "cannot read results" in res["reasons"][0]


def test_a_still_running_assessment_is_refused_not_passed():
    """Gating a partial run is itself a false clean: the findings simply have not happened yet.

    This used to assert only that `unreadable` was absent, which a plain exit 0 satisfied — so a
    CI job that gated one poll too early reported CLEAN on a run that had barely started.
    """
    res = CI.gate({"status": "running"})
    assert res["exit_code"] == 1, "a partial run must never be reported as clean"
    assert "not finished" in res["reasons"][0]


@pytest.mark.parametrize("status", ["failed", "error", "cancelled", "canceled", "aborted"])
def test_a_run_that_died_server_side_is_refused(status):
    """These are all TERMINAL statuses, so poll_assessment hands exactly this object back as the
    final result of a run. It used to gate green."""
    res = CI.gate({"status": status, "total": 100})
    assert res["exit_code"] == 1, f"a run that ended '{status}' measured only part of the target"
    assert res["unreadable"] is True


def test_a_payload_with_no_status_is_refused():
    """The old guard keyed on the status string, so drift in that very field disabled it."""
    res = CI.gate({"state": "completed", "total": 100})
    assert res["exit_code"] == 1
    assert "no status field" in res["reasons"][0]


def test_genuinely_clean_completed_run_still_passes():
    a = _assessment([{"id": "ok", "status": "pass", "severity": "low", "failed": 0, "total": 5}],
                    severity="low", score=0)
    assert CI.gate(a, fail_on_severity="high", fail_on_new=False)["exit_code"] == 0


# --------------------------------------------------------------- severity fail-safe
def test_missing_per_control_severity_is_unknown_not_medium():
    a = _assessment([{"id": "ctl", "status": "fail", "failed": 3, "total": 5}])
    f = iter_findings(a)[0]
    assert f["severity"] == "unknown"          # was silently "medium"
    assert f["severity_missing"] is True


def test_unknown_severity_breaches_the_gate():
    """Fail safe: a finding we cannot rank must not clear the threshold."""
    a = _assessment([{"id": "ctl", "status": "fail", "failed": 1, "total": 1}])
    res = CI.gate(a, fail_on_severity="high", fail_on_new=False)
    assert res["exit_code"] == 2
    assert any("unknown" in r for r in res["reasons"])


def test_unknown_severity_is_not_softened_in_sarif():
    a = _assessment([{"id": "ctl", "status": "fail", "failed": 1, "total": 1}])
    sarif = json.loads(to_sarif(a))
    assert sarif["runs"][0]["results"][0]["level"] == "error"


def test_control_severity_falls_back_to_assessment_severity_before_unknown():
    a = _assessment([{"id": "ctl", "status": "fail", "failed": 1, "total": 1}], severity="critical")
    f = iter_findings(a)[0]
    assert f["severity"] == "critical"
    assert f["severity_missing"] is True       # still flagged: it wasn't the control's own value


@pytest.mark.parametrize("sev,breaches", [
    ("critical", True), ("high", True), ("medium", False), ("low", False),
    ("weird-new-value", True),                 # unrecognized => treated as most severe
])
def test_threshold_semantics_hold(sev, breaches):
    a = _assessment([{"id": "ctl", "status": "fail", "severity": sev, "failed": 1, "total": 1}])
    res = CI.gate(a, fail_on_severity="high", fail_on_new=False)
    assert (res["exit_code"] == 2) is breaches, f"{sev} should {'breach' if breaches else 'pass'}"


# --------------------------------------------------------------- CLI-level fail-safes
import os          # noqa: E402
import subprocess  # noqa: E402


def _cli(*args, env=None):
    e = dict(os.environ)
    e["STRAIKER_PAT"] = "s6r_pat_dummy"   # FORCED: setdefault kept a real PAT from the shell
    e["ASCEND_SKIP_TENANT_CHECK"] = "1"
    if env:
        e.update(env)
    return subprocess.run([sys.executable, str(REPO / "shells/cli/ascend.py"), *args],
                          capture_output=True, text=True, env=e, cwd=str(REPO))


def test_keys_prune_has_the_all_keys_guard():
    """The wipe risk: an empty/unreadable app list must not look like 'every app is gone'."""
    src = (REPO / "shells/cli/ascend.py").read_text()
    assert "Refusing to prune" in src
    assert "would delete ALL" in src
    h = _cli("keys", "prune", "--help")
    assert h.returncode == 0 and "--yes" in h.stdout


def test_thin_key_assert_exists_at_both_create_sites():
    src = (REPO / "shells/cli/ascend.py").read_text()
    assert src.count("_require_thin_key(") >= 3      # helper def + create-thin + onboard
    assert "shown only once" in src


def test_gate_reports_the_same_code_the_process_exits_with():
    """They used to be inverses: an unreadable run published `exit_code: 2` ("findings gate
    failed") while exiting 1, and a real finding published `1` ("tool error") while exiting 2.
    An agent following the documented table got the opposite of the truth in both directions."""
    src = (REPO / "shells/cli/ascend.py").read_text()
    assert 'sys.exit(int(res.get("exit_code"' in src, \
        "cmd_ci must exit with the code it published, not a translation of it"
    unreadable = CI.gate({"status": "complete", "category_summary": []})
    assert unreadable["exit_code"] == 1
    findings = CI.gate(_assessment([{"id": "c", "status": "fail", "severity": "critical",
                                     "failed": 1, "total": 10}]), fail_on_new=False)
    assert findings["exit_code"] == 2
    clean = CI.gate(_assessment([{"id": "c", "status": "pass", "severity": "low",
                                  "failed": 0, "total": 10}]), fail_on_new=False)
    assert clean["exit_code"] == 0


# --------------------------------------------------------------- local policy (P4)
def test_policy_reranks_and_changes_the_gate_verdict():
    """Per-control severity is not settable via the v3 API, so a local policy must actually
    change the CI verdict — not just the display."""
    sys.path.insert(0, str(REPO / "runtime"))
    a = _assessment([{"id": "pii_leak", "status": "fail", "severity": "low",
                      "failed": 2, "total": 10}])
    assert CI.gate(a, fail_on_severity="high", fail_on_new=False)["exit_code"] == 0
    pol = {"default": {"controls": {"pii_leak": "critical"}}}
    res = CI.gate(a, fail_on_severity="high", fail_on_new=False, policy=pol)
    assert res["exit_code"] == 2
    assert any("critical" in r for r in res["reasons"])


def test_policy_thresholds_and_precedence(tmp_path, monkeypatch):
    sys.path.insert(0, str(REPO / "runtime"))
    monkeypatch.setenv("ASCEND_POLICY", str(tmp_path / "p.json"))
    import importlib
    import policy as P
    importlib.reload(P)
    P.save({"default": {"fail_on_severity": "high", "categories": {"data_leak": "medium"}},
            "apps": {"Bot": {"fail_on_severity": "medium",
                             "controls": {"tool_misuse": "critical"}}}})
    doc = P.load()
    assert P.thresholds(doc)["fail_on_severity"] == "high"
    assert P.thresholds(doc, "Bot")["fail_on_severity"] == "medium"   # app beats default
    # app control override beats global category override
    assert P.severity_for(doc, control_id="tool_misuse", category="data_leak",
                          reported="low", app_name="Bot") == "critical"
    # falls back to the reported value when nothing matches
    assert P.severity_for(doc, control_id="other", category="none",
                          reported="high", app_name="Bot") == "high"
