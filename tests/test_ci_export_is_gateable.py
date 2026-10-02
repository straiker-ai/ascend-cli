"""
test_ci_export_is_gateable.py — the JSON a pipeline archives must be the JSON the gate can read.

THE FALSE RED
-------------
`export --format json` emitted {tool, status, score, severity, finding_count, findings}. `ci`
reads `category_summary`, and refuses without it. So the one artifact a CI job would naturally
keep — the machine-readable export — was the one input the gate could not take. Measured on
asmt_9EnmJ2itb8QqxSjfusfhE (tenant 123, 58 controls, 33 failing):

    ascend export --assessment asmt_9EnmJ2itb8QqxSjfusfhE --format json --out export.json
    ascend ci --file export.json
      -> exit 1  "the assessment reports completed but carries no category_summary"

As a BASELINE it failed the other way, and silently, which is worse than the refusal:

    ascend ci --assessment asmt_9EnmJ2itb8QqxSjfusfhE --baseline export.json
      -> exit 2, diff.new_findings = 33, 55 reasons

Thirty-three brand-new findings, diffing a run against a file that describes that same run.
Nothing was readable in the baseline, so nothing had been failing before, so everything was new.
A red build with no bug behind it teaches a team to pass `--allow-new`, and then the gate is
decoration.

WHY THE FIX IS IN `to_json` AND NOT IN THE GATE
-----------------------------------------------
A failures-only document is irrecoverably lossy for the question the gate asks. `findings` says
what failed; it cannot say which controls ran and passed. A gate taught to accept that shape
would have to read every absent control as "passing", which is precisely the false green
test_ci_resolved_vs_not_retested.py exists to stop — the export would have become a second route
into the bug next door. `category_summary` carries the whole control table, so the export carries
it, and a round trip survives.

`total`/`failed` ride along for a smaller reason with the same shape: without `total` the
dead-bridge probe floor has nothing to measure, so gating an export silently switched that guard
off.

The `findings` fallback in `iter_findings` covers export files written BEFORE this change, which
are on disk in people's pipelines already: as a baseline they now diff correctly instead of
inventing 33 findings. It does not make such a file gateable as the CURRENT run — see
TestALossyCurrentRunIsStillRefused.
"""
import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
for p in ("shells/cli", "runtime", "control", "tests", "."):
    sys.path.insert(0, str(REPO / p))

import real_assessments as R                              # noqa: E402
from reporting import ci as CI                            # noqa: E402
from reporting import export as E                         # noqa: E402

# The run from the measurement above: 58 controls, 33 failing, 1479 probes.
REAL = R.DROPPED


def _exported(a):
    return json.loads(E.to_json(a))


class TestTheExportCarriesWhatTheGateReads:
    def test_it_carries_the_control_table(self):
        doc = _exported(REAL)
        assert doc["category_summary"], "the gate's only input"
        assert len(E.tested_control_ids(doc)) == 58

    def test_it_still_carries_the_flat_findings_list(self):
        """The readable part, and the reason the format exists. Not traded away for the fix."""
        doc = _exported(REAL)
        assert doc["finding_count"] == 33 == len(doc["findings"])
        assert all("control_id" in f and "severity" in f for f in doc["findings"])

    def test_it_carries_the_probe_counts(self):
        """Without `total` the dead-bridge floor has nothing to measure."""
        doc = _exported(REAL)
        assert doc["total"] == 1479
        r = CI.gate(_exported(R.RETESTED), None, fail_on_severity="high", min_probes=5)
        assert r["exit_code"] == 1 and "probe" in r["reasons"][0], (
            "a 1-probe clean run exported to JSON must still be refused as untrustworthy")

    def test_it_names_the_run(self):
        assert _exported(REAL)["assessment_id"] == "asmt_9EnmJ2itb8QqxSjfusfhE", (
            "a baseline file that cannot say which run it came from cannot be audited")


class TestTheExportGatesIdenticallyToItsSource:
    """`ci --file export.json` and `ci --assessment <that run>` must not disagree."""

    def test_it_is_gateable_at_all(self):
        r = CI.gate(_exported(REAL), None, fail_on_severity="high")
        assert not r.get("unreadable"), r["reasons"]
        assert r["exit_code"] == 2      # 33 findings, 22 of them at or above high

    def test_the_verdict_matches_the_raw_assessment(self):
        raw = CI.gate(REAL, None, fail_on_severity="high")
        exp = CI.gate(_exported(REAL), None, fail_on_severity="high")
        assert exp["exit_code"] == raw["exit_code"]
        assert exp["finding_count"] == raw["finding_count"] == 33
        assert exp["reasons"] == raw["reasons"]

    @pytest.mark.parametrize("sev", ["critical", "high", "medium", "low"])
    def test_the_threshold_behaves_the_same_either_way(self, sev):
        raw = CI.gate(REAL, None, fail_on_severity=sev)
        exp = CI.gate(_exported(REAL), None, fail_on_severity=sev)
        assert len(exp["threshold_breaches"]) == len(raw["threshold_breaches"])


class TestTheRoundTrip:
    """Export a completed run, feed it back as both --file and --baseline: nothing is new."""

    def test_zero_new_findings_against_its_own_export(self):
        doc = _exported(REAL)
        r = CI.gate(doc, doc, fail_on_severity="high")
        assert r["diff"]["new_findings"] == [], (
            "a run diffed against its own export invented 33 findings before this fix")
        assert not [x for x in r["reasons"] if x.startswith("new finding")]

    def test_nothing_resolved_or_regressed_either(self):
        doc = _exported(REAL)
        d = CI.compare(doc, doc)
        assert d["resolved"] == [] and d["regressions"] == [] and d["not_retested"] == []

    def test_the_raw_run_against_its_own_export_is_clean_too(self):
        """The real invocation: gate the live assessment, baseline it with yesterday's export."""
        d = CI.compare(_exported(REAL), REAL)
        assert (d["new_findings"], d["resolved"], d["not_retested"], d["regressions"]) == ([], [], [], [])

    def test_a_real_regression_still_surfaces_through_an_export(self):
        """Round-tripping must not flatten the diff into always-empty."""
        d = CI.compare(_exported(R.BASELINE), _exported(REAL))
        assert len(d["new_findings"]) == 33
        assert [f["control_id"] for f in d["not_retested"]] == ["agentic_data_exfil"]

    def test_exporting_an_export_is_idempotent(self):
        once = E.to_json(REAL)
        twice = E.to_json(json.loads(once))
        assert json.loads(once) == json.loads(twice)


class TestOlderExportFilesOnDisk:
    """Files written by the CLI before this fix — already sitting in people's pipelines."""

    @staticmethod
    def _legacy(a):
        doc = _exported(a)
        return {k: doc[k] for k in ("tool", "status", "score", "severity",
                                    "finding_count", "findings")}

    def test_the_legacy_shape_is_what_it_used_to_be(self):
        legacy = self._legacy(REAL)
        assert "category_summary" not in legacy and legacy["finding_count"] == 33

    def test_as_a_baseline_it_no_longer_invents_findings(self):
        d = CI.compare(self._legacy(REAL), REAL)
        assert d["new_findings"] == [], (
            "33 phantom new findings: the baseline parsed, yielded nothing, and every current "
            "finding looked new")

    def test_its_findings_are_read_back_faithfully(self):
        legacy = self._legacy(REAL)
        assert {f["control_id"] for f in E.iter_findings(legacy)} == \
               {f["control_id"] for f in E.iter_findings(REAL)}

    def test_the_fallback_never_shadows_a_real_control_table(self):
        """A payload with both keys is read from `category_summary`, the authoritative one."""
        doc = _exported(REAL)
        doc["findings"] = []                      # contradict the control table
        assert len(E.iter_findings(doc)) == 33


class TestALossyCurrentRunIsStillRefused:
    """The export must not become a back door into the false green next door."""

    def test_a_findings_only_payload_cannot_be_gated_as_the_current_run(self):
        legacy = TestOlderExportFilesOnDisk._legacy(REAL)
        r = CI.gate(legacy, None, fail_on_severity="high")
        assert r["exit_code"] == 1 and r["unreadable"] is True, (
            "accepting a failures-only payload as the current run means every control absent "
            "from the list reads as passing — that is the dropped-control false green")

    def test_the_refusal_names_the_field(self):
        legacy = TestOlderExportFilesOnDisk._legacy(REAL)
        assert "category_summary" in CI.gate(legacy, None)["reasons"][0]


class TestTheOtherFormatsAreUnchanged:
    """The fix is additive: CSV row counts and SARIF result counts are somebody's metric."""

    def test_csv_still_has_one_row_per_failed_control(self):
        rows = [l for l in E.to_csv(REAL).splitlines() if l.strip()]
        assert len(rows) == 34                      # header + 33 findings

    def test_sarif_still_has_one_result_per_finding(self):
        doc = json.loads(E.to_sarif(REAL))
        assert len(doc["runs"][0]["results"]) == 33

    def test_markdown_still_reports_the_same_count(self):
        assert "- **Findings:** 33" in E.to_markdown(REAL)
