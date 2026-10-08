"""
test_ci_resolved_vs_not_retested.py — a control that was never re-run is not a control that was
fixed.

THE FALSE GREEN
---------------
`ci.compare` built its `resolved` list as `[f for cid, f in base.items() if cid not in cur]`, and
`cur` is `_by_control(current)` — which comes from `iter_findings`, which is FAILURES ONLY, by
design. So "not in cur" spanned two opposite facts:

    the control was re-probed and it passed        -> fixed
    the control was never probed in this run       -> nothing was measured

and the CLI reported both as RESOLVED. Measured on tenant 123, two real runs of one app:

    ascend assess diff --baseline asmt_7fyEPrLQGXQOj0HrXFEavQ \\
                       --current  asmt_9EnmJ2itb8QqxSjfusfhE --json
      -> {"resolved": [{"control_id": "agentic_data_exfil", "severity": "high", ...}]}

agentic_data_exfil is `fail`, 2/2 probes, high in the baseline. The current run has 58 controls
and agentic_data_exfil is not one of them — the scope was narrowed and the failing control fell
out of it. Nothing about it was re-tested, and the gate exited on the findings it *did* have
without a word about the one it had dropped.

Telling a security team a control is fixed when it was never re-run is the exact false comfort
this product exists to prevent, and it is worse than a missed finding: a missed finding leaves
them looking, this one tells them to stop.

WHAT THE FIX TURNS ON
---------------------
`export.tested_control_ids` — the roster of controls the run actually PROBED, passing ones
included. `resolved` now requires membership in it; everything else that stopped failing lands in
`not_retested`, and the gate breaches on it at the same severity bar as a live finding.

The three fixtures in tests/real_assessments.py are real runs that pin both answers on ONE
control id: agentic_data_exfil fails in the baseline, passes 0/1 in asmt_isKT3xKIjaeKgBAbwFKXf
(re-run: resolved) and is absent from asmt_9EnmJ2itb8QqxSjfusfhE (dropped: not re-tested).
"""
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
for p in ("shells/cli", "runtime", "control", "tests", "."):
    sys.path.insert(0, str(REPO / p))

import real_assessments as R                              # noqa: E402
from reporting import ci as CI                            # noqa: E402
from reporting import export as E                         # noqa: E402

CONTROL = "agentic_data_exfil"


def _assessment(rows, *, status="complete", total=30, severity="high"):
    """A single-category run from (control_id, status, severity, failed, total) rows."""
    return R._run("asmt_synthetic", status=status, total=total, failed=None,
                  severity=severity, categories={"c": rows})


class TestTheMeasuredCase:
    """Three real runs, one control, both verdicts."""

    def test_a_dropped_control_is_not_reported_resolved(self):
        diff = CI.compare(R.BASELINE, R.DROPPED)
        assert [f["control_id"] for f in diff["resolved"]] == [], (
            "agentic_data_exfil is absent from all 58 controls of asmt_9EnmJ2itb8QqxSjfusfhE — "
            "it was never re-probed, so nothing about it was fixed")

    def test_a_dropped_control_is_reported_as_not_re_tested(self):
        diff = CI.compare(R.BASELINE, R.DROPPED)
        assert [f["control_id"] for f in diff["not_retested"]] == [CONTROL]
        assert diff["not_retested"][0]["severity"] == "high"
        assert diff["not_retested"][0]["retested"] is False

    def test_a_re_run_control_that_passes_is_still_resolved(self):
        """The fix must not turn every fix into a doubt."""
        diff = CI.compare(R.BASELINE, R.RETESTED)
        assert [f["control_id"] for f in diff["resolved"]] == [CONTROL]
        assert diff["resolved"][0]["retested"] is True
        assert diff["not_retested"] == []

    def test_the_two_verdicts_come_from_the_same_baseline_and_control(self):
        """Neither answer is an artifact of a different input."""
        base_fail = {f["control_id"] for f in E.iter_findings(R.BASELINE)}
        assert base_fail == {CONTROL}
        assert CONTROL in (E.tested_control_ids(R.RETESTED) or set())
        assert CONTROL not in (E.tested_control_ids(R.DROPPED) or set())
        assert len(E.tested_control_ids(R.DROPPED)) == 58

    def test_the_gate_breaches_on_the_dropped_control(self):
        r = CI.gate(R.DROPPED, R.BASELINE, fail_on_severity="high")
        assert r["exit_code"] == 2
        unproven = [x for x in r["reasons"] if x.startswith("not re-tested")]
        assert len(unproven) == 1 and CONTROL in unproven[0]

    def test_the_gate_stays_clean_when_the_control_was_re_run_and_passed(self):
        # min_probes=0: that run is a single probe, and the dead-bridge floor is a separate guard.
        r = CI.gate(R.RETESTED, R.BASELINE, fail_on_severity="high", min_probes=0)
        assert r["exit_code"] == 0, r["reasons"]
        assert r["reasons"] == []


class TestTheGateCannotPassOnAnUnprovenControl:
    """The isolated failure: nothing new, nothing regressed, and one dropped high finding."""

    BASE = _assessment([("dropped_one", "fail", "high", 3, 3),
                        ("kept_one", "pass", "high", 0, 4)])
    CUR = _assessment([("kept_one", "pass", "high", 0, 4)])

    def test_without_the_distinction_this_run_is_entirely_clean(self):
        """Proof the gate has nothing else to fail on — the unproven control is the only signal."""
        assert E.iter_findings(self.CUR) == []
        diff = CI.compare(self.BASE, self.CUR)
        assert diff["new_findings"] == [] and diff["regressions"] == []

    def test_it_exits_two(self):
        r = CI.gate(self.CUR, self.BASE, fail_on_severity="high")
        assert r["exit_code"] == 2, (
            "a baseline high finding that this run never exercised must not gate a pipeline green")

    def test_the_reason_says_unproven_not_fixed(self):
        r = CI.gate(self.CUR, self.BASE, fail_on_severity="high")
        reason = " ".join(r["reasons"])
        assert "dropped_one" in reason
        assert "unproven" in reason and "not fixed" in reason
        assert "--allow-unproven" in reason, "name the opt-out in the refusal that provokes it"


class TestTheConfigMatrix:
    """Each flag is correct alone; the pairs are where a gate silently stops gating."""

    BASE = _assessment([("dropped_one", "fail", "high", 3, 3)])
    CUR = _assessment([("other", "pass", "high", 0, 4)])

    def test_allow_unproven_turns_it_off(self):
        r = CI.gate(self.CUR, self.BASE, fail_on_severity="high", fail_on_unproven=False)
        assert r["exit_code"] == 0

    def test_allow_unproven_still_reports_the_bucket(self):
        """Opting out hides the failure, never the fact — the diff still names the control."""
        r = CI.gate(self.CUR, self.BASE, fail_on_severity="high", fail_on_unproven=False)
        assert [f["control_id"] for f in r["diff"]["not_retested"]] == ["dropped_one"]

    def test_allow_new_does_not_also_disable_it(self):
        """`--allow-new` is about findings that arrived, not about findings that vanished.

        The two live in the same `if baseline is not None or fail_on_new:` block, which is exactly
        where one flag quietly swallows another.
        """
        r = CI.gate(self.CUR, self.BASE, fail_on_severity="high",
                    fail_on_new=False, fail_on_unproven=True)
        assert r["exit_code"] == 2
        assert any(x.startswith("not re-tested") for x in r["reasons"])

    def test_it_holds_to_the_configured_severity_bar(self):
        low = _assessment([("dropped_low", "fail", "low", 1, 3)])
        r = CI.gate(self.CUR, low, fail_on_severity="high", fail_on_unproven=True)
        assert r["exit_code"] == 0, "an unproven `low` at a `high` bar is not a build failure"
        assert [f["control_id"] for f in r["diff"]["not_retested"]] == ["dropped_low"], (
            "below the bar is not below notice — it still has to be reported")

    def test_a_lower_bar_catches_it(self):
        low = _assessment([("dropped_low", "fail", "low", 1, 3)])
        r = CI.gate(self.CUR, low, fail_on_severity="low", fail_on_unproven=True)
        assert r["exit_code"] == 2

    def test_an_unclassifiable_severity_breaches(self):
        """Same fail-safe as `_sev_index` everywhere else: what we cannot rank, we do not excuse.

        `severity=None` on the run as well as the control: `iter_findings` falls back to the
        assessment severity first, so a control-only omission still ranks.
        """
        unknown = _assessment([("dropped_unknown", "fail", None, 1, 3)], severity=None)
        assert E.iter_findings(unknown)[0]["severity"] == "unknown"
        r = CI.gate(self.CUR, unknown, fail_on_severity="critical", fail_on_unproven=True)
        assert r["exit_code"] == 2

    def test_the_verdict_payload_names_the_setting(self):
        r = CI.gate(self.CUR, self.BASE, fail_on_severity="high", fail_on_unproven=False)
        assert r["fail_on_unproven"] is False, (
            "an agent reading --json cannot tell a clean run from a muted one otherwise")

    @pytest.mark.parametrize("kw", [{}, {"fail_on_new": False}, {"fail_on_unproven": True}])
    def test_the_default_is_to_refuse(self, kw):
        assert CI.gate(self.CUR, self.BASE, fail_on_severity="high", **kw)["exit_code"] == 2


class TestAnUnknownRosterIsNeverProof:
    """`tested_control_ids` returns None when the payload lists failures only."""

    def test_a_findings_only_current_run_proves_nothing_resolved(self):
        findings_only = {"status": "complete", "findings": [
            {"control_id": "other", "category": "c", "severity": "high",
             "status": "fail", "failed": 1, "total": 2, "keyfindings": []}]}
        assert E.tested_control_ids(findings_only) is None
        diff = CI.compare(_assessment([("dropped_one", "fail", "high", 3, 3)]), findings_only)
        assert diff["resolved"] == []
        assert [f["control_id"] for f in diff["not_retested"]] == ["dropped_one"]

    def test_an_empty_roster_is_not_none(self):
        """A real run that probed nothing is still a known roster — an empty one."""
        assert E.tested_control_ids({"category_summary": [{"id": "c", "controls": []}]}) == set()

    def test_a_listed_but_unprobed_control_does_not_count_as_re_tested(self):
        """total: 0 means enumerated, not exercised. No probes, no evidence, no fix."""
        base = _assessment([("x", "fail", "high", 2, 2)])
        cur = _assessment([("x", "pass", "high", 0, 0)])
        diff = CI.compare(base, cur)
        assert diff["resolved"] == []
        assert [f["control_id"] for f in diff["not_retested"]] == ["x"]


class TestTheCommandSurface:
    """A distinction the operator cannot see is not a distinction."""

    def test_ci_exposes_an_opt_out(self):
        import ascend
        opts = {a for act in ascend.build_parser()._actions for a in getattr(act, "option_strings", [])}
        # The root parser's actions do not include subcommands' flags; walk to the `ci` parser.
        sub = [a for a in ascend.build_parser()._actions if hasattr(a, "choices") and a.choices]
        ci_parser = None
        for a in sub:
            if isinstance(a.choices, dict) and "ci" in a.choices:
                ci_parser = a.choices["ci"]
        assert ci_parser is not None, "the `ci` subcommand vanished"
        flags = {o for act in ci_parser._actions for o in act.option_strings}
        assert "--allow-unproven" in flags, f"no opt-out on `ascend ci`: {sorted(flags)}"
        assert "--allow-new" in flags and "--allow-unproven" in flags, (
            "the two must be separate flags — one means 'findings that arrived', the other "
            "'findings that vanished'")
        assert opts, "sanity: the root parser has flags"

    def test_ci_wires_the_flag_through_to_the_gate(self):
        src = (REPO / "shells" / "cli" / "ascend.py").read_text()
        assert "fail_on_unproven=(not args.allow_unproven)" in src, (
            "a flag argparse accepts and the gate never sees is worse than no flag")

    def test_assess_diff_prints_the_bucket_separately(self):
        src = (REPO / "shells" / "cli" / "ascend.py").read_text()
        assert 'diff["not_retested"]' in src
        assert "NOT RE-TESTED" in src, (
            "folded into RESOLVED, the human output says 'fixed' about a control nobody re-ran")


class TestTheLocalPolicyRanksTheUnprovenBucketToo:
    """The bucket the gate now breaches on has to obey the same severity policy as the live ones.

    `gate()` re-ranked `iter_findings(current)` under `ascend-policy.json` and then measured the
    NEW `not_retested` bucket against the same `--fail-on-severity` bar using the RAW API
    severity. One run, one control id, two different severities — and per-control severity is not
    settable anywhere in v3, so that file is the only place an operator can say what a control is
    worth. Measured on the same two prod runs as the rest of this file, before the fix:

        policy {"controls": {"agentic_data_exfil": "low"}}, bar high
          live path      -> low, under the bar          (policy honoured)
          unproven path  -> high, BREACHES              (policy ignored)    false red

        policy {"categories": {"app_grounding": "critical"}}, bar critical
          10 unproven app_grounding failures stay `low`, nothing breaches, exit 0   false green

    The second is BUG 2 all over again through a different seam: a control the operator called
    critical, never re-tested, and the pipeline goes green on it.
    """

    DOWNGRADE = {"default": {"controls": {CONTROL: "low"}}}
    UPGRADE = {"default": {"categories": {"app_grounding": "critical"}}}

    def _unproven(self, r):
        return [x for x in r["reasons"] if x.startswith("not re-tested")]

    def test_a_policy_downgrade_reaches_the_unproven_bucket(self):
        """agentic_data_exfil is `high` from the API and `low` under this policy. It is the SAME
        control the live path would rank `low`, so ranking it `high` here fails a build on a
        severity the operator explicitly overruled."""
        r = CI.gate(R.DROPPED, R.BASELINE, fail_on_severity="high", fail_on_new=False,
                    policy=self.DOWNGRADE)
        assert self._unproven(r) == [], (
            "the policy says this control is `low`; the unproven bucket gated it at `high`")
        assert [f["severity"] for f in r["diff"]["not_retested"]] == ["low"]
        assert r["diff"]["not_retested"][0]["severity_source"] == "local-policy", (
            "the payload must show WHICH severity gated, or the reason list is unexplainable")

    def test_a_policy_upgrade_reaches_it_too_and_flips_the_verdict(self):
        """The false green. RETESTED probes one control, so all 33 of DROPPED's failures are
        unproven; at a `critical` bar none of them breach on API severity, and the ten
        app_grounding ones are `critical` under this policy."""
        clean = CI.gate(R.RETESTED, R.DROPPED, fail_on_severity="critical", fail_on_new=False,
                        min_probes=0)
        assert clean["exit_code"] == 0, "sanity: nothing is critical at API severity"

        r = CI.gate(R.RETESTED, R.DROPPED, fail_on_severity="critical", fail_on_new=False,
                    policy=self.UPGRADE, min_probes=0)
        assert r["exit_code"] == 2, (
            "ten controls the policy calls critical were never re-tested and the gate went green")
        breached = {x.split(":")[1].split("(")[0].strip() for x in self._unproven(r)}
        assert "world_knowledge" in breached and "math" in breached
        assert len(breached) == 10, f"every app_grounding control, got {sorted(breached)}"

    def test_the_reason_quotes_the_severity_that_gated(self):
        r = CI.gate(R.RETESTED, R.DROPPED, fail_on_severity="critical", fail_on_new=False,
                    policy=self.UPGRADE, min_probes=0)
        assert all("(critical)" in x for x in self._unproven(r)), (
            "a reason naming the API severity cannot be reconciled with the bar it crossed")

    def test_no_policy_leaves_the_api_severity_exactly_as_it_was(self):
        """The no-policy path is every pipeline that has no policy file; it must not move."""
        r = CI.gate(R.DROPPED, R.BASELINE, fail_on_severity="high")
        nr = r["diff"]["not_retested"]
        assert [(f["control_id"], f["severity"]) for f in nr] == [(CONTROL, "high")]
        assert "severity_source" not in nr[0]
        assert len(self._unproven(r)) == 1

    def test_a_malformed_policy_cannot_take_the_gate_down(self):
        """`policy.severity_for` raises AttributeError on `{"apps": "x"}` (a string where the
        block map belongs) — verified directly below, so this is the real throwing path and not a
        hypothetical one. The gate still has to produce a verdict: it falls back to the API
        severity, never to no verdict at all. It is the same swallow the live-findings path has
        always had; both go through one helper so they cannot drift apart."""
        import policy as _P
        bad = {"apps": "x"}
        with pytest.raises(AttributeError):
            _P.apply_to_findings(bad, E.iter_findings(R.BASELINE))

        r = CI.gate(R.DROPPED, R.BASELINE, fail_on_severity="high", fail_on_new=False, policy=bad)
        assert r["exit_code"] == 2
        assert len(self._unproven(r)) == 1
        assert r["diff"]["not_retested"][0]["severity"] == "high"


class TestTheFlagChangesTheVerdictThroughTheRealCLI:
    """Not a grep over ascend.py: the process, the parser, the gate and the exit code.

    `--file`/`--baseline` need no credential, so this runs the shipped entry point offline. The
    two payloads are the real prod runs from tests/real_assessments.py, written out through the
    real exporter — which also means this test fails if `export --format json` stops being a
    gateable document.
    """

    @staticmethod
    def _run(tmp_path, *args):
        import json as _json
        import os
        import subprocess
        env = dict(os.environ)
        for k in ("STRAIKER_PAT", "STRAIKER_TOKEN", "ASCEND_POLICY"):
            env.pop(k, None)
        env["ASCEND_HOME"] = str(tmp_path / "home")
        env["NO_COLOR"] = "1"
        p = subprocess.run([sys.executable, "-B", str(REPO / "shells" / "cli" / "ascend.py"),
                            *args], capture_output=True, text=True, timeout=120,
                           env=env, cwd=str(tmp_path))
        return p, (_json.loads(p.stdout) if p.stdout.strip().startswith("{") else None)

    @pytest.fixture
    def files(self, tmp_path):
        base = tmp_path / "baseline.json"
        cur = tmp_path / "current.json"
        base.write_text(E.to_json(R.BASELINE))
        cur.write_text(E.to_json(R.DROPPED))
        return str(base), str(cur)

    def test_the_default_breaches_and_the_process_exits_two(self, files, tmp_path):
        base, cur = files
        p, out = self._run(tmp_path, "ci", "--file", cur, "--baseline", base,
                           "--fail-on-severity", "high", "--json")
        assert p.returncode == 2, f"rc={p.returncode} stderr={p.stderr[-400:]}"
        assert out["fail_on_unproven"] is True
        unproven = [r for r in out["reasons"] if r.startswith("not re-tested")]
        assert [CONTROL in r for r in unproven] == [True]

    def test_allow_unproven_removes_that_reason_and_nothing_else(self, files, tmp_path):
        base, cur = files
        _, strict = self._run(tmp_path, "ci", "--file", cur, "--baseline", base,
                              "--fail-on-severity", "high", "--json")
        p, loose = self._run(tmp_path, "ci", "--file", cur, "--baseline", base,
                             "--fail-on-severity", "high", "--allow-unproven", "--json")
        assert loose["fail_on_unproven"] is False
        assert [r for r in loose["reasons"] if r.startswith("not re-tested")] == []
        assert len(strict["reasons"]) - len(loose["reasons"]) == 1, (
            "the opt-out must drop exactly the unproven reason, not soften the rest")
        assert [f["control_id"] for f in loose["diff"]["not_retested"]] == [CONTROL], (
            "opting out hides the failure, never the fact")
        assert p.returncode == 2      # the 33 real findings are still a red build

    def test_the_human_output_says_which_bucket(self, files, tmp_path):
        base, cur = files
        p, _ = self._run(tmp_path, "assess", "diff", "--baseline-file", base,
                         "--current-file", cur)
        assert p.returncode == 0, f"rc={p.returncode} stderr={p.stderr[-400:]}"
        assert "NOT RE-TESTED  1" in p.stdout
        assert "RESOLVED       0" in p.stdout, (
            f"a dropped control counted as fixed:\n{p.stdout}")
        assert CONTROL in p.stdout.split("NOT RE-TESTED")[1]
