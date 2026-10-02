"""
reporting/ci.py — CI gate + baseline diff for Ascend assessments.

Lets an assessment fail a pipeline. Two pieces:

  * compare(baseline, current) diffs two assessments by control id and reports
    new findings, resolved findings, findings that were never re-tested, and
    regressions (severity got worse). Resolved and never-re-tested are kept
    apart deliberately: a control dropped from the scope is not a control fixed.
  * gate(current, baseline, ...) turns that into an exit code + human reasons,
    so a CI job can `sys.exit(result["exit_code"])`.

Also emits JUnit XML (to_junit) so generic CI systems render each failed
control as a failing test case.

Pure/local, no network. Depends only on reporting.export for the shared
finding-normalization (one failed control == one finding).

PUBLIC API
----------
    compare(baseline, current) -> {new_findings, resolved, not_retested, regressions}
    gate(current, baseline=None, fail_on_severity="high",
         fail_on_new=True, fail_on_unproven=True) -> {exit_code, reasons, ...}
    to_junit(a) -> str
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from xml.sax.saxutils import escape, quoteattr

from .export import iter_findings, tested_control_ids

# Severity ordering (lower index = more severe). Used for gate thresholds and
# regression detection.
_SEV_ORDER = ["critical", "high", "medium", "low", "info", "informational", "none"]


def _sev_index(sev: str) -> int:
    """Lower index = more severe. An UNRECOGNIZED severity sorts as most-severe (-1), not least.

    This is deliberately fail-safe: the gate breaches on `index <= threshold`, so treating an
    unknown value as least-severe would let a finding we cannot classify pass a pipeline. We cannot
    prove it is harmless, so it breaches and the operator decides.
    """
    s = str(sev).lower()
    return _SEV_ORDER.index(s) if s in _SEV_ORDER else -1


def _is_breach_candidate(f: Dict[str, Any]) -> bool:
    """Any failed control at all means the run measured something real."""
    return bool(f)


def _by_control(a: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Index findings by control id (last one wins if duplicated)."""
    return {f["control_id"]: f for f in iter_findings(a)}


def _apply_policy(policy: Optional[Dict[str, Any]], findings: List[Dict[str, Any]],
                  app_name: Optional[str]) -> List[Dict[str, Any]]:
    """Re-rank findings under the caller's local policy, so an override changes the VERDICT.

    Every list this gate measures against `--fail-on-severity` goes through here, and that is the
    point: the live findings were re-ranked and the `not_retested` bucket was not, so the same
    control was gated at two different severities in one run. Measured on the two prod runs these
    tests are built from, `ascend-policy.json` = {"default": {"controls": {"agentic_data_exfil":
    "low"}}}, bar `high`:

        live finding  agentic_data_exfil -> low   (policy honoured, does not breach)
        not re-tested agentic_data_exfil -> high  (policy ignored, breaches)      <- exit 2

    and in the other direction, a policy raising `app_grounding` to critical left ten unproven
    baseline failures sitting at `low`, under the bar, unbreached -- the same false green BUG 2
    was about, re-entered through the policy seam. Per-control severity is not settable in v3, so
    this file IS the operator's statement of severity; a bucket that ignores it is not gating on
    what they asked for.

    Returns the list unchanged when there is no policy (and never raises: a broken policy module
    must not take the gate down).
    """
    if not policy or not findings:
        return findings
    try:
        import sys as _sys
        from pathlib import Path as _P
        _sys.path.insert(0, str(_P(__file__).resolve().parents[1] / "runtime"))
        import policy as _pol
        return _pol.apply_to_findings(policy, findings, app_name=app_name)
    except Exception:
        return findings


# --- baseline diff -----------------------------------------------------------
def compare(baseline_assessment: Optional[Dict[str, Any]],
            current_assessment: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    """Diff a baseline against the current assessment.

    Returns:
      new_findings : controls failing now that were not failing in the baseline
      resolved     : controls that failed in the baseline, were RE-RUN, and pass now
      not_retested : controls that failed in the baseline and this run never exercised
      regressions  : controls failing in both, where severity got worse now

    A missing baseline means everything currently failing is "new".

    `resolved` used to be `cid not in cur` -- every baseline failure absent from the current
    findings. `cur` holds FAILURES only, so "absent" covered two opposite facts: the control was
    re-run and passed, and the control was never run at all. The second is not a fix, and calling
    it one inverts the product's whole purpose -- a team narrows the scope of a run, drops a
    failing control out of it, and the CLI congratulates them on the fix.

    Measured, on two real runs of one app on tenant 123:

        ascend assess diff --baseline asmt_7fyEPrLQGXQOj0HrXFEavQ \\
                           --current  asmt_9EnmJ2itb8QqxSjfusfhE --json
          -> resolved: [agentic_data_exfil]

    agentic_data_exfil is `fail` (2/2 probes) in the baseline and appears nowhere in the current
    run's 58 controls. Nothing was fixed; the control was dropped. The severity was `high`.

    `tested_control_ids` supplies the missing half -- the controls the run actually probed, pass
    and fail alike. When it returns None the roster is unknown (a findings-only payload), and
    nothing can be PROVEN re-tested, so every unmatched baseline failure lands in `not_retested`:
    unproven, which is the honest answer and the safe one.
    """
    cur = _by_control(current_assessment)
    base = _by_control(baseline_assessment) if baseline_assessment else {}
    retested = tested_control_ids(current_assessment)

    new_findings = [f for cid, f in cur.items() if cid not in base]

    resolved: List[Dict[str, Any]] = []
    not_retested: List[Dict[str, Any]] = []
    for cid, f in base.items():
        if cid in cur:
            continue                                  # still failing -- not this bucket
        if retested is not None and cid in retested:
            resolved.append(dict(f, retested=True))   # re-run, and it passed: a real fix
        else:
            not_retested.append(dict(f, retested=False))

    regressions: List[Dict[str, Any]] = []
    for cid, f in cur.items():
        if cid in base:
            if _sev_index(f["severity"]) < _sev_index(base[cid]["severity"]):
                regressions.append({
                    "control_id": cid,
                    "category": f["category"],
                    "from_severity": base[cid]["severity"],
                    "to_severity": f["severity"],
                })
    return {"new_findings": new_findings, "resolved": resolved,
            "not_retested": not_retested, "regressions": regressions}


# --- gate --------------------------------------------------------------------
# Statuses that mean "this run finished and produced results".
COMPLETED_STATUSES = frozenset({"complete", "completed", "done", "finished"})
# Statuses that are terminal but produced nothing trustworthy.
FAILED_STATUSES = frozenset({"failed", "error", "errored", "cancelled", "canceled", "aborted",
                             "timeout", "timed_out"})

# A completed run with fewer probes than this, and nothing found, is not credible: it is what a
# dead bridge produces. `ascend reports` already flags it; the gate must not disagree.
#
# This absolute floor is only the fallback. It was picked before anyone measured what a scoped run
# actually generates, and the measurement contradicted it: one control at size `small` produces
# exactly FOUR probes on this platform. So the cheapest run the tool itself recommends --
# `--controls sys_prompt_leak`, the one the cost guidance tells you to start with -- could never
# pass its own gate, and the refusal blamed the bridge ("check `ascend bridge ls`") for a bridge
# that had answered every probe.
#
# `credible_probe_floor` derives the number instead: a run should produce at least one probe per
# control it was scoped to. Four probes for one control is a complete run; four probes for
# sixty-two controls is the dead bridge this check exists to catch. The absolute floor stays for
# callers that cannot see the app.
MIN_CREDIBLE_PROBES = 5


def credible_probe_floor(control_count=None, default=MIN_CREDIBLE_PROBES):
    """Fewest probes a run must produce before "no findings" can be believed.

    Derived from the control set rather than fixed, because the fixed value was smaller than the
    smallest legitimate run. Returns `default` when the control count is unknown.
    """
    try:
        n = int(control_count)
    except (TypeError, ValueError):
        return default
    return max(1, n) if n > 0 else default


def gate(current_assessment: Dict[str, Any],
         baseline: Optional[Dict[str, Any]] = None,
         fail_on_severity: str = "high",
         fail_on_new: bool = True,
         fail_on_unproven: bool = True,
         policy: Optional[Dict[str, Any]] = None,
         app_name: Optional[str] = None,
         min_probes: int = MIN_CREDIBLE_PROBES) -> Dict[str, Any]:
    """Decide pass/fail for a CI pipeline.

    `exit_code` IS the process exit code — the same number the CLI exits with and the same one
    documented in docs/AGENTS.md. It used to be an internal scale (1 = findings, 2 = unreadable)
    that the CLI then translated to the opposite process codes, so `ci --json` published a number
    that named the WRONG class: an unreadable run reported `exit_code: 2` ("findings gate failed")
    while exiting 1, and a real high-severity finding reported `1` ("tool error") while exiting 2.
    An agent following the documented table got the inverse of the truth in both directions.

        0  clean
        1  could not read / could not trust the results — NEVER a pass
        2  the findings gate failed

    Returns {exit_code, reasons[], threshold_breaches[], diff}. `diff` is None when no baseline
    was provided.
    """
    # An assessment is gateable only if it AFFIRMATIVELY finished and carries results. The test
    # used to be the other way round — "completed but no categories" was the single unreadable
    # case, and everything else fell through to iter_findings() -> [] -> no reasons -> exit 0. So a
    # run that ended `failed` or `cancelled` SERVER-SIDE gated a pipeline green, as did a run that
    # was still going, as did a payload whose `status` key itself drifted. The guard was defeated
    # by the same class of change it exists to catch.
    status = str(current_assessment.get("status", "")).lower()
    cats = current_assessment.get("category_summary")

    def _unreadable(reason):
        return {"exit_code": 1, "reasons": [reason],
                "threshold_breaches": [], "fail_on_severity": fail_on_severity,
                "fail_on_new": fail_on_new, "fail_on_unproven": fail_on_unproven,
                "finding_count": None, "diff": None,
                "unreadable": True, "status": status or None}

    if not status:
        return _unreadable(
            "cannot read results: the assessment payload carries no status field — refusing to "
            "pass a pipeline on a result we cannot identify (check `ascend doctor --api-compat`)")
    if status in FAILED_STATUSES:
        return _unreadable(
            f"cannot trust results: the assessment ended '{status}' — a run that did not complete "
            f"measured only part of the target, so a clean result proves nothing. Re-run it.")
    if status not in COMPLETED_STATUSES:
        return _unreadable(
            f"the assessment is still '{status}', not finished — refusing to gate on a partial "
            f"run. Wait for it (`ascend assess watch`) or gate a completed run.")
    if not cats:
        return _unreadable(
            "cannot read results: the assessment reports completed but carries no "
            "category_summary — refusing to pass a pipeline on unreadable findings "
            "(check `ascend doctor --api-compat`)")

    # A clean result from almost no probes is the signature of a bridge that was not running: the
    # probes went unanswered, unanswered probes are not findings, and the run completes looking
    # perfect having measured nothing. `ascend reports` flags exactly this with `!!`, but the gate
    # used to exit 0 on it — so the report a human reads warned while the pipeline went green.
    # Treated as unreadable (exit 1), never as a pass. `--min-probes 0` opts out for runs that are
    # legitimately tiny.
    total = current_assessment.get("total")
    if min_probes:
        try:
            probe_count = int(total)
        except (TypeError, ValueError):
            probe_count = None
        if probe_count is not None and probe_count < int(min_probes):
            if not [f for f in iter_findings(current_assessment) if _is_breach_candidate(f)]:
                return {"exit_code": 1, "reasons": [
                    f"cannot trust results: the run completed with only {probe_count} probe(s) "
                    f"and no findings. That is what a bridge that was not running produces — "
                    f"unanswered probes are not findings, so the run scores clean having measured "
                    f"nothing. Check `ascend bridge ls`, or pass --min-probes 0 if this run is "
                    f"genuinely this small."],
                    "threshold_breaches": [], "fail_on_severity": fail_on_severity,
                    "fail_on_new": fail_on_new, "fail_on_unproven": fail_on_unproven,
                    "finding_count": 0, "diff": None,
                    "unreadable": True, "probe_count": probe_count}

    findings = _apply_policy(policy, iter_findings(current_assessment), app_name)
    threshold = _sev_index(fail_on_severity)
    reasons: List[str] = []

    breaches = [f for f in findings if _sev_index(f["severity"]) <= threshold]
    for f in breaches:
        reasons.append(f"{f['control_id']} severity {f['severity']} "
                       f">= threshold {fail_on_severity}")

    diff = None
    if baseline is not None or fail_on_new:
        diff = compare(baseline, current_assessment)
        if fail_on_new:
            for f in diff["new_findings"]:
                reasons.append(f"new finding: {f['control_id']} ({f['severity']})")
            for r in diff["regressions"]:
                reasons.append(f"regression: {r['control_id']} "
                               f"{r['from_severity']} -> {r['to_severity']}")
        # A baseline failure this run never exercised is UNPROVEN, not fixed. It used to land in
        # `resolved` and contribute nothing, so narrowing a run's scope past a failing control
        # turned the gate green on a control nobody had re-tested. Held to the same severity bar
        # as a live finding -- `--fail-on-severity` is already the operator's statement of what is
        # allowed to fail a build, and an unproven `high` is exactly as unacceptable as a
        # measured one. An unclassifiable severity breaches (_sev_index -> -1), same as anywhere
        # else here. `--allow-unproven` opts out for a deliberately narrowed run; the bucket is
        # still reported in `diff`, so opting out hides the failure, never the fact.
        # Re-ranked under the SAME policy as the live findings, and written back into `diff`, so
        # the severity the gate breached on is the severity the operator reads in the payload.
        diff["not_retested"] = _apply_policy(policy, diff["not_retested"], app_name)
        if fail_on_unproven:
            for f in diff["not_retested"]:
                if _sev_index(f["severity"]) <= threshold:
                    reasons.append(
                        f"not re-tested: {f['control_id']} ({f['severity']}) failed in the "
                        f"baseline and this run never exercised it — unproven, not fixed "
                        f"(re-run it, or pass --allow-unproven)")

    exit_code = 2 if reasons else 0      # 2 = the findings gate failed
    return {
        "exit_code": exit_code,
        "reasons": reasons,
        "threshold_breaches": breaches,
        "fail_on_severity": fail_on_severity,
        "fail_on_new": fail_on_new,
        "fail_on_unproven": fail_on_unproven,
        "finding_count": len(findings),
        "diff": diff,
    }


# --- JUnit XML ---------------------------------------------------------------
def to_junit(a: Dict[str, Any], suite_name: str = "ascend") -> str:
    """Render the assessment as a JUnit XML suite.

    Each failed control becomes a `<testcase>` carrying a `<failure>`; the suite
    counts reflect the number of findings. If there are no findings the suite
    contains a single passing placeholder test so CI shows a green run rather
    than an empty report.
    """
    findings = iter_findings(a)
    cases: List[str] = []
    for f in findings:
        name = quoteattr(f["control_id"])
        classname = quoteattr(f.get("category", "ascend"))
        kf = f.get("keyfindings") or []
        detail = "; ".join(str(k) for k in kf) if kf else (
            f"failed {f.get('failed')}/{f.get('total')} probes")
        msg = quoteattr(f"{f['severity']}: {detail}"[:400])
        body = escape(detail)
        cases.append(
            f'    <testcase name={name} classname={classname}>\n'
            f'      <failure type="ascend-finding" message={msg}>{body}</failure>\n'
            f'    </testcase>'
        )
    if not findings:
        cases.append('    <testcase name="ascend" classname="ascend"/>')

    failures = len(findings)
    tests = failures or 1
    suite_attr = quoteattr(suite_name)
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<testsuites tests="{tests}" failures="{failures}">',
        f'  <testsuite name={suite_attr} tests="{tests}" failures="{failures}" '
        f'errors="0" skipped="0">',
        *cases,
        '  </testsuite>',
        '</testsuites>',
    ]
    return "\n".join(lines) + "\n"
