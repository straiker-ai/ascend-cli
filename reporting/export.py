"""
reporting/export.py — export a completed Ascend assessment to portable formats.

Takes an assessment dict (the shape AscendAPI.get_assessment returns) and emits
JSON, CSV, SARIF 2.1.0, and Markdown. SARIF is the interesting one: it lets the
findings flow into GitHub code scanning, Azure DevOps, and any SARIF-aware SIEM.

ASSESSMENT SHAPE (only the fields we read)
------------------------------------------
    {
      "status": "completed", "score": 42, "severity": "high",
      "category_summary": [
        {"category": "prompt-injection", "failed": 3, "total": 10,
         "score": 30, "status": "fail",
         "controls": [
           {"id": "sys_prompt_leak", "status": "fail", "severity": "high",
            "failed": 2, "total": 4,
            "keyfindings": ["leaked system prompt on turn 3", ...]}
         ]}
      ]
    }

A "finding" here is one *failed* control (failed > 0 or status in a fail set).
Every module function is pure and returns a string (CSV/SARIF/Markdown) or a
dict (JSON), with no I/O.

PUBLIC API
----------
    iter_findings(a) -> list[dict]     # normalized failed-control findings
    tested_control_ids(a) -> set|None  # every control the run actually probed
    to_json(a) -> str
    to_csv(a) -> str
    to_sarif(a) -> str                 # SARIF 2.1.0, tool = "Straiker Ascend"
    to_markdown(a) -> str
"""

from __future__ import annotations

import csv
import io
import json
from typing import Any, Dict, List, Optional, Set

TOOL_NAME = "Straiker Ascend"
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

_FAIL_STATUSES = {"fail", "failed", "failing", "error"}

# Ascend severity -> SARIF result level. SARIF levels: error/warning/note/none.
_SEVERITY_TO_SARIF = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
    "informational": "note",
    "none": "none",
    # An unclassifiable severity is surfaced as `error`, not quietly softened to `warning`:
    # a finding we cannot rank must not look milder than it might be.
    "unknown": "error",
}
# Ascend severity -> SARIF security-severity (0.0-10.0), for code-scanning UIs.
_SEVERITY_SCORE = {
    "critical": "9.5", "high": "8.0", "medium": "5.0",
    "low": "3.0", "info": "1.0", "informational": "1.0", "none": "0.0",
}


def _is_failed(control: Dict[str, Any]) -> bool:
    if str(control.get("status", "")).lower() in _FAIL_STATUSES:
        return True
    failed = control.get("failed")
    return isinstance(failed, int) and failed > 0


def _was_probed(control: Dict[str, Any]) -> bool:
    """Did this control actually get adversarial prompts sent at it?

    A control listed with `total: 0` was enumerated, not exercised, and produces no evidence
    either way. Unobserved in the two runs this was verified against (every control in
    asmt_7fyEPrLQGXQOj0HrXFEavQ and asmt_9EnmJ2itb8QqxSjfusfhE carried total > 0), so it changes
    nothing measured -- but "listed" and "tested" are the distinction the whole `resolved` bucket
    turns on, so they are not collapsed here either.
    """
    total = control.get("total")
    if isinstance(total, int):
        return total > 0
    return bool(control.get("status"))      # no counts at all: trust the status it reported


def tested_control_ids(a: Dict[str, Any]) -> Optional[Set[str]]:
    """Every control the run PROBED -- passed and failed alike -- or None if unknowable.

    `iter_findings` is failure-only by design, so it cannot answer "was this control re-run?".
    Without that answer a baseline failure missing from the current run is indistinguishable from
    a baseline failure that now passes, and `ci.compare` called both of them `resolved` -- it told
    a security team a control was FIXED when it had been dropped from the scope and never re-run
    (measured: agentic_data_exfil, `fail` in asmt_7fyEPrLQGXQOj0HrXFEavQ, absent from all 58
    controls of asmt_9EnmJ2itb8QqxSjfusfhE, reported resolved=1).

    Returns None -- not an empty set -- for a payload that carries no `category_summary` (a
    findings-only export from a CLI older than this change). None means "coverage unknown", and an
    unknown roster must never be read as "nothing was tested" nor as "everything was".
    """
    cats = a.get("category_summary")
    if not cats:
        return None
    ids: Set[str] = set()
    for cat in cats:
        for ctrl in cat.get("controls") or []:
            if _was_probed(ctrl):
                ids.add(ctrl.get("id", "unknown_control"))
    return ids


def iter_findings(a: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Flatten an assessment into a list of normalized failed-control findings.

    Each finding: {control_id, category, severity, status, failed, total,
    keyfindings[]}. Categories with no failed controls contribute nothing.

    Accepts this module's own JSON export as well as a raw assessment. `to_json` now carries
    `category_summary`, so a fresh export takes the normal path; the `findings` fallback is for
    export files written before that fix -- fed to `ci --baseline` those parsed fine and yielded
    ZERO findings, so every current failure looked brand new (measured: 33 phantom new findings
    diffing asmt_9EnmJ2itb8QqxSjfusfhE against its own export).
    """
    cats = a.get("category_summary")
    if not cats and isinstance(a.get("findings"), list):
        return [dict(f) for f in a["findings"] if isinstance(f, dict) and f.get("control_id")]

    findings: List[Dict[str, Any]] = []
    for cat in cats or []:
        category = cat.get("category", cat.get("name", "uncategorized"))
        for ctrl in cat.get("controls") or []:
            if not _is_failed(ctrl):
                continue
            # Severity drives the SARIF level AND the CI --fail-on-severity gate. Defaulting a
            # missing per-control severity to "medium" would silently downgrade a critical finding
            # into one that passes the gate. Fall back to the assessment severity, and if even that
            # is absent mark it UNKNOWN so it sorts worst-first and is visibly not a real value.
            sev = ctrl.get("severity") or a.get("severity")
            findings.append({
                "control_id": ctrl.get("id", "unknown_control"),
                "category": category,
                "severity": str(sev).lower() if sev else "unknown",
                "severity_missing": not bool(ctrl.get("severity")),
                "status": ctrl.get("status", "fail"),
                "failed": ctrl.get("failed"),
                "total": ctrl.get("total"),
                "keyfindings": list(ctrl.get("keyfindings") or []),
            })
    return findings


# --- JSON --------------------------------------------------------------------
def to_json(a: Dict[str, Any]) -> str:
    """Structured export: the assessment header, normalized findings, AND the raw control table.

    The flat `findings` list is the readable part and the reason this format exists. It is not
    enough to gate on, and the export was emitting nothing else -- so the one JSON artifact a
    pipeline would naturally archive was the one input `ascend ci` could not take:

        ascend export --format json --out export.json
        ascend ci --file export.json
          -> exit 1  "reports completed but carries no category_summary"

    and as a baseline it was worse than useless, because it failed quietly: zero readable findings
    means nothing was failing before, so every current finding is new. Measured on
    asmt_9EnmJ2itb8QqxSjfusfhE against its OWN export: 33 brand-new findings, 55 gate reasons,
    exit 2. A red build, from a file that describes the exact run under test.

    The fix is on this side rather than in the gate because a failures-only document is
    IRRECOVERABLY lossy for the question the gate asks. `findings` lists what failed; it cannot
    say which controls ran and passed, so a gate taught to accept it would have to treat every
    control absent from the list as "passing" -- which is precisely the false green BUG 2 is
    about. `category_summary` carries the whole control table, so a round trip survives it.

    `total`/`failed` come along for the same reason: without `total` the dead-bridge probe floor
    (`min_probes`) has nothing to measure and silently stops guarding a gated export.
    """
    findings = iter_findings(a)
    doc = {
        "tool": TOOL_NAME,
        # `or a.get("assessment_id")` so re-exporting an export keeps the run's name. A raw
        # assessment calls it `id`; this document calls it `assessment_id`, and reading only the
        # first dropped the identity on the second pass -- a baseline that could no longer say
        # which run it came from.
        "assessment_id": a.get("id") or a.get("assessment_id"),
        "status": a.get("status"),
        "score": a.get("score"),
        "severity": a.get("severity"),
        "total": a.get("total"),
        "failed": a.get("failed"),
        "finding_count": len(findings),
        "findings": findings,
        # The gate's actual input. Everything above it is derived from this.
        "category_summary": a.get("category_summary") or [],
    }
    return json.dumps(doc, indent=2, ensure_ascii=False)


# --- CSV ---------------------------------------------------------------------
def to_csv(a: Dict[str, Any]) -> str:
    """One row per failed control; keyfindings joined with ' | '.

    Failures only, deliberately, and NOT changed lightly: `wc -l` on this file is a findings
    count in someone's pipeline, so adding passed rows would silently inflate it.

    The cost is that a clean assessment exports a header and nothing else -- 63 bytes, exit 0,
    which from the outside is hard to tell from a broken export. `to_markdown` handles the same
    case by saying "No failed controls" out loud; CSV has nowhere to put that sentence. If this
    should become a full control table (the `status` column only carries information once passed
    rows exist), that is a format change worth making deliberately, with the row-count impact
    called out, rather than as a side effect of a bug fix.
    """
    buf = io.StringIO()
    cols = ["control_id", "category", "severity", "status", "failed", "total", "keyfindings"]
    writer = csv.DictWriter(buf, fieldnames=cols, extrasaction="ignore")
    writer.writeheader()
    for f in iter_findings(a):
        row = dict(f)
        row["keyfindings"] = " | ".join(str(k) for k in f.get("keyfindings", []))
        writer.writerow(row)
    return buf.getvalue()


# --- SARIF 2.1.0 -------------------------------------------------------------
def to_sarif(a: Dict[str, Any]) -> str:
    """Emit schema-valid SARIF 2.1.0.

    Rules are the distinct failed control ids; results are the individual
    findings. `level` derives from each finding's severity. The output validates
    against the SARIF 2.1.0 schema (version, $schema, runs[].tool.driver, rules,
    results all present and well-typed).
    """
    findings = iter_findings(a)

    rules_by_id: Dict[str, Dict[str, Any]] = {}
    for f in findings:
        cid = f["control_id"]
        if cid not in rules_by_id:
            sev = f["severity"]
            rules_by_id[cid] = {
                "id": cid,
                "name": cid,
                "shortDescription": {"text": f"Ascend control {cid}"},
                "fullDescription": {"text": f"Straiker Ascend control '{cid}' "
                                            f"(category: {f['category']})."},
                # unmapped severity -> "error" (fail safe: never soften what we can't rank)
                "defaultConfiguration": {"level": _SEVERITY_TO_SARIF.get(sev, "error")},
                "properties": {
                    "category": f["category"],
                    "security-severity": _SEVERITY_SCORE.get(sev, "5.0"),
                    "tags": ["security", "ai", f["category"]],
                },
            }

    rule_index = {cid: i for i, cid in enumerate(rules_by_id)}
    results: List[Dict[str, Any]] = []
    for f in findings:
        cid = f["control_id"]
        sev = f["severity"]
        kf = f.get("keyfindings") or []
        msg = "; ".join(str(k) for k in kf) if kf else (
            f"Control {cid} failed {f.get('failed')}/{f.get('total')} probes.")
        results.append({
            "ruleId": cid,
            "ruleIndex": rule_index[cid],
            "level": _SEVERITY_TO_SARIF.get(sev, "error"),   # unmapped -> error (fail safe)
            "message": {"text": msg},
            "properties": {
                "category": f["category"],
                "failed": f.get("failed"),
                "total": f.get("total"),
                "severity": sev,
            },
            # Ascend findings are not tied to a source file; use a logical
            # location so SARIF consumers still render them.
            "locations": [{
                "logicalLocations": [{
                    "name": f["category"],
                    "fullyQualifiedName": f"{f['category']}/{cid}",
                    "kind": "namespace",
                }]
            }],
        })

    sarif = {
        "version": "2.1.0",
        "$schema": SARIF_SCHEMA,
        "runs": [{
            "tool": {
                "driver": {
                    "name": TOOL_NAME,
                    "informationUri": "https://straiker.ai",
                    "rules": list(rules_by_id.values()),
                }
            },
            "results": results,
            "properties": {
                "assessmentStatus": a.get("status"),
                "assessmentScore": a.get("score"),
                "assessmentSeverity": a.get("severity"),
            },
        }],
    }
    return json.dumps(sarif, indent=2, ensure_ascii=False)


# --- Markdown ----------------------------------------------------------------
def _sev_rank(sev: str) -> int:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "informational": 4}
    return order.get(str(sev).lower(), 5)


def to_markdown(a: Dict[str, Any]) -> str:
    """Human-readable findings report, severity-sorted, with a summary header."""
    findings = sorted(iter_findings(a), key=lambda f: _sev_rank(f["severity"]))
    lines: List[str] = []
    lines.append("# Ascend Assessment Findings")
    lines.append("")
    lines.append(f"- **Status:** {a.get('status', 'unknown')}")
    try:
        import api as _api
        _f, _t = _api.probe_counts(a)
    except Exception:                      # export must work on a saved file with no client
        _t, _f = a.get("total"), a.get("failed")
    _pct = f"{100 * (_f or 0) / _t:.0f}%" if _t else "n/a"
    lines.append(f"- **Fail rate:** {_pct} ({_f if _f is not None else '?'}/"
                 f"{_t if _t is not None else '?'} probes)")
    lines.append(f"- **Severity:** {a.get('severity', 'n/a')}")
    lines.append(f"- **Findings:** {len(findings)}")
    lines.append("")

    if not findings:
        lines.append("_No failed controls — nothing to report._")
        return "\n".join(lines) + "\n"

    lines.append("## Findings")
    lines.append("")
    lines.append("| Severity | Control | Category | Failed/Total |")
    lines.append("| --- | --- | --- | --- |")
    for f in findings:
        lines.append(f"| {f['severity']} | `{f['control_id']}` | {f['category']} "
                     f"| {f.get('failed')}/{f.get('total')} |")
    lines.append("")

    lines.append("## Detail")
    lines.append("")
    for f in findings:
        lines.append(f"### `{f['control_id']}` — {f['severity']}")
        lines.append(f"- Category: {f['category']}")
        lines.append(f"- Failed: {f.get('failed')}/{f.get('total')}")
        kf = f.get("keyfindings") or []
        if kf:
            lines.append("- Key findings:")
            for k in kf:
                lines.append(f"  - {k}")
        lines.append("")
    return "\n".join(lines) + "\n"
