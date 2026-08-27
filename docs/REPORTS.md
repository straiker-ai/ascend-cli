# Reading results

```
ascend reports                          # latest run per app: severity, fail%, age
ascend reports --detail                 # + pass/fail bar, probe counts, findings, categories
ascend reports --min-sev high --sort sev
ascend reports --app 'My Bot' --per-app 5
ascend reports --json                   # for scripts and agents
```

```
    SEV     FAIL%  PASS/FAIL    PROBES FIND   WHEN  APP                  CATEGORIES
  ------------------------------------------------------------------------------------
  ● high     17%  ▓▓░░░░░░░░ 187/1117   56   222d  Acme SalesGenie      App Grounding, Data Leakage
  ● low       7%  ▓▓▓▓▓▓▓▓▓▓   3/41      2    12d  Acme DocsAI          Jailbreak
```

## Probes and findings are different units

| Column | Unit | Means |
|---|---|---|
| `PROBES` | **probes** | `failed/total` individual adversarial prompts sent |
| `FIND` | **controls** | how many *controls* failed — each is one finding |
| `PASS/FAIL` bar | probes | the visual ratio of the probe counts |

They are different units. 187 failed probes across 56 failed controls is a single run; the probe
count and the finding count measure different things and need not match.

`FAIL%` is failed ÷ total probes, the fraction of probes the target failed. `SEV` is the
assessment's severity, also shown as the leading ● (red high · yellow medium · green low). `WHEN`
is the age of the run (`4d`, `2h`). Every number here is derived from the probe counts.

## Why some rows are flagged

- `!!` — **suspiciously few probes on a clean result.** The likely cause is that no bridge served
  the run: unanswered probes are not findings, so the result reads clean when it measured nothing.
  `assess run` auto-starts and self-manages the bridge, so this normally can't happen. Suspect it
  when auto-management was disabled, the run started from the Console, or a remote/pre-started bridge
  died. Verify with `ascend bridge ls` (or reconcile with `ascend bridge sync`), and see
  [ASSESSMENT_LIFECYCLE.md](ASSESSMENT_LIFECYCLE.md).
- `~` — the severity was **re-ranked by your local policy** (below), overriding the platform value.

## Cost and the extra `--detail` call

There is no tenant-wide assessments endpoint, so the CLI makes one call per app to list runs. Those
calls run in parallel and show a progress line. Probe and finding counts exist only on the
*individual* assessment, so `--detail` makes one additional call per run. It is opt-in for that
reason.

## Exporting

```
ascend export --app 'My Bot' --assessment asmt_x --format sarif --out findings.sarif
ascend export --app 'My Bot' --assessment asmt_x --format markdown
ascend results captures/session.jsonl        # replay a manual chat session as a table
```

SARIF flows into GitHub code scanning, Azure DevOps, and SARIF-aware SIEMs. A finding whose
severity cannot be determined is emitted as `error`.

## Gating a pipeline

```
ascend ci --app 'My Bot' --assessment asmt_x --fail-on-severity high --junit results.xml
```

Exit codes are a stable contract:

| Code | Meaning |
|---|---|
| `0` | clean — no finding met the threshold |
| `1` | **could not read the results** (e.g. a completed run with no findings data) — never treated as a pass |
| `2` | the findings gate failed |
| `3` | bad invocation |

### The gate refuses a run that measured nothing

A completed run with **fewer than 5 probes and no findings** exits `1`. That combination indicates
a bridge that was not running: the probes went unanswered, unanswered probes are not findings, and
the assessment finishes looking clean (0% fail) having tested nothing. `ascend reports` flags the
same run with `!!`.

```
ascend ci --app 'My Bot' --assessment asmt_x                 # refuses a 2-probe clean run
ascend ci --app 'My Bot' --assessment asmt_x --min-probes 0  # for runs that really are that small
```

A tiny run that found something is a normal findings failure (exit `2`).

## Local severity policy

Per-control severity is **not settable on an Ascend app** through the v3 API. The platform assigns
severity at scoring time. If a control matters more for *your* app, express it locally in a file
you commit next to your pipeline:

```
ascend policy set --fail-on-severity high
ascend policy set --app 'My Bot' --control tool_misuse=critical
ascend policy set --category data_leak=high
ascend policy show
```

`ascend-policy.json` (or `$ASCEND_POLICY`):

```json
{
  "default": {"fail_on_severity": "high", "fail_on_new": true},
  "apps": {
    "My Bot": {
      "fail_on_severity": "medium",
      "controls":   {"tool_misuse": "critical"},
      "categories": {"data_leak": "high"}
    }
  }
}
```

The policy is applied **before** the gate decides, so an override changes the gate verdict.
Precedence: app control → app category → global control → global category → the severity the
platform reported. An explicit `--fail-on-severity` on the command line always wins.
