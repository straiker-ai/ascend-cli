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

Both flags are `--detail` columns. Without `--detail` there are no probe counts to judge a result
against, so neither can be computed and neither is printed.

- `!!` — **suspiciously few probes on a clean result**: a completed run with 4 or fewer probes and
  either no failures or `low` severity. Unanswered probes are not findings, so a run that measured
  nothing reads clean. Two causes:
  - **Nothing served the probes.** `assess run` auto-starts and self-manages the bridge, so this
    normally can't happen. Suspect it when auto-management was disabled, the run started from the
    Console, or a remote/pre-started bridge died. Verify with `ascend bridge ls` (`ANS` must be > 0)
    or reconcile with `ascend bridge sync`. See [ASSESSMENT_LIFECYCLE.md](ASSESSMENT_LIFECYCLE.md).
  - **The bridge served them and the target had drifted.** An expired credential, a moved response
    shape, a changed endpoint, or a target now answering past the platform's per-probe window all
    produce a clean-looking run. This one leaves the bridge looking healthy.
- `~` — the severity was **re-ranked by your local policy** (below), overriding the platform value.

## A pass and a false pass look identical

The flag above is a heuristic on the *result*. The thing that actually separates a pass from a
false pass is proving the target still answers, and it is one command against the live endpoint:

```
ascend target check mybot          # re-proves the adapter, prints the measured reply time
```

Run it before a run, not after. It replays one prompt through the registered config, so it catches
the drift the run itself cannot report — expired auth, a response path that no longer resolves, an
endpoint that moved — and warns when the target's reply time will not survive the platform's
per-probe window ([PERFORMANCE.md](PERFORMANCE.md)). A green `target check` makes a clean report
mean something; without one, a 0% fail rate and a dead target are the same row.

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

### The gate refuses a control it cannot prove was re-tested

```
ascend ci --app 'My Bot' --assessment asmt_x --baseline last-week.json
ascend assess diff --app 'My Bot' --baseline asmt_old --current asmt_new
```

A baseline finding that is not failing now means one of two things, and they are opposites:

| Bucket | Means | Gate |
|---|---|---|
| `resolved` | the control was **re-probed** in this run and passed | clean |
| `not_retested` | this run never exercised the control — it produced no evidence either way | exit `2` |

Both used to be reported as `resolved`. Narrowing a run's scope past a failing control therefore
read as a fix, and the pipeline went green on a control nobody had re-run. `not_retested` is held
to the same `--fail-on-severity` bar as a live finding; `--allow-unproven` turns the failure off
for a deliberately narrowed run, and the bucket is still listed in the diff either way.

### The JSON export is a valid gate input

```
ascend export --app 'My Bot' --assessment asmt_x --format json --out run.json
ascend ci --file run.json                      # gate a saved result, no credential needed
ascend ci --app 'My Bot' --baseline run.json   # or diff against it next week
```

`--format json` carries the full control table alongside the flat `findings` list, so gating an
export and gating the run it came from give the same verdict, and a run diffed against its own
export reports nothing new. The other formats are unchanged: CSV is one row per failed control,
SARIF one result per finding.

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

It re-ranks **every** list the gate measures — the live findings and the `not_retested` bucket
alike. They are the same control ids; ranking one under your policy and the other under the
platform's would fail a build on a severity you overruled, and (in the other direction) let a
control you raised to `critical` go unproven and green.
