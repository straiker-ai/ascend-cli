---
name: run-assessment
description: >-
  Run and monitor an Ascend assessment against an already-onboarded target: choose
  and validate a control selection, launch the lifecycle-correct run, watch it to
  completion, then pull results. Use when the target already has a validated
  adapter config and a registered app and you want to execute (or re-execute) a
  test pass.
---

# run-assessment

Execute a test pass against a target that is already onboarded (validated adapter
config + registered app + a running bridge). This skill is deliberately thin — the
CLI owns the create → pause → resume → poll lifecycle; you choose controls, launch,
monitor, and read results.

`ascend` below means `python3 shells/cli/ascend.py`.

## Preconditions
- The target's adapter config is **validated** (see build-adapter) and a thin app
  exists (`ascend app list` shows it; resolve a name with `ascend app resolve`).
- The bridge is running for this app so leased probes get serviced:
  ```
  STRAIKER_BRIDGE_API_KEY=tc-... ascend runtime start --adapter <type> --config <config> --qpm <cap>
  ```
  Leave it running in its own shell for the whole assessment.

## Workflow

### 1. Choose controls
Start from the attack surface (use **recon** to map surface → controls). List the
catalog, filter to what is relevant, and prefer agentic controls when the target
is an agent with tools:
```
ascend --json controls list                     # everything
ascend --json controls list --category <cat>    # by category
ascend --json controls list --agentic-only      # tool/agent controls
```
The flags in the JSON: `deprecated` and `agentic` per control. Skip deprecated ids
unless intentional.

### 2. Validate the selection (do this before running)
```
ascend --json controls validate <id1,id2,id3>
```
Read the return: `valid`, `deprecated`, `unknown`, `agentic`, and `warnings`. A
**zero-probe** selection is the trap — it launches but tests nothing. Fix unknown
ids and drop dead ones until `valid` covers your intent. `assess run` re-validates
and refuses a zero-probe selection unless you pass `--force`.

### 3. Launch
```
ascend --json assess run --app <app_or_name> --name "<run label>" \
  --controls <validated,ids> --interval 20 --timeout 7200
```
`assess run` performs the whole lifecycle correctly (create → pause → resume →
poll) and blocks until terminal, printing tick progress to stderr. For a long run
you want to monitor separately, add `--no-wait` — it returns after resume with the
assessment id, and you drive steps 4–5 yourself.

### 4. Monitor
If you launched with `--no-wait` (or want a second view), poll status:
```
ascend --json assess status --app <app_or_name> --assessment <assessment_id>
```
Key fields: `status`, `progress`, `score`, `severity`. You can `pause` / `resume`
mid-run if you need to throttle the target:
```
ascend assess pause  --app <app> --assessment <id>
ascend assess resume --app <app> --assessment <id>
```
### 4b. Read the bridge, not just the assessment

`ascend bridge ls` is the ground truth for whether anything is actually being tested:

```
ascend bridge ls        # STATE, ANS (answered), DELIV, FAIL, LEASE-ERR per relay
```

**`ANS` (answered) is the number that matters** — probes the target answered with a 200.
`FAIL` counts probes the adapter could not complete.

- `answered = 0` while `failed` climbs → the **adapter** is failing every probe, not the
  bridge. Two causes, in order of likelihood: the target takes longer than the configured
  `timeout_ms` (agentic targets take 2-3 minutes and often much more), or a short-lived
  credential expired mid-run. Fix the adapter (see **build-adapter**: Layer 3, Timeouts).
  Restarting the bridge will not help.
- `answered = 0` and nothing moving at all → no relay is serving this app. Unanswered
  probes are not findings: the run finishes **clean having measured nothing** (false pass).

**The trap: a run that goes `paused` by itself.** When probes keep failing the platform
**auto-pauses the assessment**. Observed live: a slow target under a too-short timeout
failed 5/5 probes, the run flipped `running → paused` and sat there while the bridge stayed
perfectly healthy. That reads as "the bridge died" and it is not — it is an adapter failure
the platform reacted to. Diagnose in this order:

1. `ascend bridge ls` → is a relay `serving`, and is `ANS` above zero?
2. If `ANS = 0`, fix the adapter (timeout / auth). Do **not** restart the bridge.
3. Then `ascend assess resume --app <app> --assessment <id>`.

A relay is bound to the assessment it was started for and stays up for that whole run,
including while it is paused. A standalone `ascend runtime start` stays up until stopped.
Never run two relays for one app — they split that app's probes between them.

Keep the host awake for long runs; a sleeping Mac drops the connection.

The full symptom table — including the failures that present as something else entirely (protocol
captured as the answer, probes split across two relays, a create that errored but succeeded) — is in
**build-adapter**, under *Troubleshooting: symptom -> what it actually is*. Start there rather than
guessing, and start with `ANS`.

### 5. Pull results
```
ascend --json assess results --app <app_or_name> --assessment <assessment_id>
```
This returns the full results object with a summarized view. **Do not** report the
raw pass/fail or the Console severity as-is — the numbers still contain false
positives and are not auth-adjusted. Hand the results to **triage-findings** for FP
triage and severity recalc before any count leaves this skill.

### 6. Re-run / expand
To widen coverage, repeat from step 1 with a larger or different control set (a new
`--name` each time keeps runs distinct). List prior runs with:
```
ascend --json assess list --app <app_or_name>
```

## Definition of done
- Control selection **validated** (non-zero probes, no dead ids).
- Assessment reached a terminal status; results pulled.
- Raw results handed to **triage-findings** — not reported directly.

## Reading the result

`assess run` accepts `--detail`, so the command that produces the findings can also show them —
no need to re-issue the run or follow up with `assess results`:

```bash
ascend assess run --app '<name>' --name r1 --controls sys_prompt_leak --detail
```

The result carries an `answered` line from the relay's own counters. Treat a clean score with
`answered = 0` as a failed run, not a passing one — the guard says so explicitly, and it now only
fires on evidence rather than on probe count, so when it speaks it means it.
