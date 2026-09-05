---
name: verify-run
description: >-
  Prove an assessment actually reached the target before anyone trusts its score. Reads the
  relay's own answered/delivered/failed counters and the platform's category summary, and
  separates "clean because the target refused the attacks" from "clean because nothing was ever
  asked". Use after every run, and before any number is reported, exported, or gated on in CI.
---

# verify-run

A completed assessment with a clean score is ambiguous. It means one of two things:

1. the target answered every probe and refused the attacks — a real pass; or
2. the target answered **nothing**, so there were no responses to find fault in — a **false pass**.

The platform cannot tell these apart for you: unanswered probes are not findings, so both look
like `0 failed`. This skill closes that gap in one command, and it is the most-skipped step in
practice — measured across 22 independent onboardings, every single operator eventually
established this by hand, from relay logs, because they did not know it was already available.

## The one command

```bash
ascend assess results --app '<name>'
```

Read the `answered` line:

```
  answered   8 probe(s) answered by the target  ·  8 delivered  ·  0 failed   (this machine's relay)
```

* **answered > 0** — the target was reached. A clean score is a real result.
* **answered = 0** — nothing reached the target. The score is meaningless. The command says so
  outright rather than hinting.
* **no `answered` line** — this machine has no relay record for that run. That is expected for an
  `api`/`gcp`/`bedrock` app, where the platform calls the target itself; it is a red flag for a
  bridge (`thin`) app, and means you are verifying from the wrong machine.

Under `--json` the same facts are `relay_answered`, `relay_delivered`, `relay_failed`.

## Gate on it

```bash
ascend assess results --app '<name>' --json \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); \
      sys.exit(0 if (d.get("relay_answered") or 0) > 0 else 1)'
```

Non-zero means the run measured nothing. In CI, fail the job on this **before** reading the
score — a green gate on an unanswered run is worse than a red one, because it is believed.

## When answered is zero

Work down, cheapest first:

1. `ascend bridge ls` — is a relay serving this app at all? `ANS` is the same counter.
2. `ascend bridge logs --app '<name>'` — the relay records every call it made and what came back.
   A wall of `401`/`403` is a credential problem, not a target problem.
3. `ascend target check '<name>'` — re-prove the adapter against the live target right now.
   Targets drift; a config that worked last month is not evidence about today.
4. If the config authenticates by `env:` reference, confirm the variable is exported **in the
   shell that starts the relay**. `bridge start` refuses and names it, but a relay started earlier
   from a different shell will already be failing every probe.

## What this skill will not do

It will not tell you the finding count is *correct* — only that it was measured against something
real. Use `triage-findings` for the count itself.
