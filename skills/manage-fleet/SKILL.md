---
name: manage-fleet
description: >-
  Onboard and assess several targets at once without losing track of which is which: batch
  registration under distinct names, fleet runs, watching them together, and reconciling relays.
  Use whenever there is more than one target — a customer with several bots, an environment
  matrix, or a regression sweep.
---

# manage-fleet

One target is a command. Several targets is bookkeeping, and bookkeeping is where onboarding
actually goes wrong: the wrong app assessed, two apps sharing a name, a relay serving a target you
thought you had stopped. Measured across a controlled trial, three targets was where the gap
between using the CLI and driving the API by hand was widest — a mean of 2 errors against 10.5 —
entirely because of tracking, not difficulty.

## Register each target under a name you will still recognise

```bash
ascend target add http://host-a/chat --save-as bot-a --name 'Support Bot A'
ascend target add http://host-b/chat --save-as bot-b --name 'Support Bot B'
```

Two rules that prevent most fleet pain:

* **Names must be distinct.** Registration refuses a duplicate name outright — a second app with
  the same name silently poisons every later `--app <name>`.
* **`--save-as` is the local config name, `--name` is the app name on the tenant.** Keep them
  aligned or `target list` becomes a puzzle.

## See the whole fleet

```bash
ascend target list          # every target, its adapter, whether it is registered and serving
ascend bridge ls            # every relay: state, and ANS = probes actually answered
```

`target list` flags same-named targets. If it does, fix that before running anything.

## Run them together

```bash
ascend assess run --app 'Support Bot A' --app 'Support Bot B' --name 'wave 1' --controls sys_prompt_leak
ascend assess run --all-bound --name 'wave 1'      # every target with a stored bridge key
```

A fleet run waits like the single form and prints one summary table; under `--json` it is one
document, not a stream. Relays start and self-stop per app.

## Watch and verify

```bash
ascend assess watch --all
```

Then verify **each** target individually — a fleet summary can be green while one member answered
nothing:

```bash
for t in 'Support Bot A' 'Support Bot B'; do
  ascend assess results --app "$t" --json \
    | python3 -c 'import json,sys; d=json.load(sys.stdin); \
        print(d.get("relay_answered"), "answered")'
done
```

See `verify-run` for why that check is not optional.

## Reconcile and tear down

```bash
ascend bridge sync --app 'Support Bot A'   # one target
ascend bridge sync                          # everything this machine knows about
ascend bridge stop --all
ascend target rm 'Support Bot A'            # exact name; deletes the app and forgets its relay
```

`target rm` takes the **exact** name — never a substring — and confirms on a terminal. Deleting
also drops the stored bridge key, and only after the platform delete succeeds.

## Before you scale up

Scope the controls. `--controls sys_prompt_leak` is 4 probes per target; no `--controls` registers
the whole 62-control catalog against every app in the fleet. That is the difference between a
cheap sweep and a surprising bill.
