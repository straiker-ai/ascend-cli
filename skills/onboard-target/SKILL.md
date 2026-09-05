---
name: onboard-target
description: >-
  End-to-end onboarding of a new red-team target: discover its shape, build and
  validate an adapter config, register a thin Ascend app, prove one live probe
  round-trips through the bridge, then launch the first assessment. Use when you
  have a fresh target (an API, chat widget, agent, or bot) and nothing set up yet.
---

# onboard-target

The full path from "here is a target" to "an assessment is running". It composes
the other skills and the deterministic CLI in order, with a **live probe gate** in
the middle so you never launch an assessment against a config that cannot actually
reach the target.

`ascend` below means `python3 shells/cli/ascend.py`.

## Preconditions
- `$STRAIKER_PAT` is set (tenant PAT). Confirm reachability first:
  ```
  ascend --json doctor
  ```
  PAT exchange, control catalog, and bridge reachability must be green before you
  proceed.
- You have captured evidence of one answered turn from the target (HAR, in-page
  capture, or a proxied send). If not, run **recon** first.
- Rules of engagement agreed: target allowlist, QPM cap, side-effect budget.

## Workflow

### 1. Discover + build a validated adapter
Follow the **build-adapter** skill. Do not continue past it until
`ascend target check <config>` is **green**. A thin app and an assessment
built on an unvalidated config waste the whole run.

**If the contract cannot be derived, write the adapter as code rather than iterating
forever.** A signature computed per request, a per-request nonce, a rotating conversation id,
a reply assembled from several fields, SOAP/XML/protobuf framing, a job you poll to
completion, or two unrelated credentials — none of these can be expressed as a config, so no
amount of layer-tweaking will land them. The contract is one function,
`def send_prompt(prompt: str) -> str`:

```
ascend target add --scaffold ./my_adapter.py --api <target-url>   # stub, seeded with the url
# edit send_prompt() until it returns the agent's reply
ascend target add --module ./my_adapter.py --name "<display name>" --save-as mybot
```

It passes the same hard gate as a derived adapter — nothing registers unless it answered the
live target — so the rest of this workflow is identical from here. See **build-adapter §5b**.

Output of this step: a config name (e.g. `mybot`) and its adapter type (a
transport or preset from `ascend adapter list`).

**Always pass `--save-as <name>`.** Left to itself the config name is derived from the URL's host,
so you get `myhost-com` or `127-0-0-1-8791` and then have to scrape it back out of stderr to know
what to hand `--config`. Naming it makes every later step deterministic:

```
ascend target add <url|curl|har> --save-as mybot --name "<display name>"
ascend target check mybot
```

**If the application already exists in the Console, adopt it — do not create a second one.**

```
ascend target add <url|curl|har> --app '<app name or aapp_id>' --save-as mybot --run
```

`--app` binds to the existing record and fetches its bridge key (the platform returns it on GET,
with the local key store as a fallback), preserving the system prompt, controls, size and QPM that
were set in the UI. Creating a fresh app instead strands all of that on an application nobody
assesses.

This is the shape of a stalled engagement: the app is configured, someone starts an assessment,
it fails, and nobody can say "where the bridge is". There is nothing to locate — a bridge is a
process the CLI runs. Diagnose with `ascend bridge ls` (is anything serving?) and
`ascend target show <name>` (what is this bound to?), not by hunting for a bridge.

Two behaviours to rely on rather than work around:

- Re-running against the **same endpoint** refreshes the config in place, and any `_ascend` app
  binding on it is carried forward — so re-deriving a config does not unbind the target from its
  application.
- A **different** endpoint under an already-used name is *not* overwritten; it is saved as
  `<name>-2` and both are named in the output. If you meant to replace it, pass `--save-as` with
  that exact name, which overwrites deliberately.
- `ascend target show <name>` prints which config, adapter, endpoint and key a target is bound to.
  Use it to confirm state instead of inferring it; if the config no longer resolves it says so
  rather than failing, and a missing config is the usual reason no bridge can start.

### 2. Pick the starting controls
Keep the first run tight — validate transport before spending a big control
budget. List and validate a small, relevant set (see **recon** for mapping
surface → controls):
```
ascend --json controls list --category <cat>
ascend --json controls validate <id1,id2,...>
```
Heed warnings: a selection that generates **zero probes** is a no-op. Drop
deprecated ids unless you have a reason.

### 3. Register the app
Registration is part of `target add`: the validated config, the application record and the
stored bridge key are written together, under one name.
```
ascend target add <url|curl|har> --save-as mybot --name "<display name>" \
  --controls <validated,ids> --qpm <roe_cap>
ascend target show "<display name>"        # app id, adapter, endpoint, masked key
```
The bridge key (`tc-...`) is stored for you (`ascend keys list`); `assess run` resolves it
from the store, so you never handle it by hand. A name that already exists in the Console
is **refused** — add `--app "<display name>"` to re-onboard that app (it keeps its key and
history) or pick another `--name`. To register an app that already exists in the Console
against a new config: `ascend target add <source> --app '<app name or aapp_id>'`.

> The key is **not** write-once, despite older guidance saying so: the platform returns
> `thin_api_key` on `GET /ascend/applications/{id}` and in the app list. So losing the
> create output is recoverable — never delete a working app just to see the key again.

> No customer names anywhere — the display name is a neutral target label.

Two things that bite here:

- **The platform requires an explicit control set.** `control_type: "all"` is rejected
  (400 "rejected by the upstream service"), and so is omitting the field — only `custom`
  plus a real id list is accepted. If you pass no `--controls`, the CLI resolves the whole
  catalog for you and says how many it registered. So `--controls` is optional, but a
  control set is not.
- **The response is routinely dropped *after* the app is created** ("Response ended
  prematurely"). The CLI re-reads the app by name, reports it as recovered rather than
  failing, and reads the bridge key back off the app — so nothing is lost. Do **not** retry
  blindly on a create error: check `ascend target list` first. A retry that would create a
  second app with the same name is refused by the CLI, because every later name-based
  command would become ambiguous.

### 4. Live probe gate — prove one round-trip
`target add` already proved the config against the live endpoint before it registered
anything. Re-prove it right before you spend an assessment, and keep the evidence:
```
ascend target check "<display name>"                              # the hard gate, timed
ascend chat "<display name>" --prompt "hello" --out ./captures/onboard_probe.jsonl
tail -n 2 ./captures/onboard_probe.jsonl                          # redacted, 0600
```
The relayed result must be the target's genuine answer — not an auth error, not an
empty body, not a transport parse failure. If it is wrong, go back to
**build-adapter** step 5 (iterate the failing layer) — **do not** launch the
assessment. This is the same gate build-adapter uses; here it doubles as an
end-to-end bridge check (lease → adapter → target → result).

### 5. Launch the first assessment
With the probe gate green, run it for real:
```
ascend --json assess run --app <app_id> --name "onboarding run 1" \
  --controls <validated,ids>
```
`assess run` does the correct lifecycle (create → pause → resume → poll) and blocks until
terminal. **It manages the relay for you**: it starts one before probes are scheduled,
binds it to this assessment, restarts it if it dies mid-run, and stops it when the run
ends. Stop the probe-gate runtime from step 4 first — a relay you started by hand is
reused rather than replaced, but two relays for one app would split that app's probes
between them.

For a long run pass `--no-wait` and monitor with the **run-assessment** skill; the relay
stays up on its own and stops when *this* assessment finishes.

Before trusting any result, confirm probes were actually answered:
```
ascend bridge ls          # ANS must be > 0
```
A run whose probes all failed still reports a score. It is not a clean bill of health — it
measured nothing.

### 6. Hand off
- Assessment launched and progressing (`ascend assess status`).
- When it completes, go to **run-assessment** (monitor/results) then
  **triage-findings** (FP triage + severity recalc).

## Definition of done
- `doctor` green; adapter config **validated**; one **live probe** round-tripped
  the real target answer through the bridge; thin app registered; first assessment
  running against a non-zero-probe control selection.

## Two gates that are not optional

**Before the run — credentials must resolve where the relay will run.** If the config
authenticates by `env:` reference, export the variable in the shell that starts the relay.
`ascend bridge start` refuses and names a missing one, because a relay that starts without it is
refused by the target on every probe and scores as a clean run that measured nothing.

**After the run — prove the target answered.**

```bash
ascend assess results --app '<name>'      # read the `answered` line
```

`answered = 0` means the score is meaningless regardless of how clean it looks. This is the step
operators skip most often; see the `verify-run` skill for the full triage. Do not report, export,
or gate on a number until this passes.
