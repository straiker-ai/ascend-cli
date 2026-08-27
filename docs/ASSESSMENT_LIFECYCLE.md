# Assessment lifecycle

Three platform behaviours affect how you run an assessment and how you interpret a result.

## 0. The bridge is auto-managed

For a **bridge-type** app the CLI runs the relay ("the bridge") that answers probes. You no longer
start it manually for a normal run:

- `ascend assess run` on a bridge-type app **auto-starts the bridge before any probes are
  scheduled**, and the bridge **self-stops when the assessment reaches a terminal state**
  (`complete` / `failed` / `error`).
- `ascend assess resume` **re-ensures the bridge**. Use it after a Console-side resume. The SaaS
  cannot start a process on your machine, so a run resumed from the Console has no relay until the
  CLI puts one there (see §3).
- A bridge is **per-app**: one relay serves every assessment of that app. There is no
  cross-assessment contamination. The v2 lease/result protocol carries only opaque
  `request_id`/`msg_id` values that the bridge echoes back untouched; the platform attributes each
  probe to its assessment.

The invariant: **a bridge is up while any of an app's assessments is running or paused, and stops
once they are all terminal.** `assess run` and `assess resume` establish it; the bridge maintains
it itself (§2).

`ascend bridge start` still exists for advanced/remote/continuous/pre-start use (see
[FLEET.md](FLEET.md)). It is not a step in the normal flow.

## 1. Pausing and stopping drain in-flight probes first

When an assessment starts, the assessment engine **generates its probes up front**. Those probes
are already committed: pausing or stopping the assessment prevents *new* probes from being
scheduled, but **probes already created will run their course**.

Consequences you will observe:

- You click **Pause** (or run `ascend assess pause`) and the assessment keeps sending prompts to
  your target for a while. That is expected: the assessment is draining in-flight probes.
- Status can read `paused` while your target is still receiving traffic. Watch your target's own
  logs to know when traffic has stopped.
- The bridge stays alive across a pause so those in-flight probes are still answered (see §2).

**To stop completely:** pause, then wait for the in-flight batch to cycle through. If you need
hard containment, cut it at your side (block the target endpoint) and treat whatever lands in that
window as expected drain.

## 2. The bridge reconciles its own state

The bridge polls its app's assessment state **every ~30s** and manages its own lifecycle:

- **Terminal** (`complete` / `failed` / `error`) → it self-stops.
- **Running / queued / in_progress** → it stays up and answers probes.
- **Paused** → it stays up (in-flight probes may still be draining, §1). It self-stops only on a
  terminal state; optional idle cleanup (`--idle-timeout`, off by default) can reap a paused,
  already-probed relay left running.

**False-pass safety is preserved.** A dead relay does not fail the assessment. Probes keep being
issued, go unanswered, and the run still completes. Unanswered probes are not findings, so the run
produces a **score 0 / low risk** result. That is a false negative: a clean report from a run whose
relay died reflects nothing.

Because of that, **the bridge never self-stops when it cannot verify state** (e.g. the state poll
fails). It fails safe by staying up rather than risk killing a relay under a live run. Two things
follow:

1. If you disable auto-management and run a bare `bridge start`, a dead relay is still a false-pass
   risk. The safety above applies only to the auto-managed bridge.
2. **Check the probe count.** `ascend assess results --app … --assessment … --detail`
   should show roughly the probes you expected for the selected controls. A small total, or a `low`
   verdict on a run you expected to be busy, means the relay was not there. The relay's own log
   line, `relay: N answered, M failed`, is authoritative: `N` near zero on a run you expected to be
   busy means the assessment ran without a relay.

## 3. Console and CLI sync cannot start a local process

Pause/resume from the Console changes the assessment state, but the Console **cannot start the
bridge on your machine**. A run resumed in the Console consumes probes with no relay until the CLI
reconciles.

Two ways to reconcile after Console-side state changes:

- `ascend assess resume` re-ensures the bridge for that app.
- `ascend bridge sync` reconciles every bridge to its app's assessment state: starts one for
  apps whose assessment is running or paused, stops one for apps that have gone terminal. This is
  the manual fallback when state changed in the Console. See [FLEET.md](FLEET.md).

## 4. What the CLI states mean

`ascend app list --with-runs` marks with `*` only what is **actively consuming probes**:

| STATE | Meaning | Bridge |
|---|---|---|
| `*running` / `*queued` / `*in_progress` | probes are being issued now | up (auto) |
| `paused` | no new probes scheduled; in-flight ones may still be draining (§1) | up (stops on terminal; idle cleanup opt-in) |
| `created` | assessment exists, not started (lifecycle is `created → pause → resume`) | not yet |
| `complete` | finished; check the probe total before trusting the score (§2) | self-stopped |
| `failed` / `error` | the run itself errored | self-stopped |
| `none` | the app has no assessments | none |

```
ascend app list --with-runs     # every app + latest run: state, count, progress, score, severity
ascend app list --running       # ONLY apps actively consuming probes right now
ascend app list --all-runs      # every assessment per app
ascend assess list --app <app>  # one app's assessments (live ones marked *)
```
