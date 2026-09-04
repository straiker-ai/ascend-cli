# Assessment lifecycle

Several platform behaviours affect how you run an assessment and how you interpret a result.

## The shape of a run

```bash
ascend target add <url|curl|har|config>   # adapt · prove · register (once per target)
ascend target check <target>              # re-prove it against the LIVE endpoint
ascend assess run --app <target> --name 'run 1'
ascend assess watch --all                 # the BRIDGE column flags a run nobody is answering
ascend reports --app <target> --detail
```

`target check` is not ceremony. A target that has drifted — auth expired, response shape moved,
endpoint relocated — still produces a clean-*looking* assessment that measured nothing, and a
false pass is the most expensive result this tool can produce (§2).

A note on the word "bridge": two different things get called that. The **lease service** is
Straiker-side and always up; **the bridge** is the process on your machine that leases probes and
calls your agent (these docs also call it the relay). "The bridge dropped" nearly always means
your own bridge process is not running — `ascend bridge ls` says which.

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

A relay stops **only for the assessment it is bound to**. `assess run` binds the relay it starts
to that run, so it reaps itself when *that* run ends — not when some other assessment on the same
app happens to be terminal. A relay started by hand (`ascend bridge start` / `runtime start`) is
unbound and therefore **never self-stops**, which is what makes it usable as a long-lived,
always-on relay; stop it with `ascend bridge stop`. Release follows the ~30s reconcile beat, so
expect a stopping relay to linger for up to one beat after a run goes terminal rather than
vanishing the instant the status flips.

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

**A relay that is alive but silent is replaced.** Liveness is the heartbeat, not the pid. A relay
whose process is up but has not beaten in three minutes is answering nobody, and `assess run` (and
the watchdog under it) stops it and starts a fresh one, saying which pid it replaced. The one
exception is a relay that reported a fatal error — a bridge key the lease service rejected, say. A
replacement would hit the same wall, so the error is printed instead.

**A pause that follows an outage is lifted; a pause nothing can lift ends the wait.** The platform
pauses a run whose probes go unanswered. When `assess run` saw the relay go down and brought it
back, it resumes the run (a few times at most, and never a pause it did not see happen — your own
`assess pause` is left alone and mentioned once). When the run is paused and no relay could be
started for three polls in a row, `assess run` exits 1 at once with the reason and the two commands
that continue the run, instead of polling to its timeout.

## Reading the relay's log

`ascend bridge logs --app <name>` is the ground truth when a run looks wrong. The lines are
prefixed by the component that wrote them, and those prefixes are the same three nouns the
diagram uses:

| log prefix | what it is |
|---|---|
| `ascendbridge.lease` | the bridge, talking to the Straiker cloud: leasing probes and posting results |
| `ascendbridge` | the relay's own lifecycle — heartbeats, self-reconcile, shutdown |
| `adapters.<type>` | the adapter, calling your target (`adapters.direct_api: DirectAPI: POST https://…`) |

A line under `adapters.*` is your target's problem; a line under `ascendbridge.lease` is the
Straiker edge. That split is the fastest triage this tool offers, and it is why
`ascend bridge ls`'s `ANS` column and the log agree: `ANS` counts what the adapter answered.

<a id="service-names"></a>
Straiker's own service endpoints occasionally identify themselves by an internal service name in a
raw HTTP response — the lease endpoint's health body is one. Those names are not part of any
contract and are not used anywhere in this CLI, its output or its logs. Everything you need to
troubleshoot is in the prefixes above; if you see an unfamiliar service name in a raw response,
it is the Straiker cloud answering, and the product name for that half of the picture is
**Ascend AI**.

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

## 5. Two limits that masquerade as a broken bridge

Both of these present as "the bridge keeps dropping". Neither is a dropped connection.

**The per-probe window (~110–120s).** Each probe gets a bounded window, and the clock starts when
the probe is **queued** — not when your relay picks it up and calls your agent. A probe that
exceeds the window comes back as a synthetic timeout that is indistinguishable from your target
having failed, and enough of those trip the platform's target-health check and **auto-pause the
assessment**. The run then looks exactly like a dead bridge: probes stop flowing, nothing is being
answered.

Agents that think for two or three minutes are common, so this is a real ceiling, not an edge
case. `adapter validate` and `target check` time the target and say plainly when it is at or
beyond the window. If your target is genuinely that slow, reduce concurrency and QPM so probes
are not queuing behind each other and burning their window before delivery — the queue, not the
target, is usually what pushes a borderline agent over.

**A relay that never started.** If the adapter config cannot be resolved, `runtime start` exits
*before it ever leases*, and a relay that never started looks identical to one that dropped. The
tell is that `ascend keys` and the Console both look fine, because keys are stored in `~/.ascend`
and never depended on your working directory. Configs are searched per file across
`$ASCEND_CONFIG_DIR`, `./configs`, `~/.ascend/configs` and the bundled examples; run `ascend
adapter configs` to see every one that resolves and where new ones are written, and `ascend
bridge logs <app>` to see why a relay exited.
