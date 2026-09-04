# Running many engagements at once

One tenant, many apps. Each Ascend app has its own `tc-` key, and **a `tc-` key selects exactly one
application server-side**, so N bridge-type apps means N relays. For a normal run, `assess run`
auto-starts a bridge per app (see
[ASSESSMENT_LIFECYCLE.md](ASSESSMENT_LIFECYCLE.md)):

```
ascend tenant show                 # which tenant am I locked to?
ascend target list                 # every target: adapter, config, registered, serving
ascend keys list                   # one bridge key per app, masked
ascend assess run --app A --app B --app C --name 'wave 1'   # bridge per app, waits, one summary table
ascend assess watch --all          # one table, every live run (started with --no-wait, or elsewhere)
ascend bridge ls                    # who is serving what (and who ISN'T)
ascend bridge sync                  # reconcile bridges to assessment state (manual fallback)
```

The bridges self-stop as each app's assessments reach a terminal state, so there is nothing to tear
down after a clean run.

## Driving the fleet by hand

`assess run`/`resume` cover the normal flow. The explicit fleet commands remain for advanced use:

- **Pre-start** a relay before scheduling probes, or keep one running **continuously** across many
  assessments.
- **Remote/detached** operation where you want the relays up independently of any `assess` call.
- **Reconcile** after Console-side state changes the CLI didn't drive.

```
ascend bridge start --all-running   # a detached relay per live assessment — no key pasting
ascend bridge start --app 'Bot A' --app 'Bot B'   # pre-start specific apps
ascend bridge sync                  # start relays for running/paused apps, stop them for terminal
ascend bridge stop --all
```

`bridge sync` reconciles the fleet with assessment state: it starts a relay for every
app whose assessment is running or paused and stops one for every app that has gone terminal. Use
it after a Console-side resume/pause. The SaaS can't start a process on your machine, so the
CLI has to reconcile.

## One tenant at a time

The CLI pins itself to the first tenant it authenticates against and **refuses any credential from
another tenant**. Working two customers from one CLI can cross material between them (a key, a
config, an app), so it is a hard stop.

```
$ ascend app list
error: this CLI is locked to tenant 'acme.com (admin)', but the supplied credential belongs to
  'othercustomer.com (admin)'.
  To move:  ascend tenant switch --confirm
```

Identity comes from your PAT-exchanged JWT (`iss` + `straikerId`). Only a **SHA-256 fingerprint** is
stored, never the raw id or the PAT. `tenant switch --confirm` refuses while relays are running,
then archives and clears the stored keys so nothing can leak forward. All state (keys, relay records)
lives under the tenant's fingerprint directory.

## The key store

`target add`, `onboard` and `app create` all store the `tc-` key they mint. The API shows it once,
so if it isn't captured the app can never be served.

| command | does |
|---|---|
| `ascend keys list` | every key, **masked**, with the app + config it belongs to and whether the app still exists |
| `ascend keys prune` | drop keys whose app is gone |
| `ascend keys add --app X --key tc-…` | store a key minted elsewhere (e.g. the Console) |
| `ascend keys rm X` | forget one (`--delete-app` retires the pair) |

`ascend target rm X` does both halves at once: it deletes the application and drops its stored key,
which is the state you want when an engagement ends.

Keys live in a 0600 file under the tenant's state dir. They are **never** put on a relay's command
line, because argv is world-readable via `ps`; they go into the child's environment.

`ascend app bind <config> --app <app>` records the config↔app link inside the config's `_ascend`
block, so `bridge start --app X` knows what to run without you naming a config.

## Which apps need a bridge

Only **bridge-type** apps. Those hand prompts to your local bridge over a `tc-` key, so nothing runs
without it. `api`, `gcp` and `bedrock` apps are called by Ascend **directly** and never need a local
bridge, so `bridge ls` does not list them in the NO-BRIDGE alarm.

Check an app's type with `ascend app list` (the `TYPE` column shows `bridge` for these).

## The bridge fleet

`ascend bridge start` spawns **one detached process per app**, each with its own log:

```
$ ascend bridge start --app 'Bot A' --app 'Bot B' --qpm-total 60
  started  Bot A  pid=25502  log=~/.ascend/state/<tenant>/relays/aapp_….log
  started  Bot B  pid=25503  log=…
  2 relay(s) started, qpm=30 each
  they survive this terminal closing.  check:  ascend bridge ls
```

Processes are used instead of threads for several reasons: the CLI's signal handler closes over one
client (so N-1 would never stop), `logging.basicConfig` is global and first-call-wins with app-less
logger names, the conversation router has no teardown (each relay would leak a loop, a thread and
cached adapters, including live Chromium), and a native adapter crash would take the whole fleet
down. Processes give per-app logs and isolation.

`--qpm-total N` splits the rate across the relays it starts. Rate limiting is per-relay, so without
this, three relays pointed at one customer host hit it at 3× your intended rate.

```
$ ascend bridge ls
  STATE         PID APP                          CONFIG      ANSWERED FAILED UPTIME  NAME
  *serving    25502 aapp_3cy…                    fleet-a            8      0 3m07s   Bot A
   dead       25502 aapp_5gQ…                    fleet-b            8      0 3m58s   Bot B

  !! NO BRIDGE — probes going unanswered (a run with no bridge scores a FALSE PASS):
     Bot B  assessment asmt_5EL… (running)
     fix:  ascend bridge sync      # or: ascend bridge start --app '<name>'
```

States: `*serving` (heartbeat fresh), `stale` (alive, no recent heartbeat), `dead` (process gone).
An auto-managed bridge self-stops on a terminal assessment and self-reconciles otherwise, so a
`dead` row against a live run usually means auto-management is off or the process crashed. `bridge
sync` corrects it. `relay logs <app> -f` tails one. `relay stop --all` SIGTERMs then SIGKILLs
after a grace period. An in-flight lease long-poll isn't interruptible, so a clean stop can take
~35s, and the command reports this.

## The NO-BRIDGE alarm

A dead bridge **does not fail the assessment**. Probes keep being issued, go unanswered, and the run
still completes. Unanswered probes aren't findings, so the run reports a clean-looking `score 0 / low`.
That is a false negative. The auto-managed bridge fails safe (it never self-stops when it can't
verify state), but a bare `bridge start` puts the risk back on you. `bridge ls` reports the inverse
condition, and `assess results` warns when a completed run has an implausibly small probe total on a
clean score. See [ASSESSMENT_LIFECYCLE.md](ASSESSMENT_LIFECYCLE.md).

A bridge that never **started** presents identically to one that died, and across a fleet the usual
cause was config lookup. It stopped at the first configs *directory* that existed, and every
checkout ships a `configs/` of examples — so running the CLI from a checkout hid `~/.ascend/configs`
and a config written elsewhere was "config not found", while the same app's key resolved fine
(keys live in `~/.ascend` and never depended on the working directory). Configs are searched per
*file* across every config directory now, and `ascend adapter configs` lists all of them. When a
row in `bridge ls` looks wrong, `ascend target check <t>` proves the config against the live
endpoint before you go looking at the relay.

## Many assessments

`--app` is repeatable across these commands:

```
ascend assess run --app A --app B --app C --name 'wave 1'   # control set validated ONCE, bridge per app, waits
ascend assess run --all-bound --name 'wave 1'               # every app with a stored key
ascend assess watch --all                                   # all live runs (yours with --no-wait, or anyone's)
ascend app list --with-runs                                 # per-app: state, runs, progress, score
ascend app list --running                                    # only apps actively consuming probes
```

`assess watch --all` shows a `BRIDGE` column per run, so an unserved run is visible while it is
happening.

## A full multi-engagement session

```bash
export STRAIKER_PAT=s6r_pat_…
ascend tenant show                                    # confirm the tenant

for t in bot-a bot-b bot-c; do                        # 1. onboard each target
  ascend target add "https://$t.internal/chat" --name "$t" \
    --bearer "$TOK" --controls sys_prompt_leak
done
ascend target list                                     # 2. all three registered, none serving yet
ascend assess run --app bot-a --app bot-b --app bot-c --name 'wave 1'   # 3. run: bridge per app, waits, summary table
ascend assess watch --all                                               # 4. (only with --no-wait) follow them
ascend bridge ls                                       # 5. confirm nothing is unserved
# bridges self-stop as each run goes terminal
ascend keys prune                                      # 6. tidy keys for deleted apps
```

Step 1 is the pair it replaces — `ascend adapter build --api … --out "$t.json"` then
`ascend app create --type bridge --name "$t" --config "$t" --controls sys_prompt_leak` — which
still work unchanged when you need the steps apart, e.g. to edit the config between them.
