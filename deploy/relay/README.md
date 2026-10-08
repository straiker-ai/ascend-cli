# The Ascend relay as a container

The relay, packaged so it runs **in the customer's own account** — on Fargate, on Cloud Run, or
as a Kubernetes Job — instead of on an engineer's laptop.

Everything below that says "measured" was run on 2026-09-20 against this repository, a stand-in
platform on loopback, the built image, and prod tenant 123. (Container log timestamps in this
file are UTC and read 2026-09-21; it is the same evening.) Nothing here is estimated, and the
things that were **not** run are listed at the end, by name.

---

## 1. Why it has to be the customer's

The relay only exists because the target is **not reachable from Straiker**. That single fact
settles where it can run:

| Target | Relay | Where it must run |
|---|---|---|
| Reachable from Straiker | none — direct API | the platform calls the target itself |
| Only reachable inside the customer's network | required | **inside that network** |
| Public, but IP-allowlisted to known egress | required | anywhere with a **stable egress IP** |

A relay hosted in *Straiker's* cloud does nothing for row two: if we could reach the target from
our cloud we would not be relaying. So this image is built to be run by the customer, beside the
agent under test, on their credentials — which is also where their security team already has a
deployment path, a secret store and an audit trail. (`ascend-agent/notes/relay-where-it-runs.md`
works this through.)

## 2. What it replaces, and the one thing it fixes

Today the relay is `runtime/lease_client.py` long-polling `/v2/lease`, kept alive by
`runtime/supervisor.py` as a detached local process. It genuinely survives the CLI exiting and
the terminal closing. What it does not survive is the machine — sleep, shutdown, VPN drop. The
operating workaround is literally `caffeinate -dims &`.

And the failure is silent. When the relay stops answering, the run does not fail; it goes quiet
and can still report clean, because unanswered probes are not findings.

The container does not make the relay more reliable. It makes its **death loud**. Measured, on
this repository:

```
$ ascend runtime start --config tgt --bridge-base <lease service returning 401>
ERROR ascendbridge.lease: Ascend rejected this bridge key (HTTP 401). ...
EXIT=0                                                      # 0.28 s, exit code zero
```

On a laptop a human reads the error. In ECS, Cloud Run or a Kubernetes Job that exit code means
`Succeeded`: nothing restarts, no alarm fires, and the assessment runs to `completed` having
been answered by nobody. The entrypoint in this directory exists to turn that into an exit 1
with a sentence naming what happened.

## 3. Exit codes

| Code | Meaning |
|---|---|
| **0** | The bound assessment reached a terminal state **and** this relay carried probes for it. The only success. |
| **1** | The relay stopped and that did not happen — rejected key, crash, orchestrator stop, a run that outlived it, or a terminal run this relay served nothing of. |
| **3** | The environment is unusable. Refused before the relay was started at all. Matches the CLI's own `EXIT_USAGE`. |

Exit 1 is the whole point of a restart policy: a Kubernetes Job with `restartPolicy: OnFailure`
or a Cloud Run Job with `maxRetries` puts the relay back in front of a run that is still going.

Measured in the built image:

| Case | Exit |
|---|---|
| no environment at all | 3, naming all five missing variables in one pass |
| target config references an unset `env:` variable | 3, before anything is spawned |
| the control plane rejects `$STRAIKER_PAT` | 3, before a single probe is leased |
| lease service returns 401 | 1, `"the relay never completed a single lease"` |
| `$ASCEND_RELAY_DEADLINE_S` reached with the run still live | 1, `"the STOP CONDITION never fired"` |
| bound assessment goes `completed` | 0, `"reached a terminal state and this relay stopped itself"` |

## 4. Environment

Nothing is baked into the image. Every credential arrives at run time from the orchestrator's
secret store.

### Required

| Variable | What it is |
|---|---|
| `STRAIKER_BRIDGE_API_KEY` | The app's relay credential, `tc-…`. Shown once when the app is created; `ascend keys list` has it locally. |
| `ASCEND_RELAY_APP_ID` | The Ascend application, `aapp_…`. The relay publishes its heartbeat under this id and polls this app's assessments. |
| `ASCEND_ASSESSMENT_ID` | The run this container is for. **This is the stop condition** — but only half of it: `_reconcile_decision` in `shells/cli/ascend.py` returns `serve` forever when there is no bound run *and also* whenever it cannot read the control plane or the bound id is not in the answer. A container without this variable never exits; a container with the wrong one, or with a PAT the control plane refuses, also never exits. §4.1 has both measured, and what closes them. |
| `STRAIKER_PAT` | A Straiker PAT that can read this app's assessments — the stop condition polls them, and the container makes one read with it before starting the relay, because a PAT this endpoint refuses means the relay can never stop (§4.1). The relay's own credential cannot: measured against prod 2026-09-20, a `tc-` key on `GET /api/v3/ascend/applications/{id}/assessments` returns **HTTP 401**. So the container needs a second, much more powerful credential purely to learn that its run has finished. |
| `ASCEND_RELAY_CONFIG_JSON` **or** `ASCEND_RELAY_CONFIG_FILE` | The adapter config for the target — inline JSON (from a secret) or a path to a mounted file. Exactly one; both set is refused rather than guessed. |

Inline JSON is written to `$ASCEND_RELAY_WORKDIR/target.json` at 0600 before the relay starts,
because the CLI cannot take a config any other way: `configs.load_config` accepts a dict or a
config *reference*, and a JSON string is treated as a filename. Measured —
`--config '{"adapter":"direct_api",…}'` fails with `config not found`, having searched for a
file whose name is the JSON.

If the config authenticates with `env:NAME` references, those variables must be set on the
container too. They are checked before the relay starts, for a measured reason: with
`env:CUSTOMER_AGENT_TOKEN` unset, `runtime start` logged `ready — first lease OK`, leased 23
probes, called the target **zero** times and delivered 23 failures. Externally it looked alive
the whole time. `supervisor.start()` refuses to spawn in that state; the `runtime start` path
the container uses has no such check, so the entrypoint carries it.

### Optional

| Variable | Default | Notes |
|---|---|---|
| `STRAIKER_BRIDGE_URL` | `https://ascendai-bridge.prod.straiker.ai` | Lease service. |
| `ASCEND_CONTROL_BASE` | `https://api.prod.straiker.ai/api/v3` | v3 API the stop condition polls. |
| `ASCEND_RELAY_ADAPTER` | from the config | |
| `ASCEND_RELAY_QPM` | unthrottled | Queries per minute against the target. Set this if the agent under test is rate-limited or expensive. |
| `ASCEND_RELAY_MAX_WORKERS` | auto (1 for stateful adapters, else 10) | |
| `ASCEND_RELAY_WAIT_MS` | 25000 | Long-poll hold. The server clamps to 0–55000. |
| `ASCEND_RELAY_CONVERSATION` | `per-probe` | `sequential` for multi-turn controls. |
| `ASCEND_RELAY_IDLE_TIMEOUT` | 0 (off) | Seconds a *paused*, already-probed relay waits before giving up. Off by default; reaping during a stall is how relays died mid-run. |
| `ASCEND_RELAY_CONSUMER` | `abv2-<app_id>` | Matches `supervisor.start()`, so a container replacing a laptop relay is indistinguishable to the lease service. Parallel relays on one app **must** differ. |
| `ASCEND_RELAY_ALLOW_NO_TRAFFIC` | unset | Downgrades "the run finished but this relay served nothing" from failure to a logged warning. Only for a deliberate second relay on one app. |
| `ASCEND_RELAY_CAPTURE` | unset | Path for a jsonl transcript of every probe and result. Whatever the target leaks lands here; it is written 0600 and it needs a writable volume that outlives the task if you want to keep it. |
| `ASCEND_RELAY_DEADLINE_S` | 21600 (6 h) | Ceiling on the whole container. `0` disables it. See §4.1 — this is not an estimate of how long a run takes, it is the backstop for a stop condition that cannot fire. |

### 4.1 The stop condition is not self-sufficient

`$ASCEND_ASSESSMENT_ID` stops the relay **only when the control plane can be read and the bound
id comes back in the answer**. Two ways that fails, both measured on this repo with the reconcile
graces compressed to 2 s — so that a healthy container exits in about 6 s and there is no doubt
about what "never" means:

| What is wrong | What the container did | Heartbeat while it did it |
|---|---|---|
| `GET …/assessments` returns 401 (a PAT that cannot read this app, or an expired one) | still serving at 40 s, 190 probes burned, no exit | `state: serving`, `reconcile_error: "…-> 401…"` |
| `$ASCEND_ASSESSMENT_ID` is not in the response (a typo, or the wrong app) | still serving at 40 s, 189 probes burned, no exit | `state: serving`, `reconcile_error: null`, `asmt_status: "completed"` — the CLI's `_latest()` fallback naming an unrelated run |

`_reconcile_decision` is explicit about why: `if not control_ok: return "serve"`. It will never
self-kill on an answer it cannot interpret, because an unanswered probe scores a false pass. That
is the right call for the CLI, and it means the container has to carry the other half. Two
things do that:

1. **A control-plane preflight**, one `GET` with the PAT before the relay is spawned. A
   credential the server *actually rejects* (401/403, at the endpoint or at the PAT exchange)
   exits **3** with nothing leased and the assessment untouched. A bound id that is merely
   *absent* only warns — the CLI's own beat notes that "the bridge is often started BEFORE its
   assessment exists", so refusing there would break a legitimate launch order to catch a typo.
   Anything the check could not read (timeout, 5xx) starts the relay anyway; a blip at t=0 must
   not stop a run someone is waiting on.
2. **`$ASCEND_RELAY_DEADLINE_S`**, a ceiling the container enforces on itself. On expiry it
   SIGTERMs the relay, lets the lease drain for `wait_ms + 10` s, and exits **1** with a message
   that names the stop condition rather than the relay — because the relay was working.

k8s (`activeDeadlineSeconds`) and Cloud Run (`timeoutSeconds`) have a ceiling natively and the
manifests here set both to 86400. **ECS/Fargate has no task timeout of any kind**, and neither
does `docker run`, so on the two paths §5 documents first the container's own deadline is the
only thing there is. Even where the orchestrator does cut it off, it cuts without a verdict: the
operator gets `DeadlineExceeded` and no sentence saying why nothing ever finished.

6 h is a deliberate over-estimate and **not a measurement** — the longest container lifetime
measured anywhere in this file is 122 s. It is set against two in-repo numbers rather than from
memory: `AscendAPI.poll_assessment` gives up waiting for an assessment at 7200 s, and §9 names
six hours as the length of a large scope. Raise it for a long scope; crossing it is reported as
a failure, not a success, so a Job restarts in front of a run that is still going.

## 5. Running it

```sh
# Build from the repository ROOT — the image needs the CLI, not just this directory.
docker build -f deploy/relay/Dockerfile -t ascend-relay:1.1.4 .

# Fargate and most clusters are x86_64; this machine built arm64 by default.
docker build --platform linux/amd64 -f deploy/relay/Dockerfile -t ascend-relay:1.1.4 .
```

Locally, against a real assessment:

```sh
docker run --rm --read-only \
  --tmpfs /var/lib/ascend/state:uid=10001,gid=10001,mode=0700 \
  --tmpfs /var/lib/ascend/work:uid=10001,gid=10001,mode=0700 \
  -e STRAIKER_BRIDGE_API_KEY="$STRAIKER_BRIDGE_API_KEY" \
  -e STRAIKER_PAT="$STRAIKER_PAT" \
  -e ASCEND_RELAY_APP_ID=aapp_… \
  -e ASCEND_ASSESSMENT_ID=asmt_… \
  -e ASCEND_RELAY_CONFIG_JSON="$(cat target.json)" \
  ascend-relay:1.1.4
```

The read-only root filesystem is not decoration — it was measured: with `--read-only` and those
two tmpfs mounts the container served 60 probes and exited 0 at 121 s.

Three task definitions are next to this file. Each is minimal on purpose, because a security
team reads them before running them:

* `ecs-task-definition.json` — Fargate. **The only one of the three with no orchestrator-side
  ceiling**: ECS has no task timeout, so `$ASCEND_RELAY_DEADLINE_S` (§4.1) is the only thing
  bounding a run whose stop condition never fires. `readonlyRootFilesystem: true` with two named volumes
  (Fargate does not support `linuxParameters.tmpfs`, so a writable path comes from a volume
  rather than a tmpfs mount). Credentials via `secrets` → Secrets Manager. `stopTimeout: 120`,
  because an in-flight lease long-poll is not interruptible and a clean stop can take up to
  about `wait_ms + 10` seconds.
* `cloud-run-job.yaml` — a Job, not a Service. A Service scales on request traffic and the
  relay takes none; it would also scale to zero between requests, which for this workload means
  "stops leasing".
* `k8s-job.yaml` — a Job, not a Deployment. A Deployment would restart the relay forever after
  its assessment finished, which is the "bills the customer forever" failure this directory
  removes. `restartPolicy: OnFailure`, `terminationGracePeriodSeconds: 60`.

In all three, the per-run values (`ASCEND_RELAY_APP_ID`, `ASCEND_ASSESSMENT_ID`) are meant to be
overridden at launch — `aws ecs run-task --overrides`, `gcloud run jobs execute
--update-env-vars`, a templated Job — not edited into the file for every assessment.

## 6. What it costs

**Resources.** Measured with `docker stats` while the relay served ~3 probes/s against a local
target, sampled eight times over 45 s: **1.4 % – 2.4 %** of one core and **~60 MiB** resident,
flat. The task definitions ask for 0.25 vCPU / 512 MiB, which is headroom rather than a
requirement.

**Image.** Sum of layer sizes 168.2 MB, of which this image adds ~8.5 MB to `python:3.12-slim`
(6.08 MB of pip, 2.4 MB of code). `docker save` produces a 43 MiB tarball, on both `arm64` and
`amd64`.

**Network.** Two outbound flows, both HTTPS, both initiated by the container:

* the lease long-poll — one request per `wait_ms` when the queue is empty (25 s by default), one
  per probe batch when it is not;
* the control-plane poll — the heartbeat beats every 10 s and reconciles every third beat.
  Measured: 3 `GET …/assessments` in the first 61 s, converging to one per 30 s.

**Money.** Deliberately not priced here. The shape is: one small task for the length of one
assessment, at 0.25 vCPU / 0.5 GB, which on Fargate is `(0.25 × vCPU-hour rate + 0.5 ×
GB-hour rate) × hours`. Substitute your region's published rate; this session had no AWS
credentials and did not look one up, and a price quoted from memory is the kind of number that
turns out to be wrong in front of a customer.

**When it stops.** Measured in the built image, real graces, no compression:

```
t+0     container starts, relay leasing
t+20s   the bound assessment flips to `completed`
t+122s  container exits 0 — 60 probes leased, answered and delivered
```

The 120 s floor is `_STARTUP_GRACE_S` in `shells/cli/ascend.py`: a relay never self-stops within
two minutes of starting, because of the ensure-before-create path where the relay comes up
before its assessment exists. After that floor, a run that goes terminal is picked up at the
next reconcile (≤ 30 s) plus `_TERMINATION_GRACE_S` (90 s) plus the in-flight lease drain — so
worst case is roughly **145 s** from the run ending to the container exiting. That grace is
deliberate: a gap between recon rounds is indistinguishable from a finished run, and stopping
early leaves probes unanswered, which is a false pass.

## 7. The one thing this cannot fix

**A dead relay still reports a clean run**, and no container can change that, because the
platform has nowhere to say otherwise.

Measured on prod tenant 123, 2026-09-20 —
`GET /api/v3/ascend/applications/{app}/assessments/{aid}` on a `running` run returns exactly ten
fields:

```
application_id, category_summary, created_at, id, name, object, progress, status, total, type
```

Searched for `relay`, `bridge`, `lease`, `consumer`, `heartbeat`, `connected`, `answered`,
`unanswered`, `probes_sent`: **none present**. `status` was `running`, `progress` `0.0161`,
`total` `3`.

So the container can prove to *itself* that the relay stopped early — that is what its exit code
is — but it cannot tell the platform, and the platform will not tell anyone else. An operator
reading the Console, or an agent reading the API, sees a run that completed.

### Ask — relay liveness on the assessment

> **(S1) A relay that has stopped leasing is invisible on the assessment it was serving.**
>
> **Measured 2026-09-20**, prod tenant 123. The assessment object exposes ten fields while
> running and not one of them is about the relay. A container that runs the relay can detect its
> own death locally — `deploy/relay/entrypoint.py` exits non-zero on it — but it has no way to
> record that against the run, so a Console user and an API client both see a run that completed
> normally. The CLI has carried a local version of this check since the beginning
> (`supervisor.is_serving()` treats a stale heartbeat as not-serving, explicitly "so the
> auto-lifecycle never reuses a bridge that stopped answering — a false pass"), which is the
> same judgement made in the only place that cannot publish it.
>
> **Cost.** Every bridge-type assessment carries an unfalsifiable claim. "Clean" and "nobody was
> listening" are the same result, and the second is the more likely one on a laptop relay: the
> operating workaround for keeping one alive is `caffeinate -dims &`. Customers act on these
> reports.
>
> **Ask.** `last_lease_at` on the running assessment, set by the lease service when a consumer
> leases for that run. Nothing more is needed: a client can compare it to now, and a run that
> reaches a terminal state having gone quiet for longer than the reclaim window can be marked
> rather than completed silently. A `relay_state` of `leasing | stale | never` is the nicer
> version of the same fact.
>
> **Same gap as B0 and G13.** G13 asks for `probes_sent` / `probes_answered` on the running
> object; B0 is runs that stall while still saying `running`. All three are one missing idea —
> *the platform does not publish whether work is actually moving* — and `probes_answered` alone
> would cover most of this ask, because a relay that has stopped leasing stops moving it.

(One correction to G13 while it is being read: it records 8 fields on a running assessment. On
2026-09-20 the same call returned 10 — `total` and `category_summary` have been added. The
substance is unchanged; nothing added is about liveness.)

## 8. Tests

```sh
python3 -B -m pytest tests/test_relay_container.py -q     # 50 tests, no sockets, ~6 s
python3 -B -m pytest deploy/relay/tests -q                # 5 tests, loopback socket, ~19 s
```

`tests/test_relay_container.py` runs with the main suite. It pins the preflight, the argv the
child is given, and every branch of the verdict, plus the whole spawn-and-judge path against a
stand-in CLI — no network, matching the suite's contract in `tests/conftest.py`.

`deploy/relay/tests/` is **not** collected by the main suite (`pytest.ini` sets
`testpaths = tests`, and `conftest.py` states "no sockets are opened"). It stands up a loopback
lease service, control plane and target, and runs the real entrypoint and the real CLI as child
processes: the container is proved to exit 0 when its bound assessment goes terminal, exit 1 on
a rejected key, and exit 3 on an unset `env:` reference without ever reaching the target. It
compresses two grace constants (120 s → 2 s, 90 s → 2 s) and the heartbeat sleep (10 s → 1 s) in
a wrapper that imports the real CLI module — never by editing the CLI. The uncompressed timing
was measured separately in the built image and is in §6.

Every behaviour above was mutation-checked: the behaviour was reverted in `entrypoint.py`, the
test that pins it was confirmed RED, and the file restored. **14 of 14 mutations went red**,
including "drop `--assessment-id`" (the stop condition never fires), "treat a missing heartbeat
as success", and "leave a previous attempt's heartbeat in place".

The stop-condition guard in §4.1 was added later, in review, and mutation-checked the same way —
including "the preflight is computed but not acted on", "`wait_for_relay` ignores the cap" and
"a rejected credential no longer refuses" — **13 of 13 red, after two survivors were fixed**.
Both survivors are worth recording, because they are the same mistake twice: a test that passes
on more than one branch proves neither. "SIGKILL the relay immediately instead of asking it to
stop" survived because every test checked only that the child ENDED, never that it was asked
first — so the drain that exists to stop a leased probe being stranded was unprotected. And
"delete the on-disk guard before `import api`" survived because the assertion looked for
`control/api.py` in the message, which is also in the message the OTHER branch prints. A third
mutation from that review is worth recording
because it survived at first: **replacing `missing = unresolved_env_refs(...)` with
`missing = []` in `main()` left all 33 offline tests GREEN.** The helper was unit-tested and the
`main()` wiring was not, so the whole `env:` gate — the thing that stops a relay leasing 23
probes it will answer none of — could have been deleted and shipped past CI, because the loopback
test that did catch it is not collected by `pytest` and is not in CI.
`test_an_unset_env_reference_refuses_in_main_not_just_in_the_helper` closes that, and the CI job
in the review notes closes the other half.

## 9. Never executed

Honest list. These are the steps this was written for and which nothing here proved:

1. **No image was pushed** to ECR, Artifact Registry or any other registry. The image was built
   for `linux/arm64` and `linux/amd64` and both were run locally; neither was pulled from a
   registry by anything.
2. **The ECS task definition was never registered and no Fargate task was ever run.** It passes
   the AWS CLI's client-side parameter validation — `aws ecs register-task-definition
   --cli-input-json` reaches authentication and fails there, and a deliberately bogus field
   fails earlier with `Parameter validation failed`, so the check has teeth — but that proves
   the shape, not the behaviour. Specifically unproven: that a named volume gives a writable
   path under `readonlyRootFilesystem: true` on Fargate, and that `stopTimeout: 120` leaves
   enough room for the lease drain in practice.
3. **The Cloud Run job YAML was never applied.** `gcloud` on this machine needs an interactive
   re-login (`gcloud run jobs list` returned "Reauthentication failed. cannot prompt during
   non-interactive execution"), so the file's structure — particularly the VPC-access
   annotations on `spec.template.metadata` — is from the documented Knative shape and has not
   been validated by the API.
4. **The Kubernetes Job was never applied.** `kubectl apply --dry-run=client` needs to reach a
   cluster for schema discovery and this machine has no reachable one ("the server has asked for
   the client to provide credentials"). The YAML parses and the fields were checked by hand.
5. **No run against the real lease service.** Every relay run here leased from a stand-in on
   loopback. Nothing was created, started or modified on the platform; the prod traffic was
   read-only v3 GETs on tenant 123 plus the `tc-` key 401 in §4.
6. **No long run.** The longest measured container lifetime was 122 s. Nothing here says what
   happens over the six hours a large scope actually takes — including whether the 21600 s
   default in §4.1 is the right ceiling, which is why it is a variable and not a constant.
7. **The stop-condition guard was never exercised against the real control plane.** The
   `rejected` branch — the one that exits 3 — was proved against a loopback control plane
   returning 401, never against prod refusing a real PAT. What WAS re-measured against prod
   tenant 123 on 2026-09-21 is the read itself: `GET /ascend/applications` returned 6 apps, and
   the detail of a `running` assessment returned the same ten keys listed in §7, with all nine
   liveness substrings still absent.
8. **The ECS task definition still has not been registered**, including with
   `ASCEND_RELAY_DEADLINE_S` added. It passes `aws ecs register-task-definition
   --cli-input-json` up to authentication (re-run 2026-09-21: `UnrecognizedClientException`),
   and a deliberately bogus field still fails earlier with `Parameter validation failed`, so the
   check still has teeth — but that is shape, not behaviour.

The **control-plane half was exercised against prod**, though, and is not on that list. A
container was run for 45 s with the real tenant-123 PAT and the default `ASCEND_CONTROL_BASE`
(its lease service still a stand-in, so no probes moved): the PAT exchange succeeded from inside
the image, the reconcile beat read the app's assessments with `reconcile_error: None`, and the
JWT cache landed at `/var/lib/ascend/state/<tenant-fingerprint>/jwt.json`. That last path is why
`read_status()` searches for the heartbeat rather than reading one fixed location — the state
directory really does grow tenant-fingerprint subdirectories beside `relays/`.
