#!/usr/bin/env python3
"""
entrypoint.py — the relay, as something a customer's orchestrator can run and trust.

WHY THIS EXISTS, in one sentence: `ascend runtime start` exits 0 when it fails.

Measured 2026-09-20 against the CLI at `direct-first-idempotent`, with a stand-in lease service
returning 401 (`deploy/relay/README.md` records the run):

    $ ascend runtime start --config tgt --bridge-base http://127.0.0.1:8971
    ERROR ascendbridge.lease: Ascend rejected this bridge key (HTTP 401) ...
    EXIT=0            <- 0.28s, exit code zero

On a laptop that is survivable, because a human is watching the terminal. In ECS, Cloud Run or a
Kubernetes Job it is the worst thing the process can do: the task goes `Succeeded`, nothing
restarts it, no alarm fires, and the assessment runs to `completed` having been answered by
nobody. Unanswered probes are not findings, so it reports CLEAN. That is the false pass this
whole layer exists to prevent, delivered by the exit code itself.

So this entrypoint's job is not to reimplement the relay. The relay is fine. Its job is to make
the CONTAINER's exit status mean what an orchestrator thinks it means:

    exit 0   the bound assessment reached a terminal state and this relay carried its probes
    exit 1   the relay stopped and that did NOT happen — for any reason, loudly, named;
             including "this container cut it off at its own deadline because the stop
             condition was never going to fire"
    exit 3   the environment is wrong; refused before the relay was started at all
             (3 is the CLI's own EXIT_USAGE, so the two agree)

Four things it adds on top of `runtime start`, each because of a measured gap:

  * **Every required variable is named at once, before anything starts.** A relay that starts and
    then cannot work is indistinguishable from a healthy one for the length of the run.

  * **`env:` references in the target config are resolved HERE.** `supervisor.start()` refuses to
    spawn a relay whose config references a variable the shell does not export, and explains why.
    Nothing on the `runtime start` path does. Measured: with `env:CUSTOMER_AGENT_TOKEN` unset the
    relay reported `ready — first lease OK`, leased 23 probes, called the target ZERO times and
    delivered 23 failures. Externally it looked alive the whole time.

  * **The verdict is read from the relay's own heartbeat**, not from the child's exit code, for
    the reason at the top of this file. `stopped-complete` in the status file is the one and only
    success — the CLI writes it from `_reconcile_step` when the BOUND assessment has been terminal
    for its grace period, which is the same fact a customer means by "the run finished".

  * **The stop condition is checked and then bounded.** `--assessment-id` stops the relay only
    when the control plane can be READ and the bound id is in the answer. Measured, with the
    graces compressed to 2s so a healthy container exits in ~6s: a 401 from the control plane
    left it serving at 40s having burned 190 probes, and a bound id absent from the response did
    the same at 189 — `state: serving`, `reconcile_error: null`, and no exit coming. So this
    makes one read with the PAT before spawning (a credential the server refuses exits 3 with
    nothing leased) and holds a wall-clock ceiling over the whole run. See the block above
    `deadline_s` for why that ceiling has to live here and not only in the orchestrator.

WHAT IT DOES NOT DO. It cannot tell the platform that a relay is alive, because the platform has
nowhere to put that. Measured on prod tenant 123 the same day: the detail view of a `running`
assessment returns exactly ten fields — application_id, category_summary, created_at, id, name,
object, progress, status, total, type — and not one of them mentions a relay, a lease, a consumer
or an answered count. So a relay that dies here still produces an assessment that completes
quietly. See the ask in README.md; it is the same gap as PLATFORM-ASKS.md B0/G13.

ON OUTPUT. Container logs are not a TTY, and both `runtime/ui.py` and the agent's `client/ui.py`
turn themselves off in exactly that case — going through either would emit the same bytes at the
cost of importing the CLI tree before this file has decided whether the environment is even
valid. So this prints plain, prefixed, greppable lines on stderr and nothing else.
"""
from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

EXIT_OK = 0        # bound assessment terminal AND this relay carried probes for it
EXIT_FAILED = 1    # the relay stopped without that being true
EXIT_CONFIG = 3    # refused before starting — matches the CLI's EXIT_USAGE

# Every variable that must be set, with the consequence of leaving it out. The consequence is the
# point: "STRAIKER_PAT is required" teaches nothing, "without it the container never exits" is
# the reason someone will remember at 2am.
REQUIRED = [
    ("STRAIKER_BRIDGE_API_KEY",
     "the app's relay credential (tc-...). Without it there is nothing to lease with."),
    ("ASCEND_RELAY_APP_ID",
     "the Ascend application this relay serves (aapp_...). The relay publishes its heartbeat "
     "under this id and polls this app's assessments; without it neither happens."),
    ("ASCEND_ASSESSMENT_ID",
     "the assessment this relay is being run for (asmt_.../uuid). Read the CLI's "
     "_reconcile_decision: with no BOUND run it returns 'serve' forever by design, so a "
     "container without this one NEVER EXITS and bills until someone notices."),
    ("STRAIKER_PAT",
     "a Straiker PAT (s6r_pat_...) that can read this app's assessments. The relay's own tc- key "
     "cannot: measured against prod, a tc- key on GET /api/v3/ascend/applications/{id}/assessments "
     "returns HTTP 401. Without a PAT the relay cannot see its run finish, so again: never exits."),
]

CONFIG_VARS = ("ASCEND_RELAY_CONFIG_JSON", "ASCEND_RELAY_CONFIG_FILE")


def log(msg: str) -> None:
    """One line, stderr, prefixed and timestamped. See ON OUTPUT in the module docstring."""
    print(f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} relay: {msg}",
          file=sys.stderr, flush=True)


def _safe(name: str) -> str:
    """The filename the relay's status file gets. Copied from supervisor._safe deliberately: the
    two must agree or the verdict reads the wrong file (or none), and a missing status file is
    reported as a failure — so a drift here would turn every healthy run red."""
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", str(name))


# --------------------------------------------------------------------------- preflight
def env_problems(env: Dict[str, str]) -> List[str]:
    """Everything wrong with this environment, as human sentences. Empty list = good to start.

    ALL of them, not the first: an orchestrator retries a container on a fixed backoff, so
    reporting one missing variable per attempt costs the operator one deploy cycle each. The
    CLI's own supervisor.start() names every unresolved variable in one message for the same
    reason; this is that rule applied to the container's environment as a whole.
    """
    problems: List[str] = []
    for name, why in REQUIRED:
        if not (env.get(name) or "").strip():
            problems.append(f"${name} is not set — {why}")
    present = [v for v in CONFIG_VARS if (env.get(v) or "").strip()]
    if not present:
        problems.append(
            f"neither ${CONFIG_VARS[0]} nor ${CONFIG_VARS[1]} is set — the relay has no target "
            f"to call. Pass the adapter config inline as JSON, or mount it and give the path.")
    elif len(present) > 1:
        problems.append(
            f"both ${CONFIG_VARS[0]} and ${CONFIG_VARS[1]} are set. Refusing to guess which "
            f"target you meant: a relay pointed at the wrong agent produces a real-looking "
            f"assessment of something nobody asked about.")
    key = (env.get("STRAIKER_BRIDGE_API_KEY") or "").strip()
    if key and not key.startswith("tc"):
        # Not fatal on its own — the shape could change — but it is almost always a PAT pasted
        # into the wrong variable, which costs a 401 and a whole silent run to discover.
        problems.append(
            "$STRAIKER_BRIDGE_API_KEY does not look like a relay key (tc-...). The lease service "
            "rejects anything else with a 401, and the CLI exits 0 when it does.")
    return problems


def unresolved_env_refs(config_text: str, env: Dict[str, str]) -> List[str]:
    """Every `env:NAME` in the config text whose variable is absent from THIS environment.

    Lifted from supervisor._unresolved_env_refs, which exists because a relay started from a
    shell that did not export the variable came up healthy and then got a 401 from the TARGET on
    every probe — no findings, i.e. a clean run that measured nothing. supervisor.start() refuses
    to spawn in that state; `runtime start`, which is what a container runs, does not check at
    all. Measured on this repo: config with `env:CUSTOMER_AGENT_TOKEN` unset -> relay logs
    "ready — first lease OK", leases 23 probes, makes 0 calls to the target, delivers 23
    failures. Refusing here is the difference between a loud container and a quiet lie.

    Text, not parsed JSON, on purpose: a reference can appear anywhere in the structure
    (`auth.value`, a header, a `value_ref`), and this only needs to know the names.
    """
    names = sorted(set(re.findall(r"env:([A-Za-z_][A-Za-z0-9_]*)", config_text or "")))
    return [n for n in names if not (env.get(n) or "").strip()]


def materialize_config(env: Dict[str, str], workdir: Path) -> Path:
    """Put the adapter config on disk and return its ABSOLUTE path.

    Inline JSON is written out rather than passed through, because the CLI cannot take it any
    other way: `configs.load_config` accepts a dict or a config REFERENCE, and a JSON string is
    treated as a filename. Measured — `--config '{"adapter":"direct_api",...}'` fails with
    `config not found`, having looked for a file whose name is the JSON.

    0600, like `_write_private` in the CLI: an adapter config carries the target's bearer token,
    cookie or session id whenever auth is inline rather than an `env:` reference.
    """
    inline = (env.get("ASCEND_RELAY_CONFIG_JSON") or "").strip()
    if inline:
        try:
            json.loads(inline)
        except ValueError as e:
            raise ValueError(f"$ASCEND_RELAY_CONFIG_JSON is not valid JSON: {e}")
        workdir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(workdir, 0o700)
        except OSError:
            pass
        path = workdir / "target.json"
        fd = os.open(str(path), os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(inline)
        return path
    path = Path(env["ASCEND_RELAY_CONFIG_FILE"]).expanduser()
    if not path.is_file():
        raise ValueError(
            f"$ASCEND_RELAY_CONFIG_FILE points at {path}, which is not a file in this container. "
            f"A volume that did not mount looks exactly like this.")
    return path.resolve()


def build_argv(env: Dict[str, str], config_path: Path) -> List[str]:
    """The exact `runtime start` invocation, worked out from supervisor.start()'s own spawn.

    Same shape as the detached child the CLI runs on a laptop, and for the same reasons:

      * the relay key goes in the ENVIRONMENT, never on argv — `ps` is world-readable, and in a
        container `ps` is also whatever a sidecar or an `ecs exec` session can see;
      * `--consumer` must be unique across relays leasing the same app, because the bridge
        protocol hands one probe to one consumer. Default matches supervisor's `abv2-<app_id>`
        so a container that REPLACES a laptop relay is indistinguishable to the platform;
      * `--assessment-id` is what binds the stop condition to one run. Without it the relay
        cannot prove anything finished and never stops — see REQUIRED above;
      * `--status-file` is a GATE, not a path. Measured: the CLI writes the heartbeat to
        `state_root()/relays/<app_id>.json` regardless of the value; the flag only forces the
        heartbeat thread to start for a relay whose id is not an `aapp_`. We pass an `aapp_` id
        so it would start anyway, and pass the flag too so the behaviour does not depend on the
        id's shape.
    """
    app_id = env["ASCEND_RELAY_APP_ID"]
    cli = env.get("ASCEND_CLI") or "/opt/ascend/shells/cli/ascend.py"
    argv = [sys.executable, cli, "runtime", "start",
            "--config", str(config_path),
            "--consumer", env.get("ASCEND_RELAY_CONSUMER") or f"abv2-{_safe(app_id)}",
            "--assessment-id", env["ASCEND_ASSESSMENT_ID"],
            "--status-file", str(status_path(env))]
    for flag, var in (("--adapter", "ASCEND_RELAY_ADAPTER"),
                      ("--qpm", "ASCEND_RELAY_QPM"),
                      ("--max-workers", "ASCEND_RELAY_MAX_WORKERS"),
                      ("--wait-ms", "ASCEND_RELAY_WAIT_MS"),
                      ("--conversation", "ASCEND_RELAY_CONVERSATION"),
                      ("--idle-timeout", "ASCEND_RELAY_IDLE_TIMEOUT"),
                      ("--capture", "ASCEND_RELAY_CAPTURE")):
        val = (env.get(var) or "").strip()
        if val:
            argv += [flag, val]
    if (env.get("STRAIKER_BRIDGE_URL") or "").strip():
        # `--bridge-base` is a GLOBAL flag, not a `runtime start` one, and it is accepted after
        # the verb because the globals parser is a parent of every subparser. Passed explicitly
        # rather than relying on the child inheriting $STRAIKER_BRIDGE_URL (which the CLI does
        # read) so that what the relay was pointed at is visible in the process list.
        argv += ["--bridge-base", env["STRAIKER_BRIDGE_URL"].strip()]
    return argv


def state_dir(env: Dict[str, str]) -> Path:
    return Path(env.get("ASCEND_STATE_DIR") or "/var/lib/ascend/state")


def status_path(env: Dict[str, str]) -> Path:
    return state_dir(env) / "relays" / f"{_safe(env['ASCEND_RELAY_APP_ID'])}.json"


def status_files(env: Dict[str, str]) -> List[Path]:
    """Every heartbeat this app could have, anywhere under the state directory.

    Searched rather than read from one path, because `tenant.state_root()` namespaces UNDER
    $ASCEND_STATE_DIR by tenant FINGERPRINT whenever a tenant is pinned. A container that has
    never run `ascend tenant` is not pinned, and measured, its heartbeat landed at
    `<state>/relays/<app_id>.json` with no fingerprint directory — but the same state directory
    demonstrably does grow those: after 45s against the real control plane the PAT's JWT cache
    appeared at `<state>/<fingerprint>/jwt.json`, beside `relays/`. Assuming one fixed path would
    mean a pinned container reads no heartbeat and reports every healthy run as a failure.

    Both the pre-flight wipe and the final verdict go through this one function on purpose: if
    they searched differently, a stale file the wipe missed is a file the verdict can believe.
    """
    want = f"{_safe(env['ASCEND_RELAY_APP_ID'])}.json"
    return [p for p in state_dir(env).rglob(want) if p.parent.name == "relays"]


def read_status(env: Dict[str, str]) -> Optional[Dict[str, Any]]:
    """The relay's last heartbeat, or None if it never wrote one."""
    hits = status_files(env)
    if not hits:
        return None
    try:
        newest = max(hits, key=lambda p: p.stat().st_mtime)
        return json.loads(newest.read_text())
    except (OSError, ValueError):
        # st_mtime is inside the try because rglob() lists a path and stat() reads it a moment
        # later: the relay rewrites its heartbeat every 10s and the CLI's write_status() does
        # O_TRUNC on the same inode, but a tenant re-pin can move the file between those two
        # calls. An unhandled OSError here would end the container on a traceback AFTER the run
        # finished, i.e. turn a successful assessment into an uninterpretable exit code.
        return None


# --------------------------------------------------------------------------- stop-condition guard
# How long this container may run before it stops itself, regardless of what the assessment is
# doing. NOT a measurement and not an estimate of how long an assessment takes — a ceiling.
#
# It exists because the stop condition is not self-sufficient. `--assessment-id` only stops the
# relay when the control plane can be READ and the bound id comes back in the list. Measured on
# this repo (graces compressed to 2s, so a healthy container exits in ~6s):
#
#   control plane returns 401          -> 40s, still serving, 190 probes burned, never exits
#   bound id absent from the response  -> 40s, still serving, 189 probes burned, never exits
#                                         and the heartbeat reads state=serving,
#                                         reconcile_error=null, asmt_status='completed'
#                                         (the CLI's _latest() fallback naming another run)
#
# `_reconcile_decision` is explicit about why: `if not control_ok: return "serve"` — it will
# never self-kill on an error it cannot interpret, because an unanswered probe is a false pass.
# That is right for the CLI and it means the CONTAINER has to carry the other half.
#
# k8s (`activeDeadlineSeconds`) and Cloud Run (`timeoutSeconds`) have this knob natively and the
# manifests here set it to 86400. ECS/Fargate has NO task timeout of any kind, and neither does
# `docker run`, so on the two paths README §5 documents first there is otherwise nothing at all.
# Even where the orchestrator does cut it off, it cuts without a verdict: the operator gets
# `DeadlineExceeded` and no sentence saying the stop condition never armed.
#
# 21600 (6h) is a deliberate over-estimate, chosen against two in-repo numbers rather than from
# memory: the CLI's own `AscendAPI.poll_assessment` gives up waiting for an assessment at 7200s,
# and README §9 names six hours as the length of a large scope. Nothing here has run an
# assessment anywhere near that — the longest measured container lifetime is 122s — which is
# exactly why it is an environment variable and why crossing it exits 1 rather than 0: an
# operator who needs longer raises it, and a Job that hits it gets restarted in front of a run
# that is still going.
DEFAULT_DEADLINE_S = 21600.0
DEFAULT_WAIT_MS = 25000        # the lease long-poll default, as documented in README §4


def deadline_s(env: Dict[str, str]) -> float:
    """The ceiling in seconds. 0 disables it, which is a choice an operator can make on k8s or
    Cloud Run where the orchestrator holds one anyway — and which on Fargate means nothing
    bounds this container at all."""
    raw = (env.get("ASCEND_RELAY_DEADLINE_S") or "").strip()
    if not raw:
        return DEFAULT_DEADLINE_S
    try:
        return max(0.0, float(raw))
    except ValueError:
        log(f"$ASCEND_RELAY_DEADLINE_S={raw!r} is not a number; using {DEFAULT_DEADLINE_S:.0f}s")
        return DEFAULT_DEADLINE_S


def drain_s(env: Dict[str, str]) -> float:
    """How long to let the relay finish stopping after we ask it to, before SIGKILL.

    Derived, not picked: an in-flight lease long-poll is not interruptible, so a clean stop takes
    up to about `wait_ms + 10`s — the same arithmetic behind `stopTimeout: 120` in
    ecs-task-definition.json and `terminationGracePeriodSeconds: 60` in k8s-job.yaml. Killing
    before that lands SIGKILL mid-probe, and a probe leased but never answered waits out the
    platform's reclaim window as an unanswered probe, which is a false pass.
    """
    try:
        wait_ms = float((env.get("ASCEND_RELAY_WAIT_MS") or "").strip() or DEFAULT_WAIT_MS)
    except ValueError:
        wait_ms = DEFAULT_WAIT_MS
    return wait_ms / 1000.0 + 10.0


def control_preflight_verdict(outcome: str, detail: str) -> Tuple[Optional[str], str]:
    """Should this container start, given what one read of the control plane returned?

    Split out as a pure function so every branch is tested without a socket. `outcome` is one of
    'ok' | 'rejected' | 'bound-missing' | 'unknown', and the return is (problem or None, note).

    The asymmetry is the design. Only `rejected` refuses, because it is the one answer that
    cannot be anything else: a credential the control plane will not accept now is a credential
    the reconcile beat will not get further with, and `_reconcile_decision` responds to that by
    serving forever. Everything else proceeds:

      * `bound-missing` does NOT refuse, because the CLI's own beat comments describe the
        ensure-before-create path where "the bridge is often started BEFORE its assessment
        exists". Refusing on it would break a legitimate launch order to catch a typo. It is
        loud, and the deadline above is what actually bounds it.
      * `unknown` — a timeout, a 500, an import that failed — proceeds, because a blip at t=0
        must not stop an assessment someone is waiting on. Refusing on what we could not read
        would be the same mistake `_reconcile_decision` refuses to make in the other direction.
    """
    if outcome == "rejected":
        return (f"the control plane rejected $STRAIKER_PAT for this application: {detail}. The "
                f"stop condition polls that endpoint every 30s and `_reconcile_decision` serves "
                f"forever on any answer it cannot read, so this container would lease probes "
                f"until something outside it intervened — and on Fargate nothing does.",
                "")
    if outcome == "bound-missing":
        return (None,
                f"WARNING: $ASCEND_ASSESSMENT_ID is not in this application's assessment list "
                f"({detail}). That is legitimate if the run has not been created yet, and it is "
                f"what a typo looks like. If it is a typo the relay will serve until the "
                f"deadline below and then exit non-zero.")
    if outcome == "unknown":
        return (None, f"NOTE: could not verify the stop condition before starting ({detail}). "
                      f"Continuing; the deadline is the backstop.")
    return (None, "")


def check_control(env: Dict[str, str], timeout_s: float = 10.0) -> Tuple[str, str]:
    """One read of `GET /ascend/applications/{app}/assessments` with the PAT, before spawning.

    Returns (outcome, detail) for control_preflight_verdict. Uses the CLI's own `control/api.py`
    client rather than a second HTTP path of its own: the PAT-to-JWT exchange, its on-disk cache
    and the 401-retry all live there, and a re-implementation that got the exchange wrong would
    refuse healthy containers — the most expensive possible bug in a preflight.

    Every failure mode here returns 'unknown'. It is a check, not a gate; the only thing it is
    allowed to do is refuse a credential the server has actually said no to.
    """
    cli = Path(env.get("ASCEND_CLI") or "/opt/ascend/shells/cli/ascend.py")
    root = cli.parent.parent.parent            # /opt/ascend/shells/cli/ascend.py -> /opt/ascend
    control = root / "control" / "api.py"
    if not control.is_file():
        # Checked on disk BEFORE importing, and this is not defensiveness. `import api` would
        # otherwise be satisfied by whatever `api` is already in sys.modules — and in the main
        # test suite there always is one, because tests/test_bridge_reconcile.py imports it. The
        # container would then be checked with a module the container does not ship, and an
        # offline test run would open a socket to prod, breaking the contract in
        # tests/conftest.py. No api.py beside the CLI we are about to run means no check.
        return "unknown", f"no control/api.py beside $ASCEND_CLI ({control})"
    try:
        sys.path.insert(0, str(control.parent))
        import api                              # noqa: PLC0415 — see docstring
        if Path(getattr(api, "__file__", "") or "").resolve() != control.resolve():
            return "unknown", f"an unrelated `api` module is already imported ({api.__file__})"
    except Exception as e:                      # noqa: BLE001
        return "unknown", f"{type(e).__name__}: {e}"
    client = None
    try:
        client = api.AscendAPI(token=env["STRAIKER_PAT"],
                               base=(env.get("ASCEND_CONTROL_BASE") or api.DEFAULT_BASE),
                               timeout=int(timeout_s))
        data = client._req("GET", f"/ascend/applications/{env['ASCEND_RELAY_APP_ID']}/assessments")
        # Both envelope keys, because `_assessments_for` in shells/cli/ascend.py unwraps
        # ("data", "assessments") and this must agree with it: the beat that decides when to
        # stop reads the list through THAT function, so a shape this one silently reads as empty
        # would report "your run is not there" about a run the relay can see perfectly well.
        rows = data
        if isinstance(data, dict):
            rows = data.get("data") or data.get("assessments") or []
        ids = [str(r.get("id")) for r in (rows or []) if isinstance(r, dict)]
        if env["ASCEND_ASSESSMENT_ID"] in ids:
            return "ok", f"{len(ids)} assessment(s) visible"
        return "bound-missing", f"{len(ids)} assessment(s) visible, none of them this one"
    except Exception as e:                      # noqa: BLE001
        msg = f"{type(e).__name__}: {e}"
        # The status code is only available as text — AscendAPIError formats it as
        # "GET /path -> 401: body" and carries no attribute. Matching the text is brittle, so it
        # is used ONLY to reach the refusing branch: anything it fails to recognise falls
        # through to 'unknown' and the container starts. A missed match costs a slower failure;
        # a false match would refuse a working container, which is why it is this way round.
        #
        # Two shapes, because there are two places the credential is judged. `_req` raises the
        # arrow form when the ENDPOINT refuses; `_bearer` raises "Token exchange failed (401)"
        # when the PAT itself is refused, before any endpoint is reached — and an expired PAT is
        # the likeliest way this fails in production, so missing that one would leave the
        # commonest immortal container uncaught.
        if any(s in msg for s in (" -> 401:", " -> 403:",
                                  "Token exchange failed (401)", "Token exchange failed (403)")):
            return "rejected", msg[:300]
        return "unknown", msg[:300]
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:                   # noqa: BLE001
                pass


# --------------------------------------------------------------------------- verdict
def verdict(status: Optional[Dict[str, Any]], child_rc: int,
            allow_no_traffic: bool = False, signalled: bool = False,
            timed_out: float = 0.0) -> Tuple[int, str]:
    """Turn what actually happened into an exit code and one sentence. Pure, so it is tested
    directly against every shape the heartbeat can hold.

    The ordering is the argument. Read it as: what would have to be true for this container to
    have done its job?

      1. The relay published a heartbeat at all. No file means it died before the first beat —
         a config the adapter would not load, a key the lease service refused (measured: 0.28s
         and exit 0), an import that failed. The child's own exit code cannot tell these apart
         from success, which is the entire reason this function exists.
      2. It stopped because its BOUND assessment went terminal. `stopped-complete` is written by
         the CLI's own `_reconcile_step` and means exactly that. Anything else — still `serving`
         when the process ended, `fatal`, `stopped-idle` — means the relay stopped first and the
         run outlived it. That is the dead-relay state, and a dead relay that exits 0 is how a
         clean-looking report gets made.
      3. It actually carried probes. A run can reach `completed` with this relay having leased
         nothing: started too late, or a second consumer took the work. `completed` plus
         `leased: 0` is a finished assessment that this container measured no part of, so it is
         not a success to report. $ASCEND_RELAY_ALLOW_NO_TRAFFIC=1 downgrades it to a warning for
         the deliberate case of a second relay attached to one app.

    `signalled` only changes wording, never the code. Someone who ran `kubectl delete` and then
    reads "the relay stopped while its assessment was still live" needs to be told those are the
    same event — otherwise the honest non-zero exit reads as a second, mysterious failure.

    `timed_out` is the deadline in seconds when THIS container stopped the relay rather than the
    other way round. It only replaces the wording of the still-live branch, because the exit code
    was already right: a relay that had to be cut off did not see its assessment finish. It
    matters that the sentence says so, though — "the relay stopped while its assessment was
    still live" would send the reader looking at the relay, and the fault is upstream of it.
    """
    cause = (" The orchestrator stopped this container; for an assessment that has not finished, "
             "that IS the dead-relay state, so it is reported as a failure rather than hidden."
             if signalled else "")
    if status is None:
        return EXIT_FAILED, (
            f"the relay never published a heartbeat (child exit {child_rc}). It died before it "
            f"could serve anything — check the log above for a rejected key, a config the "
            f"adapter refused, or a target it could not reach. NOTHING WAS MEASURED.")

    state = str(status.get("state") or "unknown")
    # The heartbeat is written on a 10s cadence, so these counts can lag the relay's own final
    # "stopped; stats=..." log line by up to one beat. Measured on a SIGTERM drain: the log said
    # leased=108, the last heartbeat said 96. They are the same run; use the log line for an
    # exact tally and these for the shape of it.
    stats = status.get("stats") or {}
    counts = (f"leased={stats.get('leased', 0)} answered={stats.get('answered', 0)} "
              f"delivered={stats.get('delivered', 0)} failed={stats.get('failed', 0)}")
    fatal = status.get("fatal_error")
    # `asmt_status` is a DISPLAY field and is not necessarily the bound run's. The CLI's beat
    # writes `cur or _latest(asmts)[0]` — when the bound id is not in the app's list yet, it
    # falls back to the newest assessment on that app. Measured against prod: bound to
    # `asmt_doesnotexist`, the heartbeat still read `asmt_status: running` from an unrelated
    # live run. The stop DECISION is correctly scoped to the bound id either way; only this
    # string can name someone else's run, which is why nothing below branches on it.
    asmt = status.get("asmt_status")

    if fatal:
        return EXIT_FAILED, f"the relay stopped on a fatal error: {fatal} ({counts})"

    if state != "stopped-complete":
        if int(stats.get("leased") or 0) == 0 and int(stats.get("empty_polls") or 0) == 0:
            # Zero probes AND zero empty polls means not one lease call ever succeeded — not "the
            # queue was quiet", which shows up as empty_polls climbing. Measured: a lease service
            # returning 401 puts the relay here in 30ms, and the heartbeat thread has usually
            # already written state='serving' with fatal_error null before the process dies, so
            # the fatal field cannot be relied on to say it. These two counters can.
            return EXIT_FAILED, (
                f"the relay never completed a single lease — the lease service refused it or "
                f"could not be reached, so it served nothing and stopped. The most common cause "
                f"is a relay key that is not this app's; the CLI's own log line above names the "
                f"HTTP status. Note that `ascend runtime start` EXITS 0 here, which is exactly "
                f"why this container does not. ({counts})")
        if state == "stopped-idle":
            return EXIT_FAILED, (
                f"the relay idle-stopped: its assessment was paused and quiet for the idle "
                f"timeout, so it gave up. A paused run is not a finished run — the platform "
                f"discards the pause reason (PLATFORM-ASKS B1), so look at the assessment "
                f"itself. ({counts})")
        if timed_out:
            return EXIT_FAILED, (
                f"this container stopped the relay at its own deadline of {timed_out:.0f}s, "
                f"with the assessment still reading {asmt!r}. The relay was working — it is the "
                f"STOP CONDITION that never fired. Measured causes, in the order to check them: "
                f"$ASCEND_ASSESSMENT_ID names a run the control plane does not return for this "
                f"app (a typo serves forever with reconcile_error null), the PAT cannot read "
                f"this app's assessments, or the run genuinely outlived the deadline — raise "
                f"$ASCEND_RELAY_DEADLINE_S if so. ({counts}){cause}")
        return EXIT_FAILED, (
            f"the relay stopped while its assessment was still live — last state {state!r}, "
            f"assessment {asmt!r}. Every probe issued after this moment went unanswered, and "
            f"unanswered probes are not findings: the run can still report CLEAN. ({counts})"
            f"{cause}")

    leased = int(stats.get("leased") or 0)
    answered = int(stats.get("answered") or 0)
    if leased == 0:
        msg = (f"the assessment reached {asmt!r} but this relay was never handed a single probe. "
               f"It measured no part of that run. ({counts})")
        if not allow_no_traffic:
            return EXIT_FAILED, msg
        return EXIT_OK, f"WARNING (ALLOW_NO_TRAFFIC set): {msg}"
    if answered == 0:
        msg = (f"the assessment reached {asmt!r}, and this relay failed every one of the "
               f"{leased} probes it was handed — the target answered none of them. Those probes "
               f"produced no findings, so the report understates the target. ({counts})")
        if not allow_no_traffic:
            return EXIT_FAILED, msg
        return EXIT_OK, f"WARNING (ALLOW_NO_TRAFFIC set): {msg}"

    return EXIT_OK, (f"assessment {asmt!r} reached a terminal state and this relay stopped itself. "
                     f"({counts})")


# --------------------------------------------------------------------------- run
def main() -> int:
    env = dict(os.environ)

    problems = env_problems(env)
    if problems:
        log("refusing to start — the container's environment is not usable:")
        for p in problems:
            log(f"  * {p}")
        log("nothing was started. See deploy/relay/README.md for the full variable list.")
        return EXIT_CONFIG

    workdir = Path(env.get("ASCEND_RELAY_WORKDIR") or "/var/lib/ascend/work")
    try:
        config_path = materialize_config(env, workdir)
    except ValueError as e:
        log(f"refusing to start — {e}")
        return EXIT_CONFIG

    try:
        config_text = config_path.read_text(encoding="utf-8")
    except OSError as e:
        log(f"refusing to start — cannot read the target config at {config_path}: {e}")
        return EXIT_CONFIG

    missing = unresolved_env_refs(config_text, env)
    if missing:
        names = ", ".join(missing)
        log(f"refusing to start — the target config authenticates by environment reference, but "
            f"{'these variables are' if len(missing) > 1 else 'this variable is'} not set in this "
            f"container: {names}")
        log("  The relay would start, report itself ready, and then be refused by the target on "
            "every probe — which scores as a clean run that measured nothing.")
        log("  Supply them the same way as the relay key: as secrets on the task, never baked "
            "into the image.")
        return EXIT_CONFIG

    # Ask the control plane once, with the PAT, whether the stop condition can fire at all. This
    # is the only check here that costs a network round trip, and it is worth it because the
    # thing it catches is unbounded: a rejected PAT does not stop the relay, it makes it
    # immortal. Refuses only on an answer the server actually gave; see
    # control_preflight_verdict for why nothing else does.
    outcome, detail = check_control(env)
    problem, note = control_preflight_verdict(outcome, detail)
    if problem:
        log(f"refusing to start — {problem}")
        log("  Nothing was started. No probes were leased, so the assessment is untouched.")
        return EXIT_CONFIG
    if note:
        log(note)

    # Wipe any heartbeat left by a previous attempt in the SAME container filesystem, so the
    # verdict cannot read a stale file and call this attempt a success. A Kubernetes Job with
    # restartPolicy: OnFailure restarts the container in place, which is exactly that case — and
    # a previous attempt's `stopped-complete` would otherwise make a relay that did nothing at
    # all exit 0. Every file the verdict would consider, not just the unpinned path.
    for stale in status_files(env):
        try:
            stale.unlink()
        except OSError:
            pass
    status_path(env).parent.mkdir(parents=True, exist_ok=True)

    cmd = build_argv(env, config_path)
    if not Path(cmd[1]).is_file():
        # Popen would raise FileNotFoundError here and the container would exit on a traceback
        # with a code nobody can interpret. This is the "someone rebuilt the image and moved the
        # CLI" case, and it is a configuration error like any other.
        log(f"refusing to start — no CLI at {cmd[1]}. The image puts it at "
            f"/opt/ascend/shells/cli/ascend.py; $ASCEND_CLI overrides that.")
        return EXIT_CONFIG
    log(f"app={env['ASCEND_RELAY_APP_ID']} assessment={env['ASCEND_ASSESSMENT_ID']} "
        f"config={config_path}")
    log(f"lease service: {env.get('STRAIKER_BRIDGE_URL') or 'https://ascendai-bridge.prod.straiker.ai (default)'}")
    log(f"control plane: {env.get('ASCEND_CONTROL_BASE') or 'https://api.prod.straiker.ai/api/v3 (default)'}")
    log("starting the relay. It stops itself when the assessment above reaches a terminal state; "
        "measured floor is ~120s from start, and up to ~145s after the run ends.")
    cap = deadline_s(env)
    log(f"deadline: {'none — nothing in this container bounds the run' if not cap else f'{cap:.0f}s'}"
        f" ($ASCEND_RELAY_DEADLINE_S)")

    # The key and the PAT are already in os.environ and are inherited. They are NEVER added to
    # argv above — same rule as supervisor.start(), for the same reason.
    proc = subprocess.Popen(cmd, env=env)
    signalled: List[int] = []

    def _forward(signum, _frame):
        # An orchestrator stopping the task (scale-in, spot reclaim, `kubectl delete`) must not
        # look like a finished run: forward the signal, let the relay drain its in-flight lease,
        # and then let verdict() judge what the heartbeat actually says. It will say the
        # assessment was still live, and this container will exit non-zero — which is correct,
        # and is what makes `restartPolicy: OnFailure` bring the relay back.
        signalled.append(signum)
        log(f"received signal {signum}; asking the relay to stop (an in-flight lease can take "
            f"up to ~{drain_s(env):.0f}s to drain)")
        try:
            proc.send_signal(signum)
        except OSError:
            pass

    # Saved and restored, because main() is also called in-process by
    # tests/test_relay_container.py. Left installed, `_forward` becomes that process's SIGINT
    # handler for the remaining ~2800 tests — Ctrl-C would signal a Popen that has already been
    # reaped and the run would carry on instead of stopping. Verified: without this,
    # signal.getsignal(SIGINT) is `_forward` after main() returns.
    previous = {}
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            previous[sig] = signal.signal(sig, _forward)
        except ValueError:
            # Not the main thread. The container always is; a caller that is not simply does not
            # get signal forwarding, which is better than refusing to run.
            pass
    try:
        rc, timed_out = wait_for_relay(proc, cap, drain_s(env))
    finally:
        for sig, handler in previous.items():
            try:
                signal.signal(sig, handler)
            except (ValueError, TypeError):
                pass
        # Never leave the relay behind. Measured on this machine: when the entrypoint was killed
        # while the relay was serving, the child was re-parented to init and kept leasing — one
        # of them was still long-polling a dead loopback lease service 33 minutes later. Inside a
        # container PID 1 dying takes the namespace with it, so this is belt and braces there;
        # it is not belt and braces for `pytest deploy/relay/tests`, which is how it was found.
        if proc.poll() is None:
            try:
                proc.kill()
                proc.wait(timeout=10)
            except Exception:                   # noqa: BLE001
                pass

    status = read_status(env)
    code, message = verdict(status, rc, allow_no_traffic=bool(
        (env.get("ASCEND_RELAY_ALLOW_NO_TRAFFIC") or "").strip()),
        signalled=bool(signalled), timed_out=timed_out)
    log(("OK: " if code == EXIT_OK else "FAILED: ") + message)
    return code


def wait_for_relay(proc, cap: float, drain: float) -> Tuple[int, float]:
    """Wait for the relay, but never past `cap`. Returns (child rc, deadline that fired or 0.0).

    On expiry it asks the relay to stop the same way an orchestrator would — SIGTERM first, so
    the in-flight lease drains and the heartbeat thread writes one last set of counters — and
    only kills if that does not land within `drain`. Killing straight away would leave probes
    leased and unanswered, which is the false pass this whole directory is about; it would also
    throw away the counters verdict() reads to say what the relay actually did.
    """
    if cap <= 0:
        return proc.wait(), 0.0
    try:
        return proc.wait(timeout=cap), 0.0
    except subprocess.TimeoutExpired:
        pass
    log(f"deadline: {cap:.0f}s reached and the bound assessment has not finished. Stopping the "
        f"relay. This is not the relay failing — it is the stop condition never firing.")
    try:
        proc.send_signal(signal.SIGTERM)
    except OSError:
        pass
    try:
        return proc.wait(timeout=drain), cap
    except subprocess.TimeoutExpired:
        log(f"the relay did not stop within {drain:.0f}s of SIGTERM; killing it. Any probe it "
            f"held is now unanswered and waits out the platform's reclaim window.")
        proc.kill()
        return proc.wait(), cap


if __name__ == "__main__":
    sys.exit(main())
