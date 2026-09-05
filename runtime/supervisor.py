"""
supervisor.py — run and watch MANY relays, one per Ascend app.

A `tc-` key selects exactly one Ascend application server-side, so N apps means N relays. Each relay
runs as a **detached child process** rather than a thread, for reasons that are specific and load
bearing:

  * the CLI's SIGINT/SIGTERM handler closes over a single client — N in one process means N-1 never
    stop;
  * `logging.basicConfig` is global and first-call-wins, and the logger names carry no app identity,
    so N relays would interleave indistinguishable lines on one stderr;
  * `ConversationRouter` has no teardown, so each relay would leak an event loop, a thread, and
    cached adapters (including live Chromium);
  * a native adapter crash (Playwright/boto3) would take the whole fleet down.

Child processes dissolve all four, and give per-app logs for free.

Child contract:
  * the key is passed in the child's ENVIRONMENT (`STRAIKER_BRIDGE_API_KEY`) — NEVER on argv, which
    is world-readable through `ps`;
  * each child gets a unique `--consumer` (the bridge protocol requires parallel clients to differ);
  * cwd is inherited so `config_dir()` resolves identically;
  * the child writes `<state>/relays/<app_id>.json` heartbeats so the parent can report
    answered/failed counts it cannot otherwise see (stats live inside the child).
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
from typing import Any, Dict, List, Optional

import tenant as _tenant

REPO = Path(__file__).resolve().parent.parent
HEARTBEAT_STALE_S = 180.0        # no heartbeat for this long => "dead", not "serving"
STARTUP_GRACE_S = 3.0            # longest start() watches a fresh child for its first heartbeat or its death


def _startup_grace_s() -> float:
    """$ASCEND_STARTUP_GRACE_S overrides the startup watch (0 disables it) — for tests that spawn
    stand-in children, and for an operator whose relays legitimately take longer to say hello."""
    try:
        return float(os.environ.get("ASCEND_STARTUP_GRACE_S", STARTUP_GRACE_S))
    except ValueError:
        return STARTUP_GRACE_S
STALE_REAP_S = 86_400.0          # a relay dead this long is history, not state (see prune())


def relays_dir() -> Path:
    d = _tenant.state_root() / "relays"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _safe(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", str(name))


def paths_for(app_id: str) -> Dict[str, Path]:
    base = relays_dir()
    s = _safe(app_id)
    return {"pid": base / f"{s}.pid", "log": base / f"{s}.log", "status": base / f"{s}.json"}


def pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:      # exists, owned by someone else
        return True
    except (OSError, TypeError):
        return False


def read_status(app_id: str) -> Dict[str, Any]:
    try:
        return json.loads(paths_for(app_id)["status"].read_text())
    except (OSError, ValueError):
        return {}


def write_status(app_id: str, rec: Dict[str, Any]) -> None:
    p = paths_for(app_id)["status"]
    p.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(p), os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(rec, fh)


def read_pid(app_id: str) -> Optional[int]:
    try:
        return int(paths_for(app_id)["pid"].read_text().strip())
    except (OSError, ValueError):
        return None


def _write_pid(app_id: str, pid: int) -> None:
    p = paths_for(app_id)["pid"]
    fd = os.open(str(p), os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(str(pid))


def _clear(app_id: str) -> None:
    for k in ("pid",):
        try:
            paths_for(app_id)[k].unlink()
        except FileNotFoundError:
            pass


def is_running(app_id: str) -> bool:
    pid = read_pid(app_id)
    if pid is None:
        return False
    if pid_alive(pid):
        return True
    _clear(app_id)              # reap a stale pidfile
    return False


def _state_of(alive: bool, heartbeat_age_s: Optional[float]) -> str:
    """The single definition of relay liveness, shared by ls() and is_serving() so they can never
    disagree — the false-pass alarm and the auto-lifecycle both key off the word "serving"."""
    if not alive:
        return "dead"
    if heartbeat_age_s is not None and heartbeat_age_s > HEARTBEAT_STALE_S:
        return "stale"
    return "serving"


def is_serving(app_id: str) -> bool:
    """True iff a relay for this app is alive AND its heartbeat is fresh. Stricter than is_running()
    (which only checks pid liveness): a hung relay that stopped answering must count as NOT serving,
    or the auto-lifecycle would 'reuse' a dead bridge and leave probes unanswered (a false pass)."""
    pid = read_pid(app_id)
    alive = pid is not None and pid_alive(pid)
    if not alive:
        return False
    ts = (read_status(app_id) or {}).get("ts") or 0
    age = time.time() - ts if ts else None
    return _state_of(alive, age) == "serving"


def _unresolved_env_refs(config: str):
    """Every `env:NAME` in the config whose variable is absent from THIS process's environment.

    A relay inherits os.environ, so a config that authenticates by `env:` reference works only in
    a shell that exports it. Started from a shell that does not, the relay came up healthy and
    then got a 401 from the target on every single probe -- which scores as no findings, i.e. the
    exact false pass the whole design is meant to prevent. Refusing to start, and naming the
    variable, turns a silent wrong answer into an obvious one.
    """
    import json as _json
    import re as _re
    try:
        from configs import resolve_config_path
        path = resolve_config_path(config)
        if not path:
            return []
        blob = Path(path).read_text(encoding="utf-8")
    except Exception:
        return []
    names = sorted(set(_re.findall(r"env:([A-Za-z_][A-Za-z0-9_]*)", blob)))
    return [n for n in names if not os.environ.get(n)]


def start(app_id: str, *, config: str, adapter: Optional[str], api_key: str,
          qpm: Optional[int] = None, max_workers: Optional[int] = None,
          bridge_base: Optional[str] = None, wait_ms: Optional[int] = None,
          capture: Optional[str] = None, app_name: Optional[str] = None,
          assessment_id: Optional[str] = None, control_token: Optional[str] = None,
          control_base: Optional[str] = None, idle_timeout_s: Optional[int] = None,
          self_reconcile: bool = True, python: Optional[str] = None) -> Dict[str, Any]:
    """Spawn a detached relay for one app. Returns {app_id, pid, log} or {error}.

    When self_reconcile is on, the child polls its app's assessment state and self-stops when the app
    goes terminal (or, if paused, after idle_timeout_s). To do that the child needs to reach the
    control plane, so the operator's token/base are injected into the child ENV (never argv)."""
    if is_running(app_id):
        return {"app_id": app_id, "error": "a relay is already running for this app",
                "pid": read_pid(app_id)}
    missing = _unresolved_env_refs(config)
    if missing:
        names = ", ".join(missing)
        return {"app_id": app_id, "error": (
            f"config {config!r} authenticates by environment reference, but "
            f"{'these variables are' if len(missing) > 1 else 'this variable is'} not set in this "
            f"shell: {names}. The relay would start and then be refused by the target on every "
            f"probe, which scores as a clean run that measured nothing. "
            f"Export {'them' if len(missing) > 1 else 'it'} and start again."),
            "missing_env": missing}
    # Resolve the config HERE, in the operator's shell, and hand the child an ABSOLUTE path.
    # The child is spawned with cwd=REPO (below) while `config_dirs()` searches `Path.cwd()/configs`
    # first -- so a bare name the operator can resolve is invisible to the relay. That split is not
    # theoretical: `target add --save-as x` WRITES to ./configs when that directory exists, so any
    # operator who keeps a configs/ dir in their working directory got a config every foreground
    # command could read and the relay could not. It surfaced as `relay exited at startup (code 3)`
    # naming a path in ~/.ascend/configs the operator never chose, the platform pausing the run,
    # and "probes will go unanswered" -- a false pass in waiting.
    cfg_for_child = config
    _inline = str(config).lstrip().startswith("{")      # inline JSON: nothing to resolve
    try:
        from configs import resolve_config_path, config_dirs
        _resolved = None if _inline else resolve_config_path(config)
        if _resolved:
            cfg_for_child = str(_resolved)
        elif not _inline:
            _where = ", ".join(str(d) for d in config_dirs())
            return {"app_id": app_id, "error": (
                f"config {config!r} not found, so the relay was not started. Looked in: {_where}. "
                f"The relay runs from the CLI's own directory and cannot see a config that exists "
                f"only relative to this shell -- pass a path to it, or save it under "
                f"~/.ascend/configs.")}
    except ImportError:
        pass                                   # resolver unavailable: pass the reference through

    p = paths_for(app_id)
    argv = [python or sys.executable, str(REPO / "shells" / "cli" / "ascend.py"),
            "runtime", "start", "--config", cfg_for_child,
            # a unique consumer per child: the bridge protocol requires parallel clients to differ
            "--consumer", f"abv2-{_safe(app_id)}"]
    if adapter:
        argv += ["--adapter", adapter]
    if qpm:
        argv += ["--qpm", str(qpm)]
    if max_workers:
        argv += ["--max-workers", str(max_workers)]
    if bridge_base:
        argv += ["--bridge-base", bridge_base]
    if wait_ms:
        argv += ["--wait-ms", str(wait_ms)]
    if capture:
        argv += ["--capture", capture]
    if assessment_id:                                 # id is not a secret — argv is fine
        argv += ["--assessment-id", assessment_id]
    if idle_timeout_s is not None:
        argv += ["--idle-timeout", str(idle_timeout_s)]
    if not self_reconcile:
        argv += ["--no-self-reconcile"]
    argv += ["--status-file", str(p["status"]), "--log-file", str(p["log"])]

    env = dict(os.environ)
    env["STRAIKER_BRIDGE_API_KEY"] = api_key      # key via ENV, never argv (ps is world-readable)
    env["ASCEND_RELAY_APP_ID"] = app_id
    # The control token/base let the detached child poll assessment state to self-reconcile. Same
    # rule as the bridge key: token via ENV, never argv.
    if control_token:
        env["STRAIKER_PAT"] = control_token
    if control_base:
        env["ASCEND_CONTROL_BASE"] = control_base
    log_fd = os.open(str(p["log"]), os.O_CREAT | os.O_WRONLY | os.O_APPEND, 0o600)
    try:
        proc = subprocess.Popen(argv, stdout=log_fd, stderr=subprocess.STDOUT,
                                stdin=subprocess.DEVNULL, env=env, cwd=str(REPO),
                                start_new_session=True)   # survives the parent terminal
    finally:
        os.close(log_fd)
    _write_pid(app_id, proc.pid)
    write_status(app_id, {"app_id": app_id, "app_name": app_name, "config": config,
                          "adapter": adapter, "pid": proc.pid, "state": "starting",
                          "assessment_id": assessment_id, "asmt_status": None,
                          "started_at": time.time(), "ts": time.time(), "stats": {}})
    # A relay that dies at startup — a config that does not exist, an adapter that fails to
    # import, a key of the wrong shape — used to be reported "started" with a pid; the operator
    # learned otherwise from an empty `bridge ls`, or from a run that scored clean having asked
    # nobody. Give it a moment and look.
    deadline = time.time() + _startup_grace_s()
    while time.time() < deadline:
        if proc.poll() is not None:
            _clear(app_id)
            return {"app_id": app_id, "log": str(p["log"]),
                    "error": f"relay exited at startup (code {proc.returncode}): {_log_tail(p['log'])}"}
        st = read_status(app_id) or {}
        if st.get("pid") == proc.pid and st.get("state") in ("serving", "fatal"):
            break                                   # the child's first heartbeat: it is up
        time.sleep(0.1)
    return {"app_id": app_id, "pid": proc.pid, "log": str(p["log"])}


def _log_tail(path) -> str:
    """The last non-empty line of a relay log — the `error:` line, when there is one."""
    try:
        lines = [l.strip() for l in Path(path).read_text(errors="replace").splitlines() if l.strip()]
        return lines[-1][:200] if lines else "(no log output)"
    except OSError:
        return "(log unreadable)"


def stop(app_id: str, *, grace_s: float = 8.0) -> Dict[str, Any]:
    """SIGTERM, then SIGKILL after a grace period.

    Note: an in-flight lease long-poll is not interruptible, so a clean exit can take up to
    ~(wait_ms + 10)s. We report honestly rather than claim an instant stop.
    """
    pid = read_pid(app_id)
    if pid is None:
        return {"app_id": app_id, "stopped": False, "reason": "no relay recorded"}
    if not pid_alive(pid):
        _clear(app_id)
        return {"app_id": app_id, "stopped": False, "reason": "was not running (stale pidfile reaped)"}
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError as e:
        return {"app_id": app_id, "stopped": False, "reason": f"{e}"}
    deadline = time.time() + grace_s
    while time.time() < deadline:
        if not pid_alive(pid):
            _clear(app_id)
            return {"app_id": app_id, "stopped": True, "pid": pid, "how": "SIGTERM"}
        time.sleep(0.25)
    try:
        os.kill(pid, signal.SIGKILL)
    except OSError:
        pass
    _clear(app_id)
    return {"app_id": app_id, "stopped": True, "pid": pid, "how": "SIGKILL (was draining a lease)"}


def forget(app_id: str) -> bool:
    """Drop every state file for one app's relay — after the app itself was deleted. Refuses while
    the relay is alive: forgetting a running relay would orphan it. Returns whether anything went."""
    if is_running(app_id):
        return False
    gone = False
    for k, path in paths_for(app_id).items():
        try:
            path.unlink()
            gone = True
        except FileNotFoundError:
            pass
    return gone


def prune(max_age_s: float = STALE_REAP_S) -> List[str]:
    """Drop state for relays that are dead AND long past their last heartbeat.

    Relay state otherwise accumulates forever: every app ever served leaves pid/status/log files
    behind, so `bridge ls` fills up with long-dead entries (one was still being listed 173 hours
    after it died) and a relay that is genuinely wrong gets lost in the noise. A recently-dead relay
    is kept, because that is exactly what someone triaging a failure needs to see. Logs are the
    diagnostics and are never removed here — only the pid/status files that make a corpse look like
    an entry.
    """
    removed: List[str] = []
    now = time.time()
    for status_file in sorted(relays_dir().glob("*.json")):
        app_id = status_file.stem
        pid = read_pid(app_id)
        if pid is not None and pid_alive(pid):
            continue                                   # live relay
        ts = (read_status(app_id) or {}).get("ts") or 0
        if ts and (now - ts) < max_age_s:
            continue                                   # recently dead — keep it for triage
        for key in ("pid", "status"):
            try:
                paths_for(app_id)[key].unlink()
            except (FileNotFoundError, OSError):
                pass
        removed.append(app_id)
    return removed


def ls() -> List[Dict[str, Any]]:
    """Every relay this machine knows about, with liveness + last heartbeat stats."""
    prune()                       # long-dead corpses are not state; keep the list meaningful
    out: List[Dict[str, Any]] = []
    for pid_file in sorted(relays_dir().glob("*.pid")):
        app_id = pid_file.stem
        st = read_status(app_id) or {}
        app_id = st.get("app_id") or app_id
        pid = read_pid(app_id)
        alive = pid is not None and pid_alive(pid)
        ts = st.get("ts") or 0
        age = time.time() - ts if ts else None
        state = _state_of(alive, age)
        out.append({"app_id": app_id, "app_name": st.get("app_name"), "config": st.get("config"),
                    "pid": pid, "alive": alive, "state": state,
                    "started_at": st.get("started_at"), "heartbeat_age_s": age,
                    "assessment_id": st.get("assessment_id"), "asmt_status": st.get("asmt_status"),
                    "reconcile_error": st.get("reconcile_error"),
                    "stats": st.get("stats") or {}, "fatal_error": st.get("fatal_error"),
                    "log": str(paths_for(app_id)["log"])})
    return out
