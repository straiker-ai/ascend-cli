"""
tunnel.py — the CLI's wrapper around `ascend-tunnel`, Straiker's open-source tunnel agent.

The agent runs on a machine inside the customer's network, dials OUT to Straiker over one HTTPS
connection, and Ascend reaches an app through it at https://<host>.tun.straiker.ai/<path>. It is an
L4 path: the agent splices bytes and sees only ciphertext. The bridge (supervisor.py) is the L7
path: it runs an adapter here and answers probes itself. The tunnel carries a connection; the bridge
carries a conversation.

What this module owns:

  * the rules the agent enforces on its allow list, mirrored so a bad entry is refused here, in the
    same words, before anything is spawned (parse_allow) — and the URL rule an app behind the
    tunnel must follow (url_rule);
  * the validator for a `_tunnel_agent_keys` entry (parse_key_line): the key types the engine
    accepts, and the agent id the agent derives from a key (sha256 of the wire blob, 8 hex — pinned
    by the agent's testdata/contract.json);
  * where the agent comes from — `ascend-tunnel` on PATH, else the published Docker image with the
    CLI's state directory mounted as its volume — and the exact argv for either (find_runner,
    build_argv). The Docker image inherits nothing, so HTTPS_PROXY / NO_PROXY are passed in by
    name; the PATH binary inherits them like any child;
  * the supervisor for a detached agent: pid, log and status files under the CLI's state dir, on
    the bridge supervisor's contract (start, stop, ls), plus the identity the agent printed on
    start, read back from its log.

Nothing here reads the agent's private key. It lives in the agent's state directory, and the only
thing the CLI ever asks about it is `ascend-tunnel key`, which prints the public half.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import ipaddress
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import tenant as _tenant
from supervisor import pid_alive, _safe, _startup_grace_s, _log_tail

BINARY = "ascend-tunnel"
# The published image, pinned by the digest of its multi-arch index (linux/amd64 + linux/arm64) so
# a re-pushed tag cannot change what runs here. MEASURED 2026-10-13 with `docker buildx imagetools
# inspect ghcr.io/straiker-ai/ascend-tunnel:0.1.2`; the tag stays in the reference for a human.
IMAGE_VERSION = "0.1.2"
IMAGE_DIGEST = "sha256:37ac60f6535d6686a2e561a9be199a9c1f6bf521d92725482f19d7822b2e141d"
IMAGE = f"ghcr.io/straiker-ai/ascend-tunnel:{IMAGE_VERSION}@{IMAGE_DIGEST}"
REPO_URL = "https://github.com/straiker-ai/ascend-tunnel"
CONTAINER_STATE_DIR = "/var/lib/ascend-tunnel"       # what the published image uses
CONTAINER_CA_FILE = "/etc/straiker/ca.pem"
TUNNEL_SUFFIX = "tun.straiker.ai"
DEFAULT_PORT = 443
# The agent's relay-side socket name is /run/t/<12-hex login slug>/<host>~<link>, and sun_path
# holds 107 bytes: 7 + 12 + 1 + len(host) + len("~N") <= 107, so 85 characters with one link
# (links 0-9), 84 with eleven or more (links 10-15). MEASURED 2026-10-13: the 0.1.2 binary refuses
# an 86-character host ("too long for a relay socket name"); the old cap of 97 let it through here
# to be refused there.
MAX_SOCKET_PATH = 107
SOCKET_DIR_LEN = len("/run/t/") + 12 + 1
MAX_HOST_LEN = MAX_SOCKET_PATH - SOCKET_DIR_LEN - len("~0")          # 85, at the default fanout
MAX_FANOUT = 16
KEY_FILE = "agent.key"      # the agent's private key, in its state directory (identity.KeyFile)
TEMPLATE_KEY = "_tunnel_agent_keys"
KEY_TYPES = ("ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384")
MAX_KEYS = 20
PROXY_VARS = ("HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "https_proxy", "http_proxy", "no_proxy")
CHECK_STATUSES = ("PASS", "FAIL", "WARN", "WAIT", "INFO")

# The Straiker side of the tunnel, per environment. The agent itself knows only prod; dev and stage
# are given to it as an explicit endpoint. A pinned host key is passed when one is published for
# the environment; until then the agent warns that the key is not pinned, which `check` shows.
#
# MEASURED 2026-10-13: the stage relay is `ascendai-bridge.stage.straiker.ai` (the `staging` name
# this table carried was NXDOMAIN, so every stage check failed at the dial). Its host key is the
# one the platform's tunnel chart publishes for stage; the fingerprint matches the live relay. Prod
# answers 403 at the WebSocket upgrade until the relay is switched on there (relay_not_enabled).
STAGE_HOST_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILdbcgnXLQ0PX4mltsX+dHYu3iV5dGIrtf3qTLuwswD6"
ENVIRONMENTS: Dict[str, Dict[str, Optional[str]]] = {
    "dev":   {"endpoint": "wss://ascendai-bridge.dev.straiker.ai/tunnel", "host_key": None},
    "stage": {"endpoint": "wss://ascendai-bridge.stage.straiker.ai/tunnel", "host_key": STAGE_HOST_KEY},
    "prod":  {"endpoint": "wss://ascendai-bridge.prod.straiker.ai/tunnel", "host_key": None},
}
DEFAULT_ENV = "prod"

# Where the agent comes from, in the order that works today. MEASURED 2026-10-13: the Homebrew tap,
# the winget manifest and the scoop bucket do not exist yet ("Repository not found"), so they are
# listed last and marked; the GitHub Releases archive, the Docker image and the deb/rpm do. The
# macOS archive binary is ad-hoc signed and not notarized, so Gatekeeper quarantines a download:
# the xattr step clears it, and Docker is the smoother path on macOS until it is notarized.
INSTALL_HINTS = [
    f"archive  {REPO_URL}/releases — ascend-tunnel_<version>_<os>_<arch>.tar.gz (one static binary);",
    "         verify: shasum -a 256 -c checksums.txt --ignore-missing   and   gh attestation verify "
    "ascend-tunnel_<version>_<os>_<arch>.tar.gz --repo straiker-ai/ascend-tunnel",
    "         macOS: the binary is ad-hoc signed (not notarized), so after extracting run "
    "`xattr -d com.apple.quarantine ./ascend-tunnel`; prefer Docker on macOS until it is notarized",
    f"Docker   docker pull {IMAGE}",
    f"Linux    the .deb / .rpm from {REPO_URL}/releases (installs a systemd service)",
    "brew     brew install straiker-ai/tap/ascend-tunnel        (when published)",
    "winget   winget install Straiker.AscendTunnel               (when published)",
    "scoop    scoop bucket add straiker https://github.com/straiker-ai/scoop-bucket && "
    "scoop install ascend-tunnel   (when published)",
]

# The URL rule, as the agent and the Console enforce it. Printed by `tunnel url`, so it is written
# once here rather than paraphrased per command.
URL_RULES = [
    f"the app's URL is https://<host>.{TUNNEL_SUFFIX}/<path>: the real host rides inside the name "
    "(http:// only for an app that speaks plain HTTP on port 80; wss:// for a WebSocket app)",
    "no port in the URL: the app's port lives in the agent's allow list (--allow host:port), "
    "one entry per host",
    "the host is a DNS name, never an IP address: the name is what the agent dials",
    "the agent's key must be listed on the app:  ascend app tunnel-keys <app> --add <key>",
]


class AllowError(ValueError):
    """An allow entry or a target the agent would refuse, in the agent's own words."""


class KeyLineError(ValueError):
    """A `_tunnel_agent_keys` entry the engine would refuse."""


# ----------------------------------------------------------------------------- environments
def default_env(base: Optional[str]) -> str:
    """The environment the control plane's base names (api.dev… -> dev), else prod.

    A key listed on a dev app is published to the dev side of the tunnel, so an agent dialling prod
    with it would wait forever. Following --base keeps the two on the same side by default."""
    host = (urlparse(base or "").hostname or "").lower()
    m = re.match(r"^[a-z0-9-]+\.(dev|staging|stage|prod)\.straiker\.ai$", host)
    if not m:
        return DEFAULT_ENV
    return {"staging": "stage"}.get(m.group(1), m.group(1))


def resolve_endpoint(env: str, endpoint: Optional[str] = None,
                     host_key: Optional[str] = None) -> Dict[str, Any]:
    """The endpoint and pinned host key for env, with explicit values winning over the table."""
    if env not in ENVIRONMENTS:
        raise ValueError(f"unknown environment {env!r}: one of {', '.join(ENVIRONMENTS)}")
    table = ENVIRONMENTS[env]
    ep = (endpoint or table["endpoint"] or "").strip()
    if not ep.startswith("wss://"):
        raise ValueError(f"the endpoint must be a wss:// URL, not {ep!r}")
    hk = (host_key or table["host_key"] or "").strip() or None
    if hk and len(hk.split()) < 2:
        raise ValueError("--host-key must be a public key line: <type> <base64>, e.g. ssh-ed25519 AAAA…")
    return {"env": env, "endpoint": ep, "host_key": hk,
            "host_key_source": ("flag" if host_key else "built-in" if hk else None)}


# ----------------------------------------------------------------------------- the allow list
_HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$")


def split_host_port(raw: str) -> Tuple[str, str]:
    """('host', 'port' or '') from host, host:port or [v6]:port. A bare IPv6 literal comes back
    whole, to be refused as an IP address rather than mis-split on its colons."""
    s = str(raw).strip()
    if s.startswith("["):
        host, _, rest = s[1:].partition("]")
        return host, (rest[1:] if rest.startswith(":") else "")
    if s.count(":") > 1:
        return s, ""
    host, _, port = s.partition(":")
    return host, port


def max_host_len(fanout: Optional[int] = None) -> int:
    """The longest host the relay-side socket name has room for at this fanout: the link index
    rides in the name (`~0` … `~15`), so a fanout above 10 costs one more character."""
    links = max(int(fanout or 1), 1)
    return MAX_SOCKET_PATH - SOCKET_DIR_LEN - len(f"~{links - 1}")


def check_fanout(value: Any) -> Optional[int]:
    """`--fanout` as the agent takes it (1-16), None when not given; ValueError in its words."""
    if value is None:
        return None
    try:
        n = int(str(value).strip())           # a whole number: the agent's flag is an int
    except (TypeError, ValueError):
        raise ValueError(f"fanout must be 1..{MAX_FANOUT}") from None
    if not 1 <= n <= MAX_FANOUT:
        raise ValueError(f"fanout must be 1..{MAX_FANOUT}")
    return n


def parse_allow(entries, fanout: Optional[int] = None) -> List[Dict[str, Any]]:
    """The agent's allow list, validated the way the agent validates it, plus the URL rule.

    Refuses, in order: an empty or malformed entry, a bad port, an IP literal (the host rides
    inside the tunnel name, and Straiker does not route an IP-literal name), a name that is
    already a tunnel name, a host the agent's own regex rejects, a host too long for the relay's
    socket name at this fanout, and a host listed twice (the tunnel name carries no port, so one
    host has one port).
    """
    out: List[Dict[str, Any]] = []
    seen: Dict[str, int] = {}
    cap = max_host_len(fanout)
    for i, raw in enumerate(list(entries or [])):
        s = str(raw).strip()
        if not s:
            raise AllowError(f"allow[{i}] is empty: give host or host:port")
        host, port = split_host_port(s)
        host = host.strip().lower().rstrip(".")
        if not host:
            raise AllowError(f"allow[{i}] must be host or host:port: {raw!r}")
        if port == "":
            p = DEFAULT_PORT
        else:
            try:
                p = int(port.strip())
            except ValueError:
                raise AllowError(f"allow[{i}] must be host or host:port: {raw!r}") from None
        if not 1 <= p <= 65535:
            raise AllowError(f"invalid forward {host}:{port}: the port must be 1-65535")
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            # The agent itself would dial an IPv4 literal; the platform refuses the name built
            # from it, so the refusal is Straiker's, said as such.
            raise AllowError(f"Straiker does not route an IP-literal tunnel name: the app's URL would "
                             f"be https://{host}.{TUNNEL_SUFFIX}/<path>, and the platform refuses an "
                             f"address in it (the agent would dial {host}; the name is what Straiker "
                             f"routes). Give the target's DNS name (one this machine resolves; "
                             f"/etc/hosts counts) and allow that name.")
        if host.endswith("." + TUNNEL_SUFFIX):
            raise AllowError(f"{host} is already a tunnel name: allow the real host "
                             f"({host[:-len(TUNNEL_SUFFIX) - 1]}), and use the tunnel name only as "
                             f"the app's URL")
        if not _HOST_RE.match(host):
            raise AllowError(f"invalid forward {host}:{p}: a host is letters, digits, dots and "
                             f"hyphens, and starts and ends with a letter or digit")
        if len(host) > cap:
            raise AllowError(f"host {host!r} is too long for the tunnel's socket name ({cap} characters at "
                             f"most{f' with --fanout {fanout}' if fanout and fanout > 10 else ''}; "
                             f"the agent refuses it too)")
        if host in seen:
            raise AllowError(f"one allow entry per host: the tunnel name carries no port, so "
                             f"{host} cannot be listed twice (ports {seen[host]} and {p})")
        seen[host] = p
        out.append({"host": host, "port": p, "entry": f"{host}:{p}", "app_url": app_url(host, p)})
    if not out:
        raise AllowError("allow must list at least one target: --allow host, or --allow host:port")
    return out


def app_url(host: str, port: int, ws: bool = False) -> str:
    """The URL an app reaches host:port at through the tunnel, before the app's own path. A tunnel
    name carries no port: plain HTTP on 80 is http (ws), anything else https (wss)."""
    scheme = ("ws" if ws else "http") + ("" if port == 80 else "s")
    return f"{scheme}://{host}.{TUNNEL_SUFFIX}"


def url_rule(target: str, path: Optional[str] = None) -> Dict[str, Any]:
    """The app's URL and the allow entry for a target given as host[:port] or as its real URL.

    A real URL may carry a port and a path: the port moves into the allow entry (the tunnel name
    never carries one) and the path stays on the URL. Refusals are the allow list's.
    """
    s = str(target).strip()
    ws, url_path, port, moved = False, "", "", False
    if "://" in s:
        u = urlparse(s)
        scheme = (u.scheme or "").lower()
        if scheme not in ("http", "https", "ws", "wss"):
            raise AllowError(f"{scheme or '?'}:// is not an http(s) or ws(s) URL: {s!r}")
        ws = scheme.startswith("ws")
        host = u.hostname or ""
        try:
            explicit = u.port
        except ValueError:
            raise AllowError(f"{s!r} has an invalid port") from None
        moved = explicit is not None
        port = str(explicit) if explicit else ("80" if scheme in ("http", "ws") else "443")
        url_path = (u.path or "") + (f"?{u.query}" if u.query else "")
    else:
        host, port = split_host_port(s)
    fwd = parse_allow([f"{host}:{port}" if port else host])[0]
    p = path if path is not None else url_path
    p = p.strip() if p else ""
    if p and not p.startswith("/"):
        p = "/" + p
    base = app_url(fwd["host"], fwd["port"], ws=ws)
    return {"host": fwd["host"], "port": fwd["port"], "allow": fwd["entry"],
            "scheme": base.split("://", 1)[0], "app_url": base,
            "url": base + (p or "/<path>"), "path": p or None, "websocket": ws,
            "port_moved": moved, "rules": list(URL_RULES)}


# ----------------------------------------------------------------------------- key lines
def _wire_type(raw: bytes) -> Optional[str]:
    """The key type an SSH public-key blob names in its first length-prefixed string."""
    if len(raw) < 4:
        return None
    n = int.from_bytes(raw[:4], "big")
    if n <= 0 or n > 64 or len(raw) < 4 + n:
        return None
    try:
        return raw[4:4 + n].decode("ascii")
    except UnicodeDecodeError:
        return None


def agent_id(blob: bytes) -> str:
    """The agent's id for a public key: sha256 of its wire blob, first 8 hex — the agent's rule."""
    return hashlib.sha256(blob).hexdigest()[:8]


def parse_key_line(line: Any) -> Dict[str, str]:
    """A `_tunnel_agent_keys` entry, validated: {type, blob, line, agent_id}.

    Accepts the full line (`ssh-ed25519 AAAA…`, as the docs show) and the bare base64 the agent's
    `key` prints (the type is inside it). The type is read from the key material itself and, when
    a prefix is given, must agree with it; only the types the engine accepts pass. A trailing
    comment is dropped. `line` is the self-describing form, `<type> <base64>`.
    """
    fields = str(line or "").split()
    if not fields:
        raise KeyLineError("the key is empty")
    if fields[0].startswith(("ssh-", "ecdsa-", "sk-")):
        prefix, blob = fields[0], (fields[1] if len(fields) > 1 else "")
    else:
        prefix, blob = None, fields[0]
    if not blob:
        raise KeyLineError(f"{prefix} names a type but carries no key material")
    try:
        raw = base64.b64decode(blob, validate=True)
    except (binascii.Error, ValueError):
        raise KeyLineError("the key material is not base64 (paste the whole line the agent "
                           "printed)") from None
    embedded = _wire_type(raw)
    if not embedded:
        raise KeyLineError("the key material is not an SSH public key")
    if prefix and prefix != embedded:
        raise KeyLineError(f"the line says {prefix} but the key material is {embedded}")
    if embedded not in KEY_TYPES:
        raise KeyLineError(f"{embedded} keys are not accepted: the engine takes "
                           f"{', '.join(KEY_TYPES)}")
    return {"type": embedded, "blob": blob, "line": f"{embedded} {blob}", "agent_id": agent_id(raw)}


def describe_keys(values: Any) -> List[Dict[str, Any]]:
    """Every entry of a stored `_tunnel_agent_keys` list, parsed where it can be, kept where it
    cannot (an entry the engine stored is not this command's to drop silently)."""
    out = []
    for v in (values if isinstance(values, list) else []):
        try:
            rec = parse_key_line(v)
            out.append({**rec, "stored": v, "valid": True})
        except KeyLineError as e:
            out.append({"stored": v, "line": str(v), "valid": False, "problem": str(e),
                        "type": None, "blob": None, "agent_id": None})
    return out


# ----------------------------------------------------------------------------- the runner
def _docker_ready(docker: str) -> Tuple[bool, str]:
    """Whether the docker CLI at `docker` reaches a daemon. The CLI alone proves nothing."""
    try:
        r = subprocess.run([docker, "version", "--format", "{{.Server.Version}}"],
                           capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired) as e:
        return False, f"docker did not answer ({e})"
    if r.returncode != 0:
        tail = (r.stderr or r.stdout or "").strip().splitlines()
        return False, "docker is installed but its daemon is not running" + \
            (f" ({tail[-1][:120]})" if tail else "")
    return True, ""


def find_runner(prefer: str = "auto", *, which=None, docker_ready=None
                ) -> Tuple[Optional[Dict[str, Any]], List[str]]:
    """Where the agent comes from: `ascend-tunnel` on PATH first, else the Docker image.

    Returns (runner, notes). notes says why each candidate was passed over, for the message when
    neither is available. `prefer` pins one of them ("binary" / "docker").
    """
    which = which or shutil.which
    docker_ready = docker_ready or _docker_ready
    notes: List[str] = []
    if prefer in ("auto", "binary"):
        p = which(BINARY)
        if p:
            return {"kind": "binary", "path": p, "label": f"{BINARY} at {p}"}, notes
        notes.append(f"{BINARY} is not on PATH")
    if prefer in ("auto", "docker"):
        d = which("docker")
        if not d:
            notes.append("docker is not installed")
        else:
            ok, why = docker_ready(d)
            if ok:
                return {"kind": "docker", "docker": d, "image": IMAGE,
                        "label": f"docker image {IMAGE}"}, notes
            notes.append(why)
    return None, notes


def no_runner_message(notes: List[str]) -> str:
    return (f"no way to run the tunnel agent: {'; '.join(notes)}.\n"
            f"  install it (one static binary, open source at {REPO_URL}):\n    "
            + "\n    ".join(INSTALL_HINTS))


def runner_public(runner: Dict[str, Any]) -> Dict[str, Any]:
    """The runner as reported: kind plus where it is, never the label prose."""
    return {k: v for k, v in runner.items() if k != "label"}


def ensure_image(runner: Dict[str, Any]) -> bool:
    """Pull the image when it is not present. Returns whether a pull happened. Raises RuntimeError
    with docker's last line when the pull fails — a detached start must not spend its startup
    window on a download it cannot see."""
    if runner.get("kind") != "docker":
        return False
    r = subprocess.run([runner["docker"], "image", "inspect", runner["image"]],
                       capture_output=True, text=True, timeout=30)
    if r.returncode == 0:
        return False
    r = subprocess.run([runner["docker"], "pull", runner["image"]],
                       capture_output=True, text=True, timeout=600)
    if r.returncode != 0:
        tail = (r.stderr or r.stdout or "").strip().splitlines()
        raise RuntimeError(f"docker pull {runner['image']} failed: "
                           f"{tail[-1][:200] if tail else 'no output'}")
    return True


def proxy_in_use() -> Optional[str]:
    """HTTPS_PROXY (or the lowercase form) with any password dropped, for the record."""
    raw = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
    if not raw:
        return None
    u = urlparse(raw if "://" in raw else f"http://{raw}")
    if u.username or u.password:
        return raw.replace(f"{u.username}:{u.password}@" if u.password else f"{u.username}@",
                           "redacted@", 1)
    return raw


def docker_notes(runner: Dict[str, Any], forwards: List[Dict[str, Any]]) -> List[str]:
    """What is different when the agent runs in a container, said before it matters."""
    if runner.get("kind") != "docker":
        return []
    notes = []
    loop = [f["host"] for f in forwards if f["host"] in ("localhost", "localhost.localdomain")]
    if loop:
        notes.append("localhost in --allow is the container's own loopback under Docker, not this "
                     "machine's. To reach an app on this machine allow host.docker.internal:<port> "
                     "(the app's URL is then https://host.docker.internal." + TUNNEL_SUFFIX + "/<path>).")
    proxy = proxy_in_use()
    if proxy:
        h = (urlparse(proxy if "://" in proxy else f"http://{proxy}").hostname or "").lower()
        if h in ("localhost", "127.0.0.1", "::1"):
            notes.append(f"HTTPS_PROXY names {h}, which inside the container is the container "
                         f"itself; point it at host.docker.internal instead.")
    return notes


def _agent_flags(verb: str, org, allow, endpoint, host_key, state_dir, ca_file,
                 fanout: Optional[int] = None) -> List[str]:
    """The agent's own flags, in a fixed order. `key` takes only its state directory."""
    if verb == "key":
        return ["--state-dir", state_dir] if state_dir else []
    flags = ["--org", str(org)]
    for e in allow or ():
        flags += ["--allow", e]
    if endpoint:
        flags += ["--relay", endpoint]
    if host_key:
        flags += ["--host-key", host_key]
    if state_dir:
        flags += ["--state-dir", state_dir]
    if ca_file:
        flags += ["--ca-file", ca_file]
    if fanout:
        flags += ["--fanout", str(int(fanout))]
    return flags


def build_argv(runner: Dict[str, Any], verb: str, *, org=None, allow=(), endpoint=None,
               host_key=None, state_dir=None, ca_file=None, container_name=None,
               fanout: Optional[int] = None) -> List[str]:
    """The exact command for `verb` (run | check | key) on either runner.

    Docker: the state directory is the container's volume at the image's own path, the container
    runs as this user so the key it writes there is this user's file, the proxy variables that
    are set here are passed in by name (the image inherits nothing), and host.docker.internal is
    mapped so an app on this machine stays reachable by that name.
    """
    sd = str(state_dir) if state_dir else None
    if runner["kind"] == "binary":
        return [runner["path"], verb] + _agent_flags(verb, org, allow, endpoint, host_key, sd, ca_file,
                                                     fanout)
    argv = [runner["docker"], "run", "--rm"]
    if container_name:
        argv += ["--name", container_name]
    if hasattr(os, "getuid"):
        argv += ["--user", f"{os.getuid()}:{os.getgid()}"]
    argv += ["-v", f"{sd}:{CONTAINER_STATE_DIR}", "--add-host=host.docker.internal:host-gateway"]
    for var in PROXY_VARS:
        if os.environ.get(var):
            argv += ["-e", var]
    if ca_file:
        argv += ["-v", f"{Path(ca_file).resolve()}:{CONTAINER_CA_FILE}:ro"]
    argv += [runner["image"], verb]
    return argv + _agent_flags(verb, org, allow, endpoint, host_key, CONTAINER_STATE_DIR,
                               CONTAINER_CA_FILE if ca_file else None, fanout)


def run_lines(argv: List[str], *, echo=None, timeout: float = 180.0) -> Tuple[int, List[str], str]:
    """Run the agent in the foreground and return (exit code, stdout lines, stderr). Lines are
    echoed to `echo` as they arrive, so a slow check is watched rather than waited for."""
    proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                            stdin=subprocess.DEVNULL, env=dict(os.environ))
    err_buf: List[str] = []

    def drain():
        try:
            err_buf.append(proc.stderr.read())
        except Exception:
            pass
    t = threading.Thread(target=drain, daemon=True)
    t.start()
    killer = threading.Timer(timeout, proc.kill)
    killer.daemon = True
    killer.start()
    lines: List[str] = []
    try:
        for line in proc.stdout:
            line = line.rstrip("\n")
            lines.append(line)
            if echo is not None:
                print(line, file=echo, flush=True)
        rc = proc.wait()
    finally:
        killer.cancel()
    t.join(timeout=5)
    return rc, lines, "".join(err_buf)


def parse_check_lines(lines: List[str]) -> Dict[str, Any]:
    """What the agent's `check` said: every status line, the key and app URLs it printed, and
    whether anything failed or the key is merely not listed yet (WAIT, the expected state before
    an app lists it)."""
    rows, key, aid, org, urls = [], None, None, None, []
    for ln in lines:
        m = re.match(r"^(PASS|FAIL|WARN|WAIT|INFO)\s+(.*)$", ln)
        if not m:
            continue
        status, text = m.group(1), m.group(2).strip()
        rows.append({"status": status, "text": text})
        if status != "INFO":
            continue
        mk = re.search(r"agent key \([^)]*\):\s*(\S+)", text)
        if mk:
            key = mk.group(1)
        mo = re.match(r"org (\S+), agent ([0-9a-f]{8})", text)
        if mo:
            org, aid = mo.group(1).rstrip(","), mo.group(2)
        mu = re.search(r"app URL for \S+:\s*(\S+?)/\.\.\.", text)
        if mu:
            urls.append(mu.group(1))
    counts = {s: sum(1 for r in rows if r["status"] == s) for s in CHECK_STATUSES}
    listed = any(r["status"] == "PASS" and "lists this agent's key" in r["text"] for r in rows)
    return {"lines": rows, "counts": counts, "failed": counts["FAIL"],
            "waiting": counts["WAIT"] > 0, "listed": listed, "key": key, "agent_id": aid,
            "org": org, "app_urls": urls}


_UPGRADE_STATUS = re.compile(r"expected handshake response status code 101 but got (\d{3})")


def relay_refusal(lines: List[str]) -> Optional[int]:
    """The HTTP status the relay answered the WebSocket upgrade with, read off the agent's FAIL
    line, or None when the relay line did not fail that way (a timeout, a resolver miss, a PASS).
    The agent's wording (internal/agent/check.go + coder/websocket):
    `FAIL  relay WebSocket: relay wss://…: failed to WebSocket dial: expected handshake response
    status code 101 but got 403 (…)`."""
    for ln in lines or []:
        if not ln.startswith("FAIL") or "relay WebSocket" not in ln:
            continue
        m = _UPGRADE_STATUS.search(ln)
        if m:
            return int(m.group(1))
    return None


def relay_not_enabled(env: str, lines: List[str]) -> Optional[str]:
    """Why a prod check failed at the relay when it is not the operator's network: the tunnel is
    not switched on in that environment yet (MEASURED 2026-10-13: prod answers 403 at the
    upgrade; the platform's prod values have the tunnel off). None for any other env or code, so
    a real proxy or firewall problem keeps the generic hint."""
    if env != "prod" or relay_refusal(lines) != 403:
        return None
    return ("the tunnel is not enabled on this environment yet: Straiker's prod endpoint answered 403 "
            "at the WebSocket upgrade. Nothing on this machine or network is wrong, and no proxy "
            "setting changes it. Use --env stage (or dev) for now, or ask support@straiker.ai when "
            "prod is switched on.")


def key_from_output(stdout: str) -> Optional[str]:
    """The key `ascend-tunnel key` printed: its first non-empty stdout line."""
    for ln in (stdout or "").splitlines():
        if ln.strip():
            return ln.strip()
    return None


# ----------------------------------------------------------------------------- state files
AGENT_DIR = "agent"
KEPT_PREFIX = "agent-"          # a second identity folded in from a per-tenant directory
RECORD_SUFFIXES = (".pid", ".log", ".json")


def tunnel_dir() -> Path:
    """The tunnel directory: <state base>/tunnel — BESIDE the per-tenant state dirs, never inside one.

    The agent's identity is this machine's, not a tenant's: the key is self-generated and listed
    on apps by hand, and `check`, `key` and `start` take --org and ask nothing of the platform, so
    they run before any tenant is pinned. Under the per-tenant root the directory moved with the
    pin. MEASURED 2026-10-10 in a fresh home: `tunnel check` resolved state/unpinned/tunnel/agent
    and minted one identity; `app tunnel-keys --add` then pinned the tenant, resolved
    state/<fp16>/tunnel/agent, minted a second and listed THAT one — an operator who pasted the
    key `check` printed had listed a key the agent never used. A tunnel started before the pin
    vanished from `tunnel ls` the same way. A directory an earlier CLI left under a tenant (or
    under `unpinned`) is folded in once; see adopt_legacy.
    """
    d = _tenant.state_base() / "tunnel"
    adopt_legacy(d)
    d.mkdir(parents=True, exist_ok=True)
    return d


def legacy_dirs() -> List[Path]:
    """Every `tunnel/` directory an earlier CLI wrote under a per-tenant state dir: the pinned
    tenant's first (the identity the CLI's own `--add` and `start` used once the pin existed),
    then `unpinned`, then the rest newest first."""
    base = _tenant.state_base()
    try:
        found = [p for p in base.glob("*/tunnel") if p.is_dir()]
    except OSError:
        return []
    pinned = str((_tenant.load() or {}).get("fingerprint") or "")[:16]

    def rank(p: Path):
        name = p.parent.name
        if pinned and name == pinned:
            return (0, 0.0)
        if name == "unpinned":
            return (1, 0.0)
        try:
            return (2, -p.stat().st_mtime)
        except OSError:
            return (2, 0.0)
    return sorted(found, key=rank)


def _move(src: Path, dst: Path) -> bool:
    """rename, else a copying move across devices. Never INTO an existing destination: a second
    CLI process racing this one may have created it, and shutil.move would nest src inside it."""
    try:
        src.rename(dst)
        return True
    except OSError:
        if dst.exists():
            return False
    try:
        shutil.move(str(src), str(dst))
        return True
    except (OSError, shutil.Error):
        return False


def adopt_legacy(new: Path) -> List[Dict[str, str]]:
    """Fold every per-tenant `tunnel/` directory into `new`. Returns what moved.

    The first identity (in legacy_dirs' order) becomes `new/agent` when there is none yet; any
    other is kept beside it as `new/agent-<tenant>`, never dropped: the CLI cannot tell which of
    two keys an app lists without asking the platform, and leftovers() names it until it is
    removed. Records (pid, log, status) move in unless `new` already holds that name, so a tunnel
    started before the pin stays in `tunnel ls`; a directory emptied this way is removed. Nothing
    of another tenant surfaces here: an identity is a key this machine generated.
    """
    moved: List[Dict[str, str]] = []
    for old in legacy_dirs():
        new.mkdir(parents=True, exist_ok=True)
        src = old / AGENT_DIR
        if src.is_dir():
            dst = new / AGENT_DIR
            if dst.exists():
                dst = new / f"{KEPT_PREFIX}{_safe(old.parent.name)}"
            if not dst.exists() and _move(src, dst):
                moved.append({"from": str(src), "to": str(dst), "kind": "identity"})
        for f in sorted(old.glob("*")):
            if f.suffix not in RECORD_SUFFIXES or not f.is_file():
                continue
            dst = new / f.name
            if not dst.exists() and _move(f, dst):
                moved.append({"from": str(f), "to": str(dst), "kind": "record"})
        try:
            old.rmdir()                 # only when nothing was left behind
        except OSError:
            pass
    return moved


def leftovers() -> List[Path]:
    """Identities kept beside the live one (agent-<tenant>), and any still under a per-tenant
    directory because it could not be moved: each is a key this machine once generated, and an
    app may list it rather than the live one. The key-bearing verbs name them until removed."""
    d = _tenant.state_base() / "tunnel"
    out = sorted(p for p in d.glob(f"{KEPT_PREFIX}*") if p.is_dir()) if d.is_dir() else []
    out += [p / AGENT_DIR for p in legacy_dirs() if (p / AGENT_DIR).is_dir()]
    return out


def binary_default_state_dir() -> Optional[Path]:
    """Where the `ascend-tunnel` BINARY keeps its key when run by hand, per its README — the
    agent's internal/config/config.go DefaultStateDir, restated: %LOCALAPPDATA%\\Straiker\\ascend-tunnel
    on Windows, ~/Library/Application Support/Straiker/ascend-tunnel on macOS,
    /var/lib/straiker-tunnel for root on Linux, $XDG_STATE_HOME/ascend-tunnel, else
    ~/.local/state/ascend-tunnel. None when the platform gives nothing to go on."""
    if os.name == "nt":
        d = os.environ.get("LOCALAPPDATA")
        return Path(d) / "Straiker" / "ascend-tunnel" if d else None
    home = os.environ.get("HOME")
    if sys.platform == "darwin":
        return Path(home) / "Library" / "Application Support" / "Straiker" / "ascend-tunnel" if home else None
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return Path("/var/lib/straiker-tunnel")
    xdg = os.environ.get("XDG_STATE_HOME")
    if xdg:
        return Path(xdg) / "ascend-tunnel"
    return Path(home) / ".local" / "state" / "ascend-tunnel" if home else None


def resolve_identity(override: Optional[str] = None) -> Dict[str, Any]:
    """Which key the agent runs with, and why: {dir, source, other, note}.

    --state-dir, else $TUNNEL_STATE_DIR (the agent's own variable), else the CLI's directory
    under the tunnel directory — one identity per machine, whichever tenant is pinned. One more
    case, MEASURED 2026-10-13: a customer who ran the binary by hand per its README has a key at
    the binary's per-OS default directory, and the CLI always passed its own `--state-dir`, so a
    tunnel started here ran under a SECOND identity no app listed and stayed `waiting`. When the
    CLI's directory holds no key and the binary's default does, the default is used and said;
    when both hold one, the CLI's is used and the other is named, because the CLI cannot tell
    which of the two an app lists without asking the platform.
    """
    raw = override or os.environ.get("TUNNEL_STATE_DIR")
    if raw:
        return {"dir": Path(os.path.expanduser(raw)), "source": "flag" if override else "env",
                "other": None, "note": None}
    cli = tunnel_dir() / AGENT_DIR
    default = binary_default_state_dir()
    cli_key = (cli / KEY_FILE).is_file()
    default_key = bool(default) and (default / KEY_FILE).is_file()
    if default_key and not cli_key:
        return {"dir": default, "source": "binary-default", "other": None,
                "note": (f"using the identity at {default}: the key the ascend-tunnel binary made when "
                         f"it was run by hand (its default directory), so an app that lists that key "
                         f"accepts this agent. Pass --state-dir to use another.")}
    if default_key and cli_key:
        return {"dir": cli, "source": "cli", "other": default,
                "note": (f"another identity exists at {default} (the ascend-tunnel binary's default "
                         f"directory); this agent uses {cli}. If an app lists THAT key rather than "
                         f"this agent's, pass --state-dir {default}; otherwise delete it.")}
    return {"dir": cli, "source": "cli", "other": None, "note": None}


def agent_state_dir(override: Optional[str] = None) -> Path:
    """Where the agent keeps its key — resolve_identity's directory."""
    return resolve_identity(override)["dir"]


def tunnel_id(org: Any, env: str) -> str:
    return _safe(f"{org}-{env}")


def paths_for(tid: str) -> Dict[str, Path]:
    base, s = tunnel_dir(), _safe(tid)
    return {"pid": base / f"{s}.pid", "log": base / f"{s}.log", "status": base / f"{s}.json"}


def read_status(tid: str) -> Dict[str, Any]:
    try:
        return json.loads(paths_for(tid)["status"].read_text())
    except (OSError, ValueError):
        return {}


def write_status(tid: str, rec: Dict[str, Any]) -> None:
    p = paths_for(tid)["status"]
    fd = os.open(str(p), os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(rec, fh)


def read_pid(tid: str) -> Optional[int]:
    try:
        return int(paths_for(tid)["pid"].read_text().strip())
    except (OSError, ValueError):
        return None


def _write_pid(tid: str, pid: int) -> None:
    p = paths_for(tid)["pid"]
    fd = os.open(str(p), os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(str(pid))


def _clear(tid: str) -> None:
    try:
        paths_for(tid)["pid"].unlink()
    except FileNotFoundError:
        pass


def is_running(tid: str) -> bool:
    pid = read_pid(tid)
    if pid is None:
        return False
    if pid_alive(pid):
        return True
    _clear(tid)
    return False


# ----------------------------------------------------------------------------- the agent's log
_LINK_EVENTS = {"connected": "up", "forward": "up", "waiting": "waiting",
                "disconnected": "reconnecting"}


def _json_lines(text: str):
    for ln in text.splitlines():
        ln = ln.strip()
        if not ln.startswith("{"):
            continue
        try:
            rec = json.loads(ln)
        except ValueError:
            continue
        if isinstance(rec, dict) and rec.get("event"):
            yield rec


def identity_from_log(log: Path) -> Optional[Dict[str, Any]]:
    """The `identity` event the agent prints on start: the key to list, its id, the app URLs."""
    try:
        with open(log, "r", errors="replace") as fh:
            head = fh.read(256 * 1024)
    except OSError:
        return None
    for rec in _json_lines(head):
        if rec.get("event") == "identity":
            return {"key": rec.get("agent_key"), "agent_id": rec.get("agent_id"),
                    "org": rec.get("tenant"), "app_urls": list(rec.get("app_urls") or [])}
    return None


def last_event(log: Path) -> Optional[Dict[str, Any]]:
    """The last link event in the log, as {state, event, ts, detail}."""
    try:
        size = log.stat().st_size
        with open(log, "r", errors="replace") as fh:
            fh.seek(max(0, size - 64 * 1024))
            tail = fh.read()
    except OSError:
        return None
    out = None
    for rec in _json_lines(tail):
        state = _LINK_EVENTS.get(rec.get("event"))
        if state:
            out = {"state": state, "event": rec.get("event"), "ts": rec.get("ts"),
                   "detail": rec.get("error") or rec.get("targets") or None}
    return out


# ----------------------------------------------------------------------------- supervisor
def _on_windows() -> bool:
    """A seam: the supervisor's POSIX primitives are absent on nt (tests patch this, since
    patching os.name itself breaks pathlib before the check is reached)."""
    return os.name == "nt"


def start(*, org, env: str, allow: List[Dict[str, Any]], runner: Dict[str, Any], endpoint: str,
          host_key: Optional[str], state_dir, ca_file: Optional[str] = None,
          fanout: Optional[int] = None) -> Dict[str, Any]:
    """Spawn a detached agent. Returns {id, pid, log, identity, container} or {error}.

    Same contract as the bridge supervisor: pid and log under the CLI's state dir, the process in
    its own session so it survives this terminal, a short watch for a start-up death so a bad
    flag is reported now and not discovered from an empty `tunnel ls`.
    """
    tid = tunnel_id(org, env)
    if _on_windows():
        return {"id": tid, "error": (
            "the supervised tunnel needs macOS or Linux (it is managed with POSIX signals). On "
            "Windows run it in its own terminal with `ascend tunnel start … --foreground`, run "
            "the agent as a service, or use WSL.")}
    if is_running(tid):
        return {"id": tid, "error": f"a tunnel is already running for org {org} ({env})",
                "pid": read_pid(tid)}
    p = paths_for(tid)
    sd = Path(state_dir)
    sd.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(sd, 0o700)
    except OSError:
        pass
    name = f"ascend-tunnel-{tid}" if runner["kind"] == "docker" else None
    if name:
        _docker_rm(runner, name)      # a container left by an earlier start would refuse the name
    argv = build_argv(runner, "run", org=org, allow=[f["entry"] for f in allow], endpoint=endpoint,
                      host_key=host_key, state_dir=sd, ca_file=ca_file, container_name=name,
                      fanout=fanout)
    log_fd = os.open(str(p["log"]), os.O_CREAT | os.O_WRONLY | os.O_APPEND, 0o600)
    try:
        proc = subprocess.Popen(argv, stdout=log_fd, stderr=subprocess.STDOUT,
                                stdin=subprocess.DEVNULL, env=dict(os.environ),
                                start_new_session=True)
    except OSError as e:
        os.close(log_fd)
        return {"id": tid, "error": f"could not start the agent: {e}"}
    os.close(log_fd)
    _write_pid(tid, proc.pid)
    rec = {"id": tid, "org": str(org), "env": env, "endpoint": endpoint,
           "host_key_pinned": bool(host_key), "allow": [f["entry"] for f in allow],
           "fanout": fanout, "app_urls": [f["app_url"] for f in allow], "runner": runner_public(runner),
           "container": name, "state_dir": str(sd), "pid": proc.pid, "started_at": time.time(),
           "identity": None}
    write_status(tid, rec)
    deadline = time.time() + _startup_grace_s()
    while time.time() < deadline:
        if proc.poll() is not None:
            _clear(tid)
            return {"id": tid, "log": str(p["log"]),
                    "error": f"tunnel exited at startup (code {proc.returncode}): {_log_tail(p['log'])}"}
        ident = identity_from_log(p["log"])
        if ident:
            rec["identity"] = ident
            write_status(tid, rec)
            break
        time.sleep(0.1)
    return {"id": tid, "pid": proc.pid, "log": str(p["log"]), "identity": rec.get("identity"),
            "container": name}


def _docker_rm(runner_or_status: Dict[str, Any], name: str) -> None:
    docker = (runner_or_status.get("docker")
              or (runner_or_status.get("runner") or {}).get("docker"))
    if not docker or not name:
        return
    try:
        subprocess.run([docker, "rm", "-f", name], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        pass


def stop(tid: str, *, grace_s: float = 8.0) -> Dict[str, Any]:
    """SIGTERM, then SIGKILL after the grace period. Under Docker the client proxies SIGTERM to
    the container; the container is removed by name afterwards in case the client went first."""
    st = read_status(tid)
    pid = read_pid(tid)
    if pid is None:
        return {"id": tid, "stopped": False, "reason": "no tunnel recorded"}
    if not pid_alive(pid):
        _clear(tid)
        _docker_rm(st, st.get("container"))
        return {"id": tid, "stopped": False, "reason": "was not running (stale pidfile reaped)"}
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError as e:
        return {"id": tid, "stopped": False, "reason": f"{e}"}
    how = None
    deadline = time.time() + grace_s
    while time.time() < deadline:
        _reap(pid)
        if not pid_alive(pid):
            how = "SIGTERM"
            break
        time.sleep(0.25)
    if how is None:
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass
        how = "SIGKILL"
    _reap(pid)
    _docker_rm(st, st.get("container"))
    _clear(tid)
    return {"id": tid, "stopped": True, "pid": pid, "how": how}


def _reap(pid: int) -> None:
    """Collect the exit status when the agent is this process's own child (it is, until the CLI
    that started it exits): an exited-but-unreaped child still answers `kill -0`, which would
    read as "still running" and turn a clean SIGTERM into a SIGKILL. Not our child: nothing to do."""
    try:
        os.waitpid(pid, os.WNOHANG)
    except (ChildProcessError, OSError):
        pass


def ls() -> List[Dict[str, Any]]:
    """Every tunnel this machine has started, with liveness and the link state its log shows."""
    out: List[Dict[str, Any]] = []
    for pid_file in sorted(tunnel_dir().glob("*.pid")):
        tid = pid_file.stem
        st = read_status(tid)
        pid = read_pid(tid)
        alive = pid is not None and pid_alive(pid)
        log = paths_for(tid)["log"]
        ident = st.get("identity") or identity_from_log(log)
        ev = last_event(log) if alive else None
        out.append({"id": tid, "org": st.get("org"), "env": st.get("env"), "pid": pid,
                    "alive": alive, "state": "serving" if alive else "dead",
                    "link": (ev or {}).get("state") if alive else None,
                    "link_event": ev, "started_at": st.get("started_at"),
                    "endpoint": st.get("endpoint"), "host_key_pinned": st.get("host_key_pinned"),
                    "allow": st.get("allow") or [], "fanout": st.get("fanout"),
                    "app_urls": st.get("app_urls") or [],
                    "key": (ident or {}).get("key"), "agent_id": (ident or {}).get("agent_id"),
                    "runner": (st.get("runner") or {}).get("kind"), "container": st.get("container"),
                    "state_dir": st.get("state_dir"), "log": str(log)})
    return out
