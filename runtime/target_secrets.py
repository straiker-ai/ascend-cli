"""
target_secrets.py — the local store for target credentials captured from a real session.

WHY THIS EXISTS. A browser capture sees the credential the target actually requires — a bearer,
a cookie, an `X-Window-Token` — because it watched a signed-in human use the agent. Until now
`discovery/classify.py` **threw that value away**: `_nonsecret_headers` dropped every
credential-shaped header and `dropped_secret_headers()` recorded only the NAMES into
`_withheld_headers`. The registered target could then never authenticate. MEASURED on a real
run: 10 probes leased, 10 delivered, **0 answered**, and the config said
`"_withheld_headers": ["X-Window-Token"]` — the endpoint was rejecting every request for a
header nobody had put back, and the operator was told to go find it in DevTools by hand.

Dropping it was the right instinct aimed at the wrong target. What must never happen is a
secret written into a config file — those get copied between machines, pasted into tickets and
committed. What must ALSO never happen is shipping a target that cannot authenticate. Both hold
at once if the value goes somewhere else: the config keeps an `env:` **reference**, exactly as
`layers/auth.py` has always specified, and the value lives here.

  config on disk:  {"auth": {"type": "static", "mode": "headers",
                             "headers": {"X-Window-Token": "env:ASCEND_SECRET_…"}}}
  here:            {"ASCEND_SECRET_…": {"value": "<the token>", …}}

`layers.auth.resolve_secret_ref` reads the environment first and falls back to this store, so
the same config works in the process that captured it, in a relay started tomorrow, and on a
second machine once the store is carried across — without the value ever being in the config.

Security posture, the same as `creds.py` and for the same reasons:
  * files are 0600, created with `os.open(..., O_CREAT|O_WRONLY, 0o600)` — the house pattern;
  * **tenant-scoped** (under `tenant.state_root()`), so switching tenants cannot surface another
    customer's credential;
  * values are **masked** everywhere they are displayed — `listing()` never returns one;
  * nothing here is passed on argv, because argv is world-readable through `ps`.

A stored credential is still a CAPTURED SESSION credential. It can expire, and a target that
mints a fresh one per conversation cannot be replayed from any capture at all. That is a
property of the target, not a bug in this store, and `record()` keeps `captured_at` so the
caller can say so plainly instead of letting a run burn its probes finding out.
"""
from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import tenant as _tenant

# NOT named `secrets.py`. `runtime/` is a flat directory on sys.path — that is how `import
# tenant` works — so a module called `secrets` here would SHADOW the standard library's
# `secrets` for this process and every third-party package imported into it. Nothing in this
# repo imports stdlib `secrets` today, which is exactly what would have made the breakage
# arrive later and from somebody else's dependency.

# The prefix every generated variable name carries. It makes a reference self-describing in a
# config file and makes the store's keys greppable in a support bundle.
PREFIX = "ASCEND_SECRET_"

# Process-local, names-only handoff from a workspace credential resolver. A name
# withheld by that resolver must not be resurrected from an older local copy.
EXCLUSIONS_ENV = "_ASCEND_AGENT_WITHHELD_NAMES"


def _excluded_names():
    """Read lazily: malformed metadata disables store fallback, not CLI startup.

    None denotes an invalid handoff. Explicit environment values still retain
    their historical priority; no store contents or credential values change.
    """
    raw = os.environ.get(EXCLUSIONS_ENV)
    if not raw:
        return frozenset()
    parsed = None
    try:
        parsed = json.loads(raw)
    except (TypeError, ValueError):
        pass
    if (not isinstance(parsed, list) or any(not isinstance(name, str)
            or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) is None for name in parsed)):
        return None
    return frozenset(parsed)

# ---------------------------------------------------------------------------------------------
# THE secret-name rule. One place, asked by everything that has to decide whether a header, a
# body field or a config key carries a credential: `discovery/classify.py` (what a capture
# withholds from a config and stores here), `discovery/probe.py` (what a flag-authenticated
# onboarding echoes back), `discovery/codegen.py` (`safe_headers`), `discovery/har_chains.py`
# (the redacted session report), `manual.py` (every printed config, host-call trace and turn
# log), `lease_client.py` (capture files) and the plaintext warning in `shells/cli/ascend.py`.
#
# MEASURED 2026-10-09 on the lab target: its access code arrives as `x-lab-code` (and as a
# `Cookie`). `target add --header 'x-lab-code: <literal>'` wrote both literals into the config and
# warned about neither, because the warning read the probe's own seven-name list — one of FIVE
# lists in this repo, each with its own vocabulary, none of which knew `x-lab-code`, `passcode`,
# `access_code` or `session_id`. A name every list missed is the normal case, not the edge case:
# the whole point of a custom credential header is that nobody listed it in advance.
#
# It is a WORD rule. The name is split on `-`, `_`, `.` and camelCase humps and lowercased, and a
# credential word has to stand on a word boundary: `x-lab-code`, `X_LAB_CODE` and `xLabCode` are
# one name; `country_code`, `content-type` and `x-request-id` carry no credential word and never
# match. Compounds may run together the way field names do (`apikey`, `sessionid`,
# `accesstoken`, `clientsecret`). Bare `key`, `id` and `code` say nothing on their own — an
# `Idempotency-Key`, a request id and a country code are not credentials, and a rule that withheld
# them from a config would 401 the target it was protecting — so they count only behind the
# qualifiers that make them one. `token` and `cookie` are read at the END of a name only, so
# `token_types` (a stream's frame kinds) and a cookie-consent flag stay visible.
REDACTED = "[REDACTED]"

_CAMEL_HUMP = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_SEPARATORS = re.compile(r"[-_.\s]+")
_SECRET_NAME = re.compile(
    r"(?:^|-)(?:"
    r"authorization|authentication|[a-z]*secret"
    r"|(?:api|access|subscription|tenant|app|private|client|auth|session|secret|secret-?access)-?key"
    r"|password|passwd|pwd|credentials?|bearer|signature|sig|hmac|nonce|jwt"
    r"|pass-?code|(?:access|lab|auth|api|app|client|invite)-?code"
    r"|session-?(?:id|key|token)|sid|client-?id"
    r")(?:$|-)"
    r"|(?:^|-)(?:[a-z]*token|(?:set-?)?cookies?|auth)$")

#: Names that are a credential only as a QUERY PARAMETER — `?code=` is the lab's access code,
#: `?key=` is Gemini's, `?session=` a session — and say nothing as a header or field name.
QUERY_ONLY_SECRET_NAMES = frozenset({"code", "key", "session"})


def normalize_name(name: Any) -> str:
    """`X_LAB_CODE`, `x.lab.code` and `xLabCode` -> `x-lab-code`: the spelling the rule reads."""
    if not isinstance(name, str):
        return ""
    return _SEPARATORS.sub("-", _CAMEL_HUMP.sub("-", name.strip())).strip("-").lower()


def is_secret_name(name: Any) -> bool:
    """Does this header / field / parameter NAME carry a credential? Case-insensitive, on
    `-` / `_` / `.` / camelCase boundaries. Never raises: a display path may hand it anything."""
    n = normalize_name(name)
    return bool(n) and _SECRET_NAME.search(n) is not None


def is_secret_param_name(name: Any) -> bool:
    """`is_secret_name`, plus the bare names that are a credential only in a query string."""
    return is_secret_name(name) or normalize_name(name) in QUERY_ONLY_SECRET_NAMES


def store_path() -> Path:
    """Where a record is WRITTEN: this tenant's state dir, or the unpinned one before a pin."""
    return _tenant.state_root() / "target_secrets.json"


def _unpinned_path() -> Path:
    """The store a capture wrote BEFORE this home was pinned to a tenant.

    `target add` captures and stores at step 1 and creates its platform client — the moment the
    home is pinned — at step 3. So the first registration in a fresh home writes the credential
    under the unpinned root, and every later command (a `--config` re-run, `adapter validate`)
    looks under the pinned fingerprint and finds nothing. MEASURED 2026-10-09: the re-run died
    with "this tenant's credential store has no value for it" four seconds after the capture had
    stored it. Reads therefore merge both; the pinned store wins. Nothing of another tenant can
    surface this way: the unpinned store exists only while no tenant was pinned at all.
    """
    env = os.environ.get("ASCEND_STATE_DIR")
    if env:
        return Path(os.path.expanduser(env)) / "target_secrets.json"
    return _tenant.ASCEND_HOME / "state" / "unpinned" / "target_secrets.json"


def _paths() -> List[Path]:
    """Every store a read consults, current first."""
    out = [store_path()]
    other = _unpinned_path()
    if other != out[0]:
        out.append(other)
    return out


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def mask(value: Optional[str]) -> str:
    """`eyJhbGciOi…9f` — never print a whole credential, here or anywhere else."""
    if not value:
        return "-"
    v = str(value)
    return "…" + v[-4:] if len(v) <= 12 else f"{v[:6]}…{v[-4:]}"


def var_name(host: str, header: str) -> str:
    """A stable variable name for (host, header).

    Stable matters: re-capturing the same target must overwrite the same entry rather than
    growing a new one per run, and a config written last week must still resolve today.
    """
    slug = re.sub(r"[^A-Z0-9]+", "_", f"{host}_{header}".upper()).strip("_")
    return f"{PREFIX}{slug}"


def _read(p: Path) -> Dict[str, Any]:
    try:
        return json.loads(p.read_text())
    except (OSError, ValueError):
        return {}


def _write(p: Path, data: Dict[str, Any]) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(p), os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(data, fh, indent=2)


def load_all() -> Dict[str, Dict[str, Any]]:
    """Every record for this tenant. Refuses a file other users can read.

    A credential store that silently accepted a world-readable file would quietly undo the only
    thing it is for, so this is loud and returns nothing rather than pretending.
    """
    excluded = _excluded_names()
    if excluded is None:
        return {}
    merged: Dict[str, Dict[str, Any]] = {}
    for p in reversed(_paths()):        # unpinned first, so the current store overrides it
        merged.update(_load_one(p))
    return {name: record for name, record in merged.items() if name not in excluded}


def _load_one(p: Path) -> Dict[str, Dict[str, Any]]:
    try:
        mode = p.stat().st_mode
    except OSError:
        return {}                       # no store yet, or unreadable — both mean "nothing here"
    # NOT raised from inside a `try/except OSError`. `PermissionError` IS an `OSError`, so the
    # first version of this refusal was caught by its own handler and returned `{}` — the check
    # ran, reported nothing, and the file was treated as empty instead of as a problem. A
    # world-readable credential store must be loud; silence here is the whole failure.
    if mode & 0o077:
        raise PermissionError(
            f"{p} is readable by other users — refusing to load credentials from it. "
            f"chmod 600 {p}")
    data = _read(p)
    return data if isinstance(data, dict) else {}


def record(name: str, value: str, *, host: str = "", header: str = "",
           source: str = "capture") -> str:
    """Store one credential value under `name`. Returns the `env:` reference for the config."""
    if not name or not isinstance(value, str) or not value:
        raise ValueError("a stored secret needs a name and a non-empty value")
    data = _load_one(store_path())      # the CURRENT store only: never copy another file's rows
    data[name] = {"value": value, "host": host, "header": header, "source": source,
                  "captured_at": _now()}
    _write(store_path(), data)
    return f"env:{name}"


def get(name: str) -> Optional[str]:
    """The value for `name`, or None. The environment always wins over the store, so an
    operator can override a stale captured credential for one run without editing anything."""
    from_env = os.environ.get(name)
    if from_env:
        return from_env
    excluded = _excluded_names()
    if excluded is None or name in excluded:
        return None
    rec = load_all().get(name)
    if isinstance(rec, dict):
        val = rec.get("value")
        return val if isinstance(val, str) and val else None
    return None


def meta(name: str) -> Dict[str, Any]:
    """Everything about a stored secret EXCEPT its value — safe to print or log."""
    rec = load_all().get(name) or {}
    if not isinstance(rec, dict):
        return {}
    return {k: v for k, v in rec.items() if k != "value"} | {"masked": mask(rec.get("value"))}


def listing() -> List[Dict[str, Any]]:
    """What is stored, for `ascend target secrets`. Never includes a value."""
    out = []
    for name, rec in sorted(load_all().items()):
        if not isinstance(rec, dict):
            continue
        out.append({"name": name, "host": rec.get("host") or "-",
                    "header": rec.get("header") or "-",
                    "value": mask(rec.get("value")),
                    "captured_at": rec.get("captured_at") or "-",
                    "source": rec.get("source") or "-"})
    return out


def forget(name: str) -> bool:
    found = False
    for p in _paths():
        data = _load_one(p)
        if name in data:
            data.pop(name)
            _write(p, data)
            found = True
    return found


def forget_host(host: str) -> List[str]:
    """Drop every credential captured for one host, wherever it was stored. Returns the names."""
    gone: List[str] = []
    for p in _paths():
        data = _load_one(p)
        here = [n for n, r in data.items() if isinstance(r, dict) and r.get("host") == host]
        for n in here:
            data.pop(n)
        if here:
            _write(p, data)
        gone += [n for n in here if n not in gone]
    return gone
