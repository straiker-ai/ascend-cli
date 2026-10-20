"""
console — the Console's own application ids, joined to the platform's by name.

Two id spaces name one Ascend application. The v3 API spells it `aapp_…` (an encrypted token);
the Console routes by its own uuid (`…/applications/ascend/<uuid>`), and the engine's adaptor
routes (`adaptor get | test | verify`) take THAT uuid — they answer a bare 404 "could not be read"
for the `aapp_` form. No v3 field carries the uuid and neither id encodes the other, so the only
join is the Console's own listing: its SvelteKit remote function `listApplications` answers a
plain GET with the PAT-exchanged JWT presented as the `auth-id-token` cookie, and the rows carry
`irisId` (the uuid), `name` and `url`. Measured live on tenant 123 (every app matched by exact
name; a duplicate name is settled by url).

This is the one place that call is made. `AscendAPI.console_app_uuid` wraps it with the client's
own token and base; the CLI resolves a name or an `aapp_` id through it and keeps `--console-id`
as the override for the day the listing cannot be read.
"""
from __future__ import annotations

import base64
import json
import math
import os
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

import requests

DEFAULT_CONSOLE_BASE = "https://app.straiker.ai"
# The SvelteKit hash of `src/lib/remote/assessments.remote.ts` (djb2 over the reversed path, base36).
# Override with STRAIKER_CONSOLE_REMOTE if the file moves.
DEFAULT_REMOTE_ID = "3s6sbx"
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)


class ConsoleError(RuntimeError):
    """The Console's listing could not be read: not a 'not found'."""


def console_base_for(api_base: Optional[str]) -> str:
    """The Console that fronts an API base: `api.prod.straiker.ai` -> `app.straiker.ai`,
    `api.<env>.straiker.ai` -> `app.<env>.straiker.ai`. STRAIKER_CONSOLE_BASE wins."""
    env = os.environ.get("STRAIKER_CONSOLE_BASE")
    if env:
        return env.rstrip("/")
    host = ""
    try:
        host = (urlsplit(api_base or "").hostname or "").lower()
    except ValueError:
        host = ""
    m = re.match(r"^api\.([a-z0-9-]+)\.straiker\.ai$", host)
    if m and m.group(1) != "prod":
        return f"https://app.{m.group(1)}.straiker.ai"
    return DEFAULT_CONSOLE_BASE


def remote_id() -> str:
    return os.environ.get("STRAIKER_CONSOLE_REMOTE") or DEFAULT_REMOTE_ID


# ----------------------------------------------------------------------------- devalue
_SPECIALS = {-1: None, -2: None, -3: math.nan, -4: math.inf, -5: -math.inf, -6: -0.0}


def unflatten(text: Any) -> Any:
    """A devalue-flattened value (what every remote function answers under `data`) as Python.

    The format is one flat array; objects and arrays hold INDEXES into it, not values, and a
    negative index is a sentinel (undefined, a hole, NaN, ±Infinity, -0).
    """
    arr = json.loads(text) if isinstance(text, str) else text
    if not isinstance(arr, list):
        return arr

    def hyd(i: Any) -> Any:
        if not isinstance(i, int):
            return i
        if i < 0:
            return _SPECIALS.get(i)
        v = arr[i]
        if isinstance(v, list):
            if v and isinstance(v[0], str) and v[0] in ("Date", "Set", "Map", "RegExp", "Object", "BigInt", "null"):
                if v[0] == "Date":
                    return v[1] if len(v) > 1 else None
                if v[0] == "Set":
                    return [hyd(j) for j in v[1:]]
                if v[0] == "Map":
                    return {hyd(v[j]): hyd(v[j + 1]) for j in range(1, len(v) - 1, 2)}
                if v[0] == "null":
                    return hyd(v[1]) if len(v) > 1 else None
                return v
            return [hyd(j) for j in v]
        if isinstance(v, dict):
            return {k: hyd(j) for k, j in v.items()}
        return v

    return hyd(0)


def devalue_payload(obj: Optional[Dict[str, Any]]) -> str:
    """The `?payload=` of a remote query: empty for a no-argument call, else the base64url of
    devalue.stringify over one flat object of scalars."""
    if obj is None:
        return ""
    arr: List[Any] = [{}]
    for k, val in obj.items():
        arr[0][k] = len(arr)
        arr.append(val)
    raw = json.dumps(arr, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


# ----------------------------------------------------------------------------- the listing
def list_applications(jwt: str, *, base: Optional[str] = None, timeout: float = 30.0,
                      session: Any = None) -> List[Dict[str, Any]]:
    """Every Ascend application the Console lists for this token's tenant, as rows with at
    least `irisId`, `name` and `url`."""
    base = (base or DEFAULT_CONSOLE_BASE).rstrip("/")
    url = f"{base}/_app/remote/{remote_id()}/listApplications?payload="
    headers = {"Cookie": f"auth-id-token={jwt}", "Accept": "application/json"}
    client = session or requests
    r = client.get(url, headers=headers, timeout=timeout)
    if r.status_code != 200:
        raise ConsoleError(f"the Console answered {r.status_code} to listApplications")
    try:
        doc = r.json()
    except ValueError:
        raise ConsoleError("the Console's listing was not JSON")
    if not isinstance(doc, dict) or doc.get("type") != "result":
        kind = doc.get("type") if isinstance(doc, dict) else type(doc).__name__
        raise ConsoleError(f"the Console's listing answered {kind!r}: {str(doc)[:200]}")
    value = unflatten(doc.get("data"))
    rows = value.get("_") if isinstance(value, dict) and "_" in value else value
    return [row for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []


def _norm(s: Any) -> str:
    return " ".join(str(s or "").split()).lower()


def _norm_url(u: Any):
    from urllib.parse import urlsplit
    if not isinstance(u, str) or not u.strip():
        return None
    if any(character.isspace() or ord(character) < 32 for character in u.strip()):
        return None
    try:
        parts = urlsplit(u.strip())
        if (parts.scheme.lower() not in ("http", "https") or not parts.hostname
                or parts.username is not None or parts.password is not None or parts.fragment):
            return None
        # Host and scheme are insensitive; path/query bytes are not. Do not
        # equate /chat and /chat/, reorder queries, or decode escaped characters.
        return (parts.scheme.lower(), parts.hostname.lower(), parts.port,
                parts.path or "/", parts.query)
    except ValueError:
        return None


def match_application(rows: List[Dict[str, Any]], name: str, url: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Match name and, when supplied, URL; never override a URL conflict by name."""
    exact = [r for r in rows if _norm(r.get("name")) == _norm(name)]
    if url is not None:
        target = _norm_url(url)
        if target is None:
            return None
        exact = [r for r in exact if _norm_url(r.get("url")) == target]
    return exact[0] if len(exact) == 1 else None


def console_app_uuid(jwt: str, name: str, *, url: Optional[str] = None, base: Optional[str] = None,
                     timeout: float = 30.0, session: Any = None) -> Optional[str]:
    """The Console uuid of the application called `name`, or None when the listing does not
    name it (yet) or names it more than once. Raises ConsoleError when the listing itself
    cannot be read, which is a different answer."""
    row = match_application(list_applications(jwt, base=base, timeout=timeout, session=session), name, url)
    uid = str((row or {}).get("irisId") or "").strip()
    return uid if UUID_RE.match(uid) else None


__all__ = ["ConsoleError", "DEFAULT_CONSOLE_BASE", "console_base_for", "remote_id", "unflatten",
           "devalue_payload", "list_applications", "match_application", "console_app_uuid"]
