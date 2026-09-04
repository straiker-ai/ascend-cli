"""
tenant.py — the single-tenant lock.

An SE works across many customers. The highest-consequence mistake this CLI could enable is
operating on the WRONG TENANT: registering a test app, or pointing a relay holding customer A's
`tc-` key, while believing you are in customer B. So the CLI pins itself to exactly ONE tenant and
refuses to run against any other until you explicitly switch.

Identity comes from the PAT-exchanged JWT: `iss` (the Cognito user pool) + `straikerId` (the tenant
id). We store only a **SHA-256 fingerprint** of those two — never the raw id, never the PAT — plus a
human label for display. The fingerprint is a comparison token, not a secret.

Everything mutable on disk (key store, relay state) lives under the tenant's fingerprint directory,
so switching can never surface another tenant's material.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

ASCEND_HOME = Path(os.path.expanduser(os.environ.get("ASCEND_HOME", "~/.ascend")))
TENANT_FILE = ASCEND_HOME / "tenant.json"


class TenantMismatch(Exception):
    """Raised when the supplied PAT belongs to a different tenant than the pinned one."""

    def __init__(self, pinned_label: str, incoming_label: str,
                 pinned_fp: str = "", incoming_fp: str = ""):
        self.pinned_label = pinned_label
        self.incoming_label = incoming_label
        self.pinned_fp = pinned_fp
        self.incoming_fp = incoming_fp
        # The label is derived from the PAT's email domain and role, so two different tenants
        # administered from the same domain get the SAME label -- and this message then read
        # "locked to 'straiker.ai (admin)', but the credential belongs to 'straiker.ai (admin)'":
        # self-contradictory, and it told the operator nothing. Seen live between the demo tenant
        # and the Discover tenant. The fingerprint is what the check actually compares, so it is
        # what the message must show.
        def tag(label, fp):
            return f"{label!r} (id {fp[:12]}...)" if fp else repr(label)
        msg = (f"this CLI is locked to tenant {tag(pinned_label, pinned_fp)}, but the supplied "
               f"credential belongs to {tag(incoming_label, incoming_fp)}.\n")
        if pinned_label == incoming_label:
            msg += ("  The names match but the tenant ids do not: this is a different tenant that "
                    "happens to share a name.\n")
        msg += ("  Working two tenants from one CLI is how customer data gets crossed, so it is "
                "refused.\n"
                "  To move:  ascend tenant switch --confirm   "
                "(clears stored keys; requires no relays running)\n"
                "  To check: ascend tenant show")
        super().__init__(msg)


def _b64url_json(segment: str) -> Dict[str, Any]:
    pad = "=" * (-len(segment) % 4)
    return json.loads(base64.urlsafe_b64decode(segment + pad))


def claims_from_jwt(jwt: str) -> Dict[str, Any]:
    """Decode a JWT's claims WITHOUT verifying the signature.

    We are not authenticating here — the server does that. We only read the tenant identity out of
    a token the server already issued to us, to compare it against what we pinned.
    """
    parts = (jwt or "").split(".")
    if len(parts) < 2:
        return {}
    try:
        return _b64url_json(parts[1])
    except Exception:
        return {}


def identity(jwt: str) -> Tuple[Optional[str], str]:
    """(fingerprint, label) for a JWT. fingerprint is None when identity can't be determined."""
    c = claims_from_jwt(jwt)
    iss, sid = c.get("iss"), c.get("straikerId")
    if not iss or sid in (None, ""):
        return None, "unknown"
    fp = hashlib.sha256(f"{iss}|{sid}".encode()).hexdigest()
    email = str(c.get("email") or "")
    domain = email.split("@")[-1] if "@" in email else ""
    role = str(c.get("role") or "")
    label = " ".join(x for x in (domain or f"tenant-{sid}", f"({role})" if role else "") if x)
    return fp, label


def load() -> Optional[Dict[str, Any]]:
    try:
        return json.loads(TENANT_FILE.read_text())
    except (OSError, ValueError):
        return None


def _pinned_fingerprint() -> Optional[str]:
    """The fingerprint this CLI is pinned to, if any (from tenant.json)."""
    rec = load()
    return (rec or {}).get("fingerprint")


def _write(rec: Dict[str, Any]) -> None:
    ASCEND_HOME.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(TENANT_FILE), os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(rec, fh, indent=2)


def pin(fingerprint: str, label: str) -> Dict[str, Any]:
    rec = {"fingerprint": fingerprint, "label": label, "pinned_at": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                                                                 time.gmtime())}
    _write(rec)
    return rec


def check(jwt: str) -> Dict[str, Any]:
    """Pin on first use; verify on every later use.

    Returns {"status": "pinned"|"ok"|"unknown", "fingerprint", "label"}.
    Raises TenantMismatch when the credential belongs to another tenant.
    """
    fp, label = identity(jwt)
    if fp is None:
        return {"status": "unknown", "fingerprint": None, "label": label}
    cur = load()
    if not cur or not cur.get("fingerprint"):
        pin(fp, label)
        return {"status": "pinned", "fingerprint": fp, "label": label}
    if cur["fingerprint"] != fp:
        raise TenantMismatch(cur.get("label", "unknown"), label, cur["fingerprint"], fp)
    return {"status": "ok", "fingerprint": fp, "label": cur.get("label", label)}


def clear() -> bool:
    """Forget the pinned tenant (does NOT touch per-tenant state; caller decides)."""
    try:
        TENANT_FILE.unlink()
        return True
    except FileNotFoundError:
        return False


def state_root(fingerprint: Optional[str] = None) -> Path:
    """Per-tenant state dir: $ASCEND_STATE_DIR > ~/.ascend/state/<fp16>.

    Tenant-scoped so a switch can never expose another tenant's keys or relay records.
    """
    env = os.environ.get("ASCEND_STATE_DIR")
    if env:
        base = Path(os.path.expanduser(env))
        # Still namespace by tenant fingerprint UNDER the override, so two customers worked from
        # one exported ASCEND_STATE_DIR do not share one keys.json / jwt.json.
        fp = fingerprint or _pinned_fingerprint()
        return base / fp[:16] if fp else base
    fp = fingerprint
    if fp is None:
        rec = load() or {}
        fp = rec.get("fingerprint")
    return ASCEND_HOME / "state" / (str(fp)[:16] if fp else "unpinned")
