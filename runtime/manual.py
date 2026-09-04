"""
manual.py — send your own prompts through an adapter, outside an Ascend assessment.

Why this exists: while building an adapter, reproducing a finding, or hand-red-teaming a
target, you need to send arbitrary prompts and see exactly what comes back. `adapter
validate` answers "does it work at all" (a gate); this answers "what does it say".

Evidence format — deliberately the SAME file format the relay writes with --capture:
newline-delimited JSON envelopes, 0600, sensitive headers redacted. A manual turn is
`kind: "turn"` rather than the relay's `probe`/`result` pair, so anything that reads a
transcript keeps working and you can analyse human-driven and platform-driven traffic with
one set of tools. Nothing here invents a second evidence schema.
"""
from __future__ import annotations

import json
import os
import time
import uuid
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

SENSITIVE = {"authorization", "cookie", "set-cookie", "x-api-key", "api-key",
             "x-csrf-token", "proxy-authorization", "authentication",
             "x-amz-security-token", "x-goog-api-key", "x-auth-token", "x-access-token"}

# Secrets do not only live in headers. A mapped config routinely carries a session token, an
# access key or a signed blob INSIDE the request body — `map --curl` preserves the body verbatim,
# so whatever authenticated the browser is now in the file. Redaction that only knew about header
# names printed those in clear.
SENSITIVE_FIELDS = {
    "token", "access_token", "accesstoken", "refresh_token", "refreshtoken", "id_token",
    "idtoken", "session_token", "sessiontoken", "session", "sessionid", "session_id",
    "api_key", "apikey", "apisecret", "api_secret", "secret", "client_secret", "clientsecret",
    "password", "passwd", "pwd", "auth", "credential", "credentials", "signature", "sig",
    "private_key", "privatekey", "secret_access_key", "secretaccesskey", "jwt", "bearer",
}


# Compared after the same normalisation the key gets: `X-API-Key` -> `x_api_key`. The header set is
# written with dashes, so comparing the normalised key against it matched only the two names with
# no dash (authorization, cookie) — x-api-key, x-auth-token, set-cookie and x-csrf-token were
# printed in clear by every command that promised masking.
_SENSITIVE_NORMALISED = {s.lower().replace("-", "_") for s in SENSITIVE} | set(SENSITIVE_FIELDS)


def _is_sensitive_key(key: Any) -> bool:
    if not isinstance(key, str):
        return False
    return key.lower().replace("-", "_") in _SENSITIVE_NORMALISED


def redact_url(value: Any) -> Any:
    """Mask sensitive query parameters inside a URL string.

    Redaction used to match on key NAMES only, which missed the case this tool creates itself:
    `--api-key NAME:VALUE:in=query` and the Gemini-style `?key=` are baked straight into the
    config's endpoint. The credential was then in a value, not under a sensitive key, so it
    survived masking — and got printed by the command that promises masking, logged on every
    probe, written to capture files, and posted upstream inside a failing probe's error string.
    """
    if not isinstance(value, str) or "?" not in value:
        return value
    if not value.lower().startswith(("http://", "https://", "ws://", "wss://")):
        return value
    try:
        from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
        parts = urlsplit(value)
        if not parts.query:
            return value
        pairs = parse_qsl(parts.query, keep_blank_values=True)
        cleaned = [(k, "[REDACTED]" if _is_sensitive_key(k) or k.lower() in ("key", "apikey")
                    else v) for k, v in pairs]
        return urlunsplit(parts._replace(query=urlencode(cleaned)))
    except Exception:                       # never let masking raise on the display path
        return value


def redact(obj: Any) -> Any:
    """Mask known-sensitive values — headers, body fields, AND credentials carried in a URL."""
    if isinstance(obj, dict):
        return {k: ("[REDACTED]" if _is_sensitive_key(k) else redact(v))
                for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact(x) for x in obj]
    return redact_url(obj)


def load_prompts(path: str) -> List[Dict[str, Any]]:
    """Read a prompt file. Two formats, chosen by content, not extension.

    * one prompt per line (blank lines and `#` comments ignored) — zero friction for
      quick manual work, and diffs cleanly in git
    * JSONL objects for prompts that carry metadata:
      {"prompt": "...", "id": "...", "category": "...", "expect": "...", "note": "..."}
    """
    out: List[Dict[str, Any]] = []
    text = Path(path).read_text()
    for i, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("{"):
            try:
                obj = json.loads(line)
                if "prompt" in obj:
                    obj.setdefault("id", f"p{i:04d}")
                    out.append(obj)
                    continue
            except ValueError:
                pass  # not JSON after all — treat it as a literal prompt
        out.append({"id": f"p{i:04d}", "prompt": line})
    return out


class TurnLog:
    """Append-only JSONL transcript, 0600, same file format as relay captures."""

    def __init__(self, path: Optional[str]):
        self.path = path
        if path:
            Path(path).parent.mkdir(parents=True, exist_ok=True)

    def write(self, record: Dict[str, Any]) -> None:
        if not self.path:
            return
        try:
            fd = os.open(self.path, os.O_CREAT | os.O_WRONLY | os.O_APPEND, 0o600)
            with os.fdopen(fd, "a") as fh:
                fh.write(json.dumps(redact(record)) + "\n")
        except Exception:
            pass  # logging must never break a session


def run_turn(caller, prompt: str, *, meta: Optional[Dict[str, Any]] = None,
             session: str = "") -> Dict[str, Any]:
    """Send one prompt through the adapter and return a turn record.

    `caller` is a TargetCaller; using it (rather than the adapter directly) means manual
    turns take the exact same path as assessment probes — including conversation/session
    state, so an interactive session is genuinely multi-turn against a stateful target.
    """
    meta = meta or {}
    started = time.time()
    # Use the config's prompt_field, not a hardcoded "prompt" — otherwise every chat turn
    # fails on a config that sets prompt_field, while validate/runtime work.
    field = (caller.config.get("prompt_field") or "prompt")
    status, body = caller.handler(
        {"payload": {"body": {field: prompt}, "headers": {}}})
    response = str(body.get("response", "") or "")
    rec: Dict[str, Any] = {
        "ts": started,
        "kind": "turn",
        "source": "manual",
        "request_id": meta.get("id") or uuid.uuid4().hex[:12],
        "session": session,
        "adapter": caller.adapter_type,
        "config": caller.config_name,
        "prompt": prompt,
        "response": response,
        "status_code": status,
        "ok": status == 200 and bool(response),
        "duration_ms": int((time.time() - started) * 1000),
    }
    for k in ("category", "expect", "note"):
        if meta.get(k):
            rec[k] = meta[k]
    if meta.get("expect"):
        rec["matched"] = str(meta["expect"]).lower() in response.lower()
    if body.get("_error"):
        rec["error"] = body["_error"]
    return rec


def summarize(records: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    recs = list(records)
    ok = sum(1 for r in recs if r.get("ok"))
    expected = [r for r in recs if "matched" in r]
    return {
        "turns": len(recs),
        "ok": ok,
        "failed": len(recs) - ok,
        "checked": len(expected),
        "matched": sum(1 for r in expected if r["matched"]),
        "avg_ms": int(sum(r.get("duration_ms", 0) for r in recs) / len(recs)) if recs else 0,
    }
