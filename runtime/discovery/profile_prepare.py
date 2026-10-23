"""Read-only, expected-profile preparation; never discovery or execution proof.

Captures are private consumer inputs, not model-facing source summaries. A hash
identifies observed entity bytes or sanitized JSON, never remote attestation.
"""
from __future__ import annotations

from datetime import datetime, timezone
import base64
import hashlib
import json
import math
import os
import re
import stat
import time
from pathlib import Path
from urllib.parse import urlsplit

import requests

from runtime import target_secrets
from . import profiles

VERSION = 1
PRODUCER_REVISION = "published-profile-prepare/1"
MAX_GETS = 4
MAX_BYTES = 64 * 1024
MAX_OUTPUT_BYTES = 512 * 1024
MAX_SECONDS = 20.0
_REF = re.compile(r"env:([A-Za-z_][A-Za-z0-9_]*)\Z")
_WORKSPACE = re.compile(r"[A-Za-z0-9_-]{1,96}\Z")


class Hold(Exception):
    def __init__(self, outcome, code, requirement=None):
        self.outcome, self.code, self.requirement = outcome, code, requirement


class PrivateOutput:
    """Exclusive caller-owned artifact; failed publication removes only our inode."""

    def __init__(self, path):
        self.directory = self.fd = None
        self.identity = None
        self.published = False
        try:
            self.path = Path(path)
            if not self.path.is_absolute() or self.path.name in (".", ".."):
                raise OSError()
            self.directory = os.open(str(self.path.parent), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            info = os.fstat(self.directory)
            if info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise OSError()
            self.fd = os.open(self.path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                              0o600, dir_fd=self.directory)
            info = os.fstat(self.fd)
            self.identity = (info.st_dev, info.st_ino)
            os.fchmod(self.fd, 0o600)
        except (OSError, TypeError, ValueError, AttributeError):
            self.close()
            raise Hold("refused", "private_output_unavailable") from None

    def publish(self, bundle):
        payload = _json_bytes(bundle)
        if len(payload) > MAX_OUTPUT_BYTES:
            raise Hold("refused", "prepare_output_too_large")
        try:
            offset = 0
            while offset < len(payload):
                written = os.write(self.fd, payload[offset:])
                if written <= 0:
                    raise OSError()
                offset += written
            os.fsync(self.fd)
            info = os.stat(self.path.name, dir_fd=self.directory, follow_symlinks=False)
            if (not stat.S_ISREG(info.st_mode) or (info.st_dev, info.st_ino) != self.identity
                    or info.st_nlink != 1 or info.st_mode & 0o777 != 0o600):
                raise OSError()
            os.fsync(self.directory)
        except OSError:
            raise Hold("refused", "private_output_unavailable") from None
        self.published = True
        return {"path": str(self.path), "sha256": hashlib.sha256(payload).hexdigest(),
                "bytes": len(payload), "format": "published_profile_prepare_private_v1"}

    def close(self):
        if self.fd is not None:
            try:
                if not self.published:
                    info = os.stat(self.path.name, dir_fd=self.directory, follow_symlinks=False)
                    if (info.st_dev, info.st_ino) == self.identity:
                        os.unlink(self.path.name, dir_fd=self.directory)
            except OSError:
                pass
            finally:
                os.close(self.fd)
                self.fd = None
        if self.directory is not None:
            os.close(self.directory)
            self.directory = None


def capability(profile):
    if (type(getattr(profile, "prepare_version", None)) is int and profile.prepare_version == VERSION
            and callable(getattr(profile, "prepare_config", None))):
        return {"version": VERSION, "profile_version": profile.prepare_version,
                "command": "target prepare"}
    return None


def capabilities():
    return {"version": VERSION, "producer_revision": PRODUCER_REVISION,
            "source_kind": "published_profile", "command": "target prepare",
            "profiles": {p.name: capability(p) for p in profiles.PROFILES if capability(p)},
            "max_gets": MAX_GETS, "max_response_bytes": MAX_BYTES,
            "max_seconds": MAX_SECONDS, "private_output": True,
            "observed_inputs": True, "remote_attested": False}


def _origin(url):
    try:
        if (not isinstance(url, str) or len(url) > 2048 or "\\" in url
                or any(ord(c) <= 32 or ord(c) >= 127 for c in url)):
            raise ValueError()
        p = urlsplit(url)
        if (p.scheme not in ("https", "http") or not p.hostname or p.username is not None
                or p.password is not None or p.query or p.fragment or "%" in p.netloc
                or p.netloc.endswith(":")):
            raise ValueError()
        if p.port is not None and not 1 <= p.port <= 65535:
            raise ValueError()
        return "{}://{}".format(p.scheme, p.netloc.lower())
    except (ValueError, TypeError):
        raise Hold("refused", "invalid_origin") from None


def _json_bytes(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("ascii")


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _invalid_constant(value):
    raise ValueError("non-JSON constant")


class Inputs:
    def __init__(self, slots, origin, profile, environ, allow_observed=False):
        if not isinstance(slots, list) or len(slots) > 8:
            raise Hold("refused", "invalid_credential_slots")
        self.origin = origin
        self.allow_observed, self.observed_inputs = allow_observed, []
        self.slots, self.values, self.by_slot = [], {}, {}
        for row in slots:
            if not isinstance(row, dict) or set(row) != {"origin", "in", "field", "reference"}:
                raise Hold("refused", "invalid_credential_slots")
            kind, field, ref = row["in"], row["field"], row["reference"]
            if not all(isinstance(v, str) for v in row.values()):
                raise Hold("refused", "invalid_credential_slots")
            if row["origin"] != origin:
                raise Hold("refused", "credential_scope_changed")
            key = (kind, field.lower() if kind == "header" else field)
            if key in self.by_slot or key not in profile.prepare_slots or not _REF.fullmatch(ref):
                raise Hold("refused", "ambiguous_or_unsupported_slot")
            value = environ.get(_REF.fullmatch(ref)[1])
            if not isinstance(value, str) or not value:
                raise Hold("inputs_required", "credential_reference_unresolved", dict(row))
            if len(value) > 16384 or any(ord(c) < 32 or ord(c) == 127 for c in value):
                raise Hold("refused", "unsafe_credential_value")
            if value in self.values and self.values[value] != ref:
                raise Hold("refused", "ambiguous_credential_replacement")
            self.values[value] = ref
            self.by_slot[key] = ref
            self.slots.append(dict(row))

    def required(self, kind, field):
        value = self.by_slot.get((kind, field))
        if value is None:
            raise Hold("inputs_required", "credential_slot_required",
                       {"origin": self.origin, "in": kind, "field": field})
        return value

    def capture_slot(self, slot, value, observation, url, pointer):
        if not isinstance(value, str) or not value or len(value) > 16384 or any(ord(c) < 32 for c in value):
            raise Hold("refused", "unsafe_source_credential")
        existing = self.by_slot.get(slot)
        if existing is not None:
            if self.values.get(value) != existing:
                raise Hold("conflicting_source", "observed_credential_conflict")
            return
        if not self.allow_observed:
            raise Hold("refused", "private_output_required")
        if value in self.values:
            raise Hold("refused", "ambiguous_credential_replacement")
        ident = "profile_" + slot[1]
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", ident):
            raise Hold("refused", "unsafe_observed_slot")
        reference = "input:" + ident
        self.values[value], self.by_slot[slot] = reference, reference
        self.observed_inputs.append({"id": ident, "origin": self.origin, "in": slot[0],
            "field": slot[1], "reference": reference, "value": value,
            "source_observation": observation, "source_url": url, "source_pointer": pointer})

    def validate_contract(self, headers, body):
        used = set()
        for kind, fields in (("header", headers), ("body", body)):
            for field, value in fields.items():
                text = _json_bytes(value).decode("ascii")
                if "env:" not in text and "input:" not in text:
                    continue
                expected = self.by_slot.get((kind, field.lower() if kind == "header" else field))
                if expected is None or value != expected:
                    raise Hold("refused", "undeclared_credential_placement")
                used.add(expected)
        if any(row["reference"] not in used for row in [*self.slots, *self.observed_inputs]):
            raise Hold("refused", "unused_credential_slot")

    def sanitize(self, value, extra_secret_fields=(), sensitive=False, trusted_markers=False):
        if isinstance(value, dict):
            result = {}
            for key, item in value.items():
                if any(secret in key for secret in self.values):
                    raise Hold("refused", "credential_in_property_name")
                secret = sensitive or target_secrets.is_secret_name(key) or key in extra_secret_fields
                result[key] = self.sanitize(item, extra_secret_fields, secret, trusted_markers)
            return result
        if isinstance(value, list):
            return [self.sanitize(item, extra_secret_fields, sensitive, trusted_markers) for item in value]
        if isinstance(value, str):
            if trusted_markers and (value in self.values.values() or value == "{{PROMPT}}"):
                return value
            if "env:" in value or "input:" in value or "{{" in value:
                raise Hold("refused", "unsafe_source_template")
            if sensitive and value and value not in self.values:
                raise Hold("inputs_required", "source_credential_binding_required")
            if not self.values:
                return value
            pattern = "|".join(re.escape(secret) for secret in sorted(self.values, key=len, reverse=True))
            return re.sub(pattern, lambda match: self.values[match[0]], value)
        if sensitive and value not in (None, False, 0):
            raise Hold("refused", "unsafe_source_credential")
        return value


class Reader:
    def __init__(self, origin, inputs, profile, workspace, timeout, session_factory):
        self.origin, self.inputs, self.profile = origin, inputs, profile
        self.source_slots = {origin + path.format(workspace=workspace): slots
                             for path, slots in getattr(profile, "prepare_source_slots", {}).items()}
        self.deadline = time.monotonic() + timeout
        self.observations, self.raw_captures, self.cache = [], [], {}
        self.session = session_factory()
        self.session.trust_env = False

    def close(self):
        self.session.close()

    def get(self, url, headers=None, verify=True):
        if _origin(url) != self.origin or verify is not True:
            raise Hold("refused", "read_scope_changed")
        if url in self.cache:
            return self.cache[url]
        left = self.deadline - time.monotonic()
        if len(self.observations) >= MAX_GETS or left <= 0:
            raise Hold("unavailable", "read_budget_exhausted")
        send = {"Accept": "application/json", "Accept-Encoding": "identity"}
        for name, ref in (headers or {}).items():
            if name.lower() == "content-type":
                continue
            if self.inputs.by_slot.get(("header", name.lower())) != ref:
                raise Hold("refused", "unscoped_read_header")
            send[name] = next(value for value, reference in self.inputs.values.items() if reference == ref)
        response = None
        try:
            self.session.cookies.clear()
            response = self.session.get(url, headers=send, allow_redirects=False, stream=True,
                                        verify=True, timeout=(min(3.0, left), min(3.0, left)))
            if response.url != url:
                raise Hold("refused", "read_scope_changed")
            status = response.status_code
            if type(status) is not int or not 100 <= status <= 599:
                raise Hold("unavailable", "invalid_http_status")
            if 300 <= status < 400:
                raise Hold("unavailable", "redirect_not_followed")
            if status in (401, 403):
                raise Hold("inputs_required", "source_access_refused")
            if status >= 500:
                raise Hold("unavailable", "source_unavailable")
            if status != 200:
                raise Hold("conflicting_source", "expected_profile_source_changed")
            content = bytearray()
            for chunk in response.iter_content(chunk_size=4096):
                if time.monotonic() >= self.deadline:
                    raise Hold("unavailable", "read_budget_exhausted")
                if not isinstance(chunk, bytes):
                    raise Hold("unavailable", "invalid_response_bytes")
                content.extend(chunk)
                if len(content) > MAX_BYTES:
                    raise Hold("refused", "source_too_large")
            data = json.loads(bytes(content).decode("utf-8"), object_pairs_hook=_object,
                              parse_constant=_invalid_constant)
            for key, slot in self.source_slots.get(url, {}).items():
                if isinstance(data, dict) and data.get(key):
                    self.inputs.capture_slot(slot, data[key], len(self.observations), url, "/" + key)
            sanitized = self.inputs.sanitize(data, self.profile.prepare_secret_fields)
            capture = _json_bytes(sanitized)
            self.observations.append({
                "method": "GET", "url": url, "status": status,
                "observed_at": datetime.now(timezone.utc).isoformat(),
                "raw_response_bytes_sha256": hashlib.sha256(content).hexdigest(),
                "raw_response_bytes": len(content), "raw_hash_basis": "decoded_response_entity_bytes",
                "sanitized_capture_sha256": hashlib.sha256(capture).hexdigest(),
                "sanitized_hash_basis": "canonical_json_ascii_utf8", "sanitized_data": sanitized,
                "remote_attested": False})
            self.raw_captures.append(bytes(content))
            self.cache[url] = (status, data)
            return status, data
        except requests.RequestException:
            raise Hold("unavailable", "source_unavailable") from None
        except (ValueError, UnicodeError, RecursionError):
            raise Hold("refused", "unsafe_or_invalid_source_json") from None
        finally:
            if response is not None:
                response.close()
            self.session.cookies.clear()


def _prepare(source, *, expected_profile, workspace=None, credential_slots=None,
             expected_origin=None, timeout=MAX_SECONDS, environ=None, session_factory=None, artifact=None):
    """Expected profile only. No profile detection, ambient stores or mutations."""
    out = {"version": VERSION, "producer_revision": PRODUCER_REVISION,
           "source_kind": "published_profile", "ok": False, "read_observations": [],
           "remote_attested": False}
    reader = None
    try:
        origin = _origin(source)
        profile = next((p for p in profiles.PROFILES if p.name == expected_profile), None)
        if profile is None or capability(profile) is None:
            raise Hold("unsupported", "profile_prepare_unsupported")
        out.update(profile=profile.name, profile_version=profile.prepare_version, origin=origin)
        if expected_origin is not None and expected_origin != origin:
            raise Hold("refused", "expected_origin_changed")
        if (isinstance(timeout, bool) or not isinstance(timeout, (float, int))
                or not math.isfinite(timeout) or not 0 < timeout <= MAX_SECONDS):
            raise Hold("refused", "invalid_read_budget")
        if workspace is not None and (not isinstance(workspace, str) or not _WORKSPACE.fullmatch(workspace)):
            raise Hold("refused", "invalid_workspace_selection")
        inputs = Inputs(credential_slots if credential_slots is not None else [], origin, profile,
                        os.environ if environ is None else environ, allow_observed=artifact is not None)
        reader = Reader(origin, inputs, profile, workspace, timeout, session_factory or requests.Session)
        path, field, required = profile.prepare_shape
        _, data = reader.get(origin + path)
        if not isinstance(data, dict) or data.get(field) != required:
            raise Hold("conflicting_source", "expected_profile_source_changed")
        if not workspace:
            raise Hold("selection_required", "workspace_selection_required")
        cfg, facts, fact_sources = profile.prepare_config(origin, workspace, inputs, reader.get)
        if cfg.get("adapter") != "direct_api" or cfg.get("method") != "POST" or _origin(cfg["endpoint"]) != origin:
            raise Hold("unsupported", "profile_contract_unsupported")
        body = inputs.sanitize(cfg["body"], profile.prepare_secret_fields, trusted_markers=True)
        headers = inputs.sanitize(cfg["headers"], profile.prepare_secret_fields, trusted_markers=True)
        inputs.validate_contract(headers, body)
        facts = inputs.sanitize(facts, profile.prepare_secret_fields)
        if len(_json_bytes(facts)) > 24000:
            raise Hold("refused", "profile_facts_too_large")
        out.update(ok=True, outcome="prepared", selected_workspace=workspace,
                   contract={"steps": [{"method": "POST", "url": cfg["endpoint"],
                       "redirect": "manual", "headers": headers, "body": body}],
                       "reply": {"kind": "json", "path": cfg["response_path"]}},
                   credential_slots=inputs.slots,
                   facts={**facts, "sources": fact_sources, "profile": profile.name, "selected_workspace": workspace,
                          "basis": "native_profile_and_observed_json", "local_verified": False,
                          "engine_tested": False, "stored_verified": False})
    except Hold as hold:
        out.update(ok=False, outcome=hold.outcome, error={"code": hold.code})
        if hold.requirement is not None:
            out["required_slot"] = hold.requirement
    except (ValueError, TypeError, KeyError, RecursionError):
        out.update(ok=False, outcome="refused", error={"code": "profile_contract_invalid"})
    finally:
        if reader is not None:
            out["read_observations"] = reader.observations
            reader.close()
    if artifact is not None:
        summary = {key: out[key] for key in ("version", "producer_revision", "source_kind", "ok",
                   "outcome", "profile", "profile_version", "origin", "selected_workspace", "error",
                   "required_slot", "remote_attested") if key in out}
        summary["read_observation_count"] = len(out["read_observations"])
        if out["ok"]:
            out["observed_inputs"] = inputs.observed_inputs
            for observation, raw in zip(out["read_observations"], reader.raw_captures):
                observation["raw_response_bytes_base64"] = base64.b64encode(raw).decode("ascii")
            try:
                summary["private_output"] = artifact.publish(out)
                summary["observed_input_count"] = len(inputs.observed_inputs)
            except Hold as hold:
                summary.update(ok=False, outcome=hold.outcome, error={"code": hold.code})
        return summary
    if len(_json_bytes(out)) > MAX_OUTPUT_BYTES:
        return {"version": VERSION, "producer_revision": PRODUCER_REVISION,
                "source_kind": "published_profile", "ok": False, "outcome": "refused",
                "error": {"code": "prepare_output_too_large"}, "read_observations": [],
                "observations_omitted": True, "remote_attested": False}
    return out


def prepare(source, *, private_output=None, **kwargs):
    artifact = None
    try:
        if private_output is not None:
            artifact = PrivateOutput(private_output)
        return _prepare(source, artifact=artifact, **kwargs)
    except Hold as hold:
        return {"version": VERSION, "producer_revision": PRODUCER_REVISION,
                "source_kind": "published_profile", "ok": False, "outcome": hold.outcome,
                "error": {"code": hold.code}, "remote_attested": False}
    finally:
        if artifact is not None:
            artifact.close()
