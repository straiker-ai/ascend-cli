#!/usr/bin/env python3
"""
ascend — the Ascend CLI: red-team any AI agent from one binary.

Map a target, talk to it, register it with Ascend, run its bridge, then run, watch and read the
assessments. Every command takes --json for machine/agent consumption. Auth: a Straiker PAT via
--token or $STRAIKER_PAT (exchanged for a short-lived JWT automatically). The CLI is locked to
ONE tenant at a time, deliberately — see `ascend tenant`.

The commands are listed below in the order you use them. `ascend <command> --help` has the flags
and worked examples for each; docs/COMMAND_MAP.md is the full reference.
"""
import argparse
import collections
import base64
import csv
import json
import math
import os
import re
import threading
import time
import uuid
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "control"))
sys.path.insert(0, str(REPO / "runtime"))
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "runtime"))
from configs import config_dir, resolve_config_path, candidate_paths  # shared with the bridge
from reporting import analyze as _analyze, turns as _turns
import ui as _ui  # noqa: E402  (runtime/ is on sys.path above)

VERSION = "1.0.0"


def _bundled_dir() -> Path:
    """Where read-only bundled assets live (differs when frozen by PyInstaller)."""
    meipass = getattr(sys, "_MEIPASS", None)
    return Path(meipass) if meipass else REPO


def _write_private(path, text):
    """Write a file 0600, dir 0700 — for anything that can carry customer auth (configs, generated
    adapter modules, saved evidence). These bake in bearer tokens / cookies / session ids, so they
    must not be world-readable the way `keys.json`/`jwt.json` already aren't."""
    path = Path(path)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(path.parent, 0o700)
        except OSError:
            pass
        fd = os.open(str(path), os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(text)
        os.chmod(path, 0o600)          # in case it pre-existed with looser perms
    except OSError:
        path.write_text(text)          # never lose the write over a perms hiccup
    return path


# config_dir() is imported from `configs` (line 35) — the ONE resolver shared by the
# CLI and the bridge, so a config the CLI writes is a config the runtime can find.

# Exit codes (Semgrep/Grype convention): a CI job must be able to tell
# "the target has findings" apart from "the tool broke".
EXIT_OK = 0        # clean / success
EXIT_ERROR = 1     # tool or target error
EXIT_FINDINGS = 2  # findings present / gate failed
EXIT_USAGE = 3     # bad invocation


# ----------------------------------------------------------------------------- helpers
def _client(args, *, check_tenant: bool = True):
    import api
    tok = args.token or os.environ.get("STRAIKER_PAT") or os.environ.get("STRAIKER_TOKEN")
    if not tok:
        _die("no token: pass --token or set $STRAIKER_PAT")
    c = api.AscendAPI(token=tok, base=args.base)
    if check_tenant and os.environ.get("ASCEND_SKIP_TENANT_CHECK"):
        # The lock is the guard against operating the WRONG customer's tenant. Disabling it is a
        # deliberate, dangerous act — say so, loudly, every invocation, so it can't be forgotten.
        print("\033[33m! ASCEND_SKIP_TENANT_CHECK is set — the single-tenant lock is OFF. You can "
              "cross customers.\033[0m" if _ui_color(sys.stderr) else
              "! ASCEND_SKIP_TENANT_CHECK is set — the single-tenant lock is OFF. You can cross "
              "customers.", file=sys.stderr)
    elif check_tenant:
        # SINGLE-TENANT LOCK: pin on first use, refuse another tenant thereafter. The bearer
        # exchange happens anyway on the first API call, so this costs nothing extra.
        import tenant as _tenant
        try:
            _tenant.check(c._bearer())
        except _tenant.TenantMismatch as e:
            _die(str(e))
        except Exception as exc:
            # Identity could not be determined. Do NOT silently disengage the lock — that is how a
            # decode hiccup turns into cross-customer key contamination. Warn plainly; the operator
            # can set ASCEND_SKIP_TENANT_CHECK to proceed on purpose.
            print(f"\033[33m! could not verify the tenant lock ({type(exc).__name__}). Proceeding, "
                  f"but if you work multiple customers, confirm which tenant this is "
                  f"(ascend tenant show).\033[0m" if _ui_color(sys.stderr) else
                  f"! could not verify the tenant lock ({type(exc).__name__}). Confirm the tenant: "
                  f"ascend tenant show", file=sys.stderr)
    return c


def _ui_color(stream):
    try:
        import ui as _ui
        return _ui.color_ok(stream)
    except Exception:
        return False


def _out(obj, args, human=None):
    if getattr(args, "json", False):
        print(json.dumps(obj, indent=2, default=str))
    elif human is not None:
        print(human)
    else:
        print(json.dumps(obj, indent=2, default=str))


def _wants_json() -> bool:
    """--json can appear anywhere (it is on every subparser), and errors are raised before args
    are parsed sometimes — so read argv directly."""
    return "--json" in sys.argv


def _err_json(message, *, code="error", exit_code=EXIT_ERROR, hint=""):
    """The machine-readable error envelope.

    Every failure used to be plain prose on stderr, so an agent driving `--json` could parse
    success but never failure — it had to regex English. Now stdout always carries a parseable
    object and the human text stays on stderr.
    """
    payload = {"ok": False, "error": {"code": code, "message": str(message),
                                      "hint": hint or None, "exit_code": exit_code}}
    try:
        print(json.dumps(payload, default=str))
    except Exception:
        pass


def _die(msg, code=EXIT_USAGE, *, error_code=None, hint=""):
    text = str(msg)
    if _wants_json():
        # split a trailing hint block off the human message so the JSON stays tidy
        head = text.split("\n", 1)
        _err_json(head[0], code=error_code or ("usage" if code == EXIT_USAGE else "error"),
                  exit_code=code, hint=hint or (head[1].strip() if len(head) > 1 else ""))
    print(f"error: {text}", file=sys.stderr)
    raise SystemExit(code)


def _unwrap_list(payload, *keys):
    """Return the list from an API payload, whatever envelope it uses.

    `payload.get("data", payload if isinstance(payload, list) else [])` was copy-pasted to
    five sites and is DEAD: .get is evaluated on a list first, so a bare-list response
    raises AttributeError before the fallback is reached.
    """
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for k in keys or ("data", "items", "applications", "assessments"):
            v = payload.get(k)
            if isinstance(v, list):
                return v
    return []


def _resolve_app(client, ref):
    """Accept an aapp_ id or a name; return the app id."""
    if not ref:
        _die("no application given: pass --app <name-or-aapp_id>")
    if ref.startswith("aapp_"):
        return ref
    data = client.list_apps()
    apps = _unwrap_list(data)
    matches = [a for a in apps if (a.get("name") or "") == ref]
    if not matches:
        matches = [a for a in apps if ref.lower() in (a.get("name") or "").lower()]
    if not matches:
        # "did you mean" beats "not found": app names are long and typo-prone, and the alternative
        # is the user running `app list` and scanning 38 rows by eye.
        import difflib
        names = [a.get("name") or "" for a in apps if a.get("name")]
        close = difflib.get_close_matches(ref, names, n=3, cutoff=0.5)
        hint = ""
        if close:
            hint = "\n  did you mean:  " + "\n                 ".join(repr(n) for n in close)
        elif names:
            hint = f"\n  {len(names)} apps exist — list them with:  ascend app list"
        _die(f"no app named {ref!r} (and not an aapp_ id){hint}")
    if len(matches) > 1:
        listing = "\n  ".join(f"{a.get('id')}  {a.get('name','')}" for a in matches[:10])
        _die(f"{ref!r} matches {len(matches)} apps — be more specific:\n  {listing}")
    return matches[0]["id"]



# Only a BRIDGE-BASED app needs a local bridge process. An `api` app is called directly by
# Ascend over the internet; `gcp`/`bedrock` are native cloud integrations. Flagging those as
# "no bridge" is a false alarm — and it trains people to ignore the one alarm that matters.
#
# Defined once in control/api.py so the CLI, the alarm, and the fleet cannot drift apart.
def needs_bridge(app) -> bool:
    import api
    return api.needs_bridge(app)


def _type_label(api_type) -> str:
    """CLI-facing label for an app's wire api_type. The platform's wire value is 'thin'; the Console
    and this CLI call that app type 'bridge' (it's the type that needs the CLI's built-in bridge)."""
    return "bridge" if str(api_type or "").lower() == "thin" else str(api_type or "?")


# ----------------------------------------------------------------------------- app
def _pct(v):
    return f"{float(v) * 100:.0f}%" if isinstance(v, (int, float)) else "-"


def _score(v):
    """Scores come back as long floats (97.22222222222223) — keep the column readable."""
    if v is None:
        return "-"
    if isinstance(v, (int, float)):
        return f"{float(v):.0f}" if float(v) == int(float(v)) else f"{float(v):.1f}"
    return str(v)


# Genuinely consuming probes right now — these are the ones that need a live bridge.
ACTIVE_STATES = {"running", "queued", "in_progress"}


def _latest(rows):
    """Newest assessment first — the API returns them newest-first already, but sort
    defensively on created_at so the 'LATEST' column is never a stale row."""
    return sorted(rows, key=lambda a: str(a.get("created_at") or ""), reverse=True)


def cmd_app_list(args):
    """Management view: every app, its assessments, and which ones are live."""
    c = _client(args)
    apps = _unwrap_list(c.list_apps())
    want_runs = args.with_runs or args.running or args.all_runs

    runs: Dict[str, list] = {}
    if want_runs:
        # The v3 API has no tenant-wide assessments endpoint, so this is one call per app.
        # Do them in parallel or a 40-app tenant takes ~40 round-trips serially.
        from concurrent.futures import ThreadPoolExecutor
        import ui as _ui
        def fetch(a):
            try:
                return a["id"], _assessments_for(c, a["id"])
            except Exception:
                return a["id"], []
        # One call per app (no tenant-wide endpoint), so show the work instead of a blank screen.
        with _ui.progress("reading assessments", total=len(apps), args=args) as prog:
            with ThreadPoolExecutor(max_workers=12) as pool:
                for app_id, rows in pool.map(fetch, apps):
                    runs[app_id] = _latest(rows)
                    prog.advance()

    def live_of(app_id):
        return [x for x in runs.get(app_id, [])
                if str(x.get("status", "")).lower() in RUNNING_STATES]

    if args.running:
        # "running" means ACTIVELY consuming probes (needs a live bridge) — paused/created
        # assessments are explicitly NOT running.
        apps = [a for a in apps
                if any(str(x.get("status", "")).lower() in ACTIVE_STATES
                       for x in runs.get(a.get("id"), []))]

    if args.json:
        for a in apps:
            rows = runs.get(a.get("id"), [])
            if want_runs:
                a["assessments"] = [{"id": r.get("id"), "name": r.get("name"),
                                     "status": r.get("status"), "progress": r.get("progress"),
                                     "score": r.get("score"), "severity": r.get("severity"),
                                     "created_at": r.get("created_at")} for r in rows]
                a["running_count"] = len(live_of(a.get("id")))
                a["completed_count"] = sum(
                    1 for r in rows
                    if str(r.get("status", "")).lower() in ("complete", "completed", "done"))
                a["needs_bridge"] = needs_bridge(a)
        _out(apps, args)
        return

    if not want_runs:
        for a in sorted(apps, key=lambda x: (x.get("api_type") or "", x.get("name") or "")):
            print(f"  {_type_label(a.get('api_type')):7} {a.get('id'):28} {a.get('name','')}")
        print(f"total={len(apps)}")
        print("(--with-runs adds assessment status · --running shows only live apps"
              " · --all-runs lists every assessment)")
        return

    # ---- management table -------------------------------------------------------
    hdr = (f"  {'STATE':9} {'APP':28} {'TYPE':6} {'RUNS':>4} {'DONE':>4}  "
           f"{'LATEST':26} {'PROG':>5} {'SCORE':>5} {'SEV':8} NAME")
    print(hdr)
    print("  " + "-" * (len(hdr) - 2))
    n_live = 0
    def _active(app):
        rows_ = runs.get(app.get("id"), [])
        return bool(rows_) and str(rows_[0].get("status", "")).lower() in ACTIVE_STATES
    for a in sorted(apps, key=lambda x: (not _active(x), x.get("name") or "")):
        rows = runs.get(a.get("id"), [])
        live = live_of(a.get("id"))
        latest = (live or rows or [None])[0]
        st_latest = str((latest or {}).get("status", "")).lower()
        if st_latest in ACTIVE_STATES:
            state = "*" + st_latest[:8]          # * = consuming probes, needs a live bridge
            n_live += 1
        elif rows:
            state = st_latest[:9]                 # paused / created / complete / failed
        else:
            state = "none"
        lid = (latest or {}).get("id", "-")
        prog = _pct((latest or {}).get("progress"))
        score = _score((latest or {}).get("score"))
        sev = str((latest or {}).get("severity") or "-")[:8]
        done = sum(1 for r in rows
                   if str(r.get("status", "")).lower() in ("complete", "completed", "done"))
        print(f"  {state:9} {a.get('id'):28} {_type_label(a.get('api_type')):7} {len(rows):>4} {done:>4}  "
              f"{str(lid):26} {prog:>5} {score:>5} {sev:8} {a.get('name','')}")
        if args.all_runs and len(rows) > 1:
            for r in rows[1:]:
                st = str(r.get("status", "")).lower()
                mark = "*" if st in ACTIVE_STATES else " "
                print(f"    {mark}{st:8} {'':28} {'':6} {'':>4}  {str(r.get('id')):26} "
                      f"{_pct(r.get('progress')):>5} {_score(r.get('score')):>5} "
                      f"{str(r.get('severity') or '-')[:8]:8} {r.get('name','')}")
    total_asmt = sum(len(v) for v in runs.values())
    print(f"\n  {len(apps)} app(s), {total_asmt} assessment(s), {n_live} actively running (*)")
    print("  * = consuming probes NOW · RUNS = all assessments · DONE = completed")
    print("  thin apps need a local bridge (`ascend bridge start`); api/gcp/bedrock do not")
    if n_live:
        print("  watch one:  ascend assess watch --app <app> --assessment <asmt>")


def cmd_app_get(args):
    c = _client(args)
    _out(c.get_app(_resolve_app(c, args.app)), args)


def cmd_app_resolve(args):
    c = _client(args)
    print(_resolve_app(c, args.name))



def _parse_kv_pairs(items, what):
    """`a=b` repeatable flags -> dict, with a readable error on a malformed pair."""
    out = {}
    for raw in (items or []):
        if "=" not in raw:
            _die(f"--{what} expects name=value, got {raw!r}")
        k, v = raw.split("=", 1)
        out[k.strip()] = v.strip()
    return out


def _spec_from_config(args, api):
    """Borrow url/templates/headers from a mapped adapter config.

    `ascend adapter build` already produces exactly the fields an `api` app needs, so an operator who has
    validated an adapter should not have to retype them.
    """
    if not getattr(args, "config", None):
        return {}
    try:
        path = resolve_config_path(args.config)
        cfg = json.loads(Path(path).read_text())
    except Exception:
        return {}
    out = {}
    if cfg.get("url"):
        out["url"] = cfg["url"]
    if cfg.get("headers"):
        out["headers"] = dict(cfg["headers"])
    body = cfg.get("body") or cfg.get("request_body")
    if isinstance(body, dict):
        # The mapped body carries a literal probe prompt; Ascend needs the placeholder.
        field = cfg.get("prompt_field") or "prompt"
        out["request_template"] = {**{k: v for k, v in body.items() if k != field},
                                   field: "{{PROMPT}}"}
    if cfg.get("response_path"):
        out["response_template"] = {cfg["response_path"]: "{{RESPONSE}}"}
    return out


def cmd_app_create(args):
    """Create an Ascend application of any of the four types the platform supports.

    Validation happens locally first: a missing per-type field becomes a readable message naming
    it, instead of a 422 from the API.
    """
    import api
    c = _client(args)
    at_cli = (getattr(args, "type", None) or "bridge").lower()
    # The CLI-facing type is `bridge`; the platform wire value for it is still `thin`. Map here so
    # everything downstream (build_app_spec, creds, needs_bridge) sees the wire truth.
    at = "thin" if at_cli == "bridge" else at_cli

    ctrl = args.controls.split(",") if args.controls else None
    if ctrl:
        v = c.validate_controls(ctrl)
        for w in v["warnings"]:
            print(f"warning: {w}", file=sys.stderr)
        # `v["valid"] or ctrl` used to fall back to the ORIGINAL list when nothing validated, so
        # `--controls not_a_real_control` created an app pinned to a control that does not exist.
        # It even printed "this run would generate zero probes" and created it anyway — an app
        # whose every future assessment comes back perfectly clean having tested nothing.
        if v.get("unknown") and not args.force:
            _die(f"unknown control id(s): {', '.join(v['unknown'])}\n"
                 f"  list them:  ascend controls list\n"
                 f"  a control that does not exist generates zero probes, so this app would "
                 f"score clean without ever being tested (--force to create it anyway)",
                 error_code="unknown_control")
        if not v.get("valid") and not args.force:
            _die("none of the selected controls can generate probes\n"
                 "  check:  ascend controls validate " + ",".join(ctrl) + "\n"
                 "  (--force to create the app anyway)",
                 error_code="no_scorable_controls")
        ctrl = v["valid"] or ctrl

    sev = _parse_kv_pairs(getattr(args, "category_severity", None), "category-severity")
    if sev:
        clamped = api.clamped_severities(sev)
        if clamped:
            print(f"warning: the platform's category severity enum stops at 'high' — "
                  f"clamping 'critical' to 'high' for: {', '.join(clamped)}", file=sys.stderr)

    guard = None
    if getattr(args, "input_guardrail", None):
        gt, _, gv = args.input_guardrail.partition("=")
        if not gv:
            _die("--input-guardrail expects type=value, e.g. "
                 "http_status_code=403  or  response_pattern='I can't help'")
        guard = {"type": gt.strip(), "value": [x for x in gv.split("|") if x]}

    borrowed = _spec_from_config(args, api) if at in ("api", "thin") else {}
    if at == "api" and borrowed.get("url"):
        print(f"using target from config {args.config!r}: {borrowed['url']}", file=sys.stderr)

    try:
        spec = api.build_app_spec(
            name=args.name, api_type=at,
            system_prompt=args.system_prompt, business_purpose=getattr(args, "purpose", None),
            control_ids=ctrl, assessment_size=args.size, qpm=args.qpm,
            category_severities=sev or None, input_guardrails=guard,
            strategy_type=(getattr(args, "strategy_type", None)
                           or ("custom" if getattr(args, "strategy", None) else None)),
            strategies=([x.strip() for x in args.strategy.split(",")] if getattr(args, "strategy", None) else None),
            url=getattr(args, "url", None) or borrowed.get("url"),
            api_key=getattr(args, "target_api_key", None),
            request_template=borrowed.get("request_template"),
            response_template=borrowed.get("response_template"),
            headers=borrowed.get("headers"),
            service_account_info=_read_maybe_file(getattr(args, "service_account", None)),
            bedrock_authentication_method=getattr(args, "bedrock_auth", None),
            region=getattr(args, "region", None),
            role_arn=getattr(args, "role_arn", None),
            external_id=getattr(args, "external_id", None),
            role_session_name=getattr(args, "role_session_name", None),
            access_key_id=getattr(args, "access_key_id", None),
            secret_access_key=getattr(args, "secret_access_key", None),
            session_token=getattr(args, "session_token", None),
        )
    except api.SpecError as e:
        _die(str(e), error_code="invalid_spec",
             hint=f"see docs/APP_TYPES.md for what a '{at}' application needs")

    if getattr(args, "if_not_exists", False):
        # A retried step must not leave two apps with the same name: that makes every later
        # name-based command ambiguous AND orphans the first app's one-shot bridge key.
        existing = [a for a in _unwrap_list(c.list_apps()) if (a.get("name") or "") == args.name]
        if existing:
            app = existing[0]
            _out({**app, "created": False, "reason": "an app with this name already exists"}, args,
                 human=(f"app_id:  {app.get('id')}   (already existed — not re-created)\n"
                        f"         its bridge key was only shown at creation; "
                        f"check:  ascend keys list"))
            return

    _say(args, f"Creating {_type_label(at)} application {args.name!r}...")
    app = c.create_app(spec)
    _say(args, f"created {args.name!r}  ({app.get('id')})", done=True)
    stored = False
    tc = app.get("thin_api_key")
    if at == "thin":
        # The API returns this key exactly ONCE. If it is absent (an API change, a wrong
        # api_type), storing None would print "stored" and leave an app no bridge can ever
        # serve. Fail loudly.
        _require_thin_key(tc, app.get("id"))
        try:
            import creds as C
            C.save(app.get("id"), tc, app_name=args.name, config=getattr(args, "config", None))
            stored = True
        except Exception as e:
            print(f"warning: could not store the key locally ({e}) — copy it NOW: {tc}",
                  file=sys.stderr)

    if args.json:
        _out({**app, "key_stored": stored, "needs_bridge": api.needs_bridge(app)}, args)
        return
    print(f"app_id:  {app.get('id')}")
    print(f"type:    {_type_label(app.get('api_type'))}")
    if at == "thin":
        print(f"tc_key:  {tc}   (put in $STRAIKER_BRIDGE_API_KEY — shown ONCE)")
        if stored:
            print("         stored locally too:  ascend keys list")
        print(f"bridge:  auto-managed — `ascend assess run --app {args.name!r}` starts the relay "
              f"and stops it when the run ends")
        print(f"         (or pre-start one:  ascend bridge start --app {args.name!r})")
    else:
        print(f"bridge:  not needed — Ascend calls this target directly")
    print(f"controls:{app.get('control_ids')}  size:{app.get('assessment_size')}")
    if app.get("category_severities"):
        print(f"severity:{app.get('category_severities')}")


def _read_maybe_file(v):
    """Accept an inline value or @path — service-account JSON is never pasted on a command line."""
    if not v:
        return None
    if str(v).startswith("@"):
        try:
            return Path(os.path.expanduser(str(v)[1:])).read_text()
        except OSError as e:
            _die(f"could not read {v[1:]}: {e}")
    return v


def cmd_app_update(args):
    """Change an existing app's settings in place — no delete/recreate, so the bridge key survives.

    Only the fields you pass are sent (PATCH). Covers the things you actually change on a live app:
    QPM, controls, system prompt, category severities, input guardrail, frequency, strategy.
    """
    c = _client(args)
    app_id = _resolve_app(c, args.app)
    import api
    patch = {}
    if args.name:
        patch["name"] = args.name
    if args.system_prompt:
        patch["system_prompt"] = args.system_prompt
    if getattr(args, "purpose", None):
        patch["business_purpose"] = args.purpose
    if args.qpm is not None:
        patch["max_queries_per_minute"] = args.qpm
    if args.frequency:
        patch["frequency"] = args.frequency
    if args.controls:
        ctrl = args.controls.split(",")
        v = c.validate_controls(ctrl)
        for w in v["warnings"]:
            print(f"warning: {w}", file=sys.stderr)
        if v.get("unknown"):
            _die(f"unknown control id(s): {', '.join(v['unknown'])}\n  list them: ascend controls list",
                 error_code="unknown_control")
        patch["control_type"] = "custom"
        patch["control_ids"] = v["valid"] or ctrl
    sev = _parse_kv_pairs(getattr(args, "category_severity", None), "category-severity")
    if sev:
        clamped = api.clamped_severities(sev)
        if clamped:
            print(f"warning: category severity clamps 'critical' to 'high' for: {', '.join(clamped)}",
                  file=sys.stderr)
        patch["category_severities"] = api.normalize_category_severities(sev)
    if getattr(args, "input_guardrail", None):
        gt, _, gv = args.input_guardrail.partition("=")
        if not gv:
            _die("--input-guardrail expects type=value")
        patch.update(api.build_input_guardrails(type=gt.strip(),
                                                value=[x for x in gv.split("|") if x]))
    strat = _strategy_from_args(args)
    patch.update(strat)
    if not patch:
        _die("nothing to update — pass at least one field (see: ascend app update --help)")
    _say(args, f"Updating {args.app}...")
    res = c.patch_app(app_id, patch)
    _out(res, args, human=f"updated {args.app}: {', '.join(sorted(patch))}")


def _strategy_from_args(args):
    out = {}
    if getattr(args, "strategy_type", None):
        out["strategy_type"] = args.strategy_type
    if getattr(args, "strategy", None):
        out["strategies"] = [x.strip() for x in args.strategy.split(",") if x.strip()]
        out.setdefault("strategy_type", "custom")
    return out


def cmd_assess_diff(args):
    """Compare two assessments: what's newly failing, what got fixed, what regressed.

    Promotes the baseline-diff already used by `ci` into a human command — for a before/after
    readout of a fix, or two runs of the same app.
    """
    from reporting import ci as CI
    c = _client(args)

    def _load(app, aid, filearg):
        if filearg:
            return json.loads(Path(filearg).read_text())
        if not (app and aid):
            _die("give two runs: --app X --baseline <aid> --current <aid>, or the -file forms")
        return c.get_assessment(_resolve_app(c, app), aid)

    base = _load(args.app, args.baseline, getattr(args, "baseline_file", None))
    cur = _load(args.app, args.current, getattr(args, "current_file", None))
    diff = CI.compare(base, cur)
    if args.json:
        _out({"ok": True, "data": diff}, args)
        return
    nf, rs, rg = diff["new_findings"], diff["resolved"], diff["regressions"]
    print(f"  NEW findings   {len(nf)}")
    for f in nf: print(f"    + {f['control_id']:32} {f['severity']}")
    print(f"  RESOLVED       {len(rs)}")
    for f in rs: print(f"    - {f['control_id']:32} {f.get('severity','')}")
    print(f"  REGRESSED      {len(rg)}")
    for r in rg: print(f"    ! {r['control_id']:32} {r['from_severity']} -> {r['to_severity']}")
    if not (nf or rs or rg):
        print("  no change between the two runs.")


def cmd_app_delete(args):
    """Delete an Ascend app — and clean up what only existed to serve it.

    A stored bridge key outlives its app as a dead secret on disk, and a bridge holding that key can
    never serve anything again. Keys and apps are two halves of one thing, so they are managed
    together: `--keep-key` opts out.
    """
    c = _client(args)
    app_id = _resolve_app(c, args.app)
    _say(args, f"Deleting {args.app}...")
    name = None
    try:
        name = (c.get_app(app_id) or {}).get("name")
    except Exception:
        pass

    stopped = None
    try:                                   # a live bridge for a deleted app is pointless
        import supervisor as S
        if S.is_running(app_id):
            stopped = S.stop(app_id)
    except Exception:
        pass

    res = c.delete_app(app_id)
    key_removed = False
    if not args.keep_key:
        try:
            import creds as C
            key_removed = C.remove(app_id)
        except Exception:
            pass

    payload = {"deleted": True, "app_id": app_id, "app_name": name,
               "key_removed": key_removed, "bridge_stopped": bool(stopped),
               "api_response": res}
    human = f"deleted {name or app_id}"
    if stopped:
        human += "\n  stopped its bridge"
    if key_removed:
        human += "\n  removed its stored bridge key (a key without its app is a dead secret)"
    elif args.keep_key:
        human += "\n  kept the stored key (--keep-key)"
    _out(payload, args, human=human)


# ----------------------------------------------------------------------------- controls
def cmd_controls_list(args):
    """The control catalog, and the categories it is grouped into.

    `/ascend/controls` returns BOTH lists — controls and categories — and the categories carry
    the platform's own risk tag (Security / Safety / Trust) plus display names. Showing only the
    control ids threw that away and left no way to answer "what is this category called".
    """
    c = _client(args)
    cat = c.list_controls()
    controls = _unwrap_list(cat, "controls")
    categories = _unwrap_list(cat, "categories") if isinstance(cat, dict) else []
    meta = {g.get("id"): g for g in categories}

    if args.categories:
        # The grouping view: one row per category, with its risk tag and membership count.
        if args.json:
            _out(categories, args)
            return
        live = collections.Counter(
            x.get("category_id") for x in controls if not x.get("deprecated"))
        print(f"  {'TAG':10} {'CATEGORY':34} {'NAME':28} {'ACTIVE':>6} {'TOTAL':>6}")
        print("  " + "-" * 88)
        for g in sorted(categories, key=lambda g: (g.get("tag") or "", g.get("id") or "")):
            total = len(g.get("control_ids") or [])
            active = live.get(g.get("id"), 0)
            row = (f"  {(g.get('tag') or '-'):10} {(g.get('id') or ''):34} "
                   f"{(g.get('name') or '')[:27]:28} {active:>6} {total:>6}")
            # A category with controls on paper but none active selects nothing.
            print(row + ("   !! no active controls" if total and not active else ""))
        print(f"\n  {len(categories)} categories · "
              f"tags: {', '.join(sorted({g.get('tag') or '-' for g in categories}))}")
        return

    if args.category:
        controls = [x for x in controls if x.get("category_id") == args.category]
    if args.tag:
        want = args.tag.lower()
        controls = [x for x in controls
                    if (meta.get(x.get("category_id"), {}).get("tag") or "").lower() == want]
    if not args.include_deprecated:
        controls = [x for x in controls if not x.get("deprecated")]
    if args.agentic_only:
        controls = [x for x in controls if x.get("agentic")]

    if args.json:
        _out(controls, args)
        return
    for x in controls:
        # Only render flags that are actually set — a `[--]` on every row is noise that trains
        # the eye to skip the column where the real signal lives.
        flags = []
        if x.get("deprecated"):
            flags.append("deprecated")
        if x.get("agentic"):
            flags.append("agentic")
        g = meta.get(x.get("category_id"), {})
        line = (f"  {x.get('id'):34} {(g.get('tag') or ''):9} "
                f"{(g.get('name') or x.get('category_id') or ''):26}")
        if x.get("prefix"):
            line += f" {x['prefix']}"
        print(line.rstrip() + (("  [" + ", ".join(flags) + "]") if flags else ""))
    total = len(controls)
    hidden = "" if args.include_deprecated else "  (deprecated hidden: --include-deprecated)"
    print(f"total={total}{hidden}")


def cmd_controls_validate(args):
    """Check control ids against the live catalog BEFORE a run depends on them.

    Exit codes matter here: this is the command whose whole job is catching a bad id, and it used
    to print the warning and exit 0 — so a typo'd control sailed through the check and then
    generated zero probes, producing a run that looks clean because it tested nothing.

      unknown id     -> exit 3 (the id does not exist; fix the invocation)
      deprecated id  -> warn, exit 0; exit 3 under --strict (generates zero probes)
    """
    c = _client(args)
    v = c.validate_controls(args.controls.split(","))
    bad = list(v.get("unknown") or [])
    stale = list(v.get("deprecated") or [])
    fatal = bool(bad) or bool(stale and args.strict)
    # In JSON mode emit exactly ONE object. Printing the success envelope and then dying would
    # put two objects on stdout, which is unparseable — the failure envelope carries the detail.
    if args.json and not fatal:
        _out({"ok": True, **v}, args)
    elif not args.json:
        for w in v.get("warnings") or []:
            print(f"warning: {w}", file=sys.stderr)
        if v.get("agentic"):
            print(f"note: agentic controls selected ({', '.join(v['agentic'])}) — these probe "
                  f"tool use, so the target needs its tools reachable for them to mean anything.",
                  file=sys.stderr)
        if v.get("valid"):
            print(f"OK: {v['valid']}")
    if bad:
        _die(f"{len(bad)} control id(s) do not exist: {', '.join(bad)}\n"
             f"  list them:  ascend controls list\n"
             f"  a nonexistent control generates zero probes, so the run would score nothing",
             error_code="unknown_control")
    if stale and args.strict:
        _die(f"{len(stale)} deprecated control(s): {', '.join(stale)}\n"
             f"  deprecated controls generate zero probes; drop them or run without --strict",
             error_code="deprecated_control")


def _assess_run_many(args, c, refs):
    """Start one assessment per app, concurrently. Always wait=False: a fleet is watched, not
    babysat one run at a time (`ascend assess watch --all`)."""
    from concurrent.futures import ThreadPoolExecutor
    resolved = []
    for ref in refs:
        try:
            resolved.append((ref, _resolve_app(c, ref)))
        except SystemExit:
            resolved.append((ref, None))

    def go(item):
        ref, appid = item
        if not appid:
            return {"app": ref, "error": "could not resolve this app"}
        try:
            # Auto-lifecycle: ensure a bridge per bridge-type app before the run is scheduled.
            ensure = _ensure_bridge(c, appid, args=args)
            # AscendAPI.create_assessment already verifies against the server when the response
            # is lost, and flags the result `recovered` — one implementation for both paths, so
            # the single-app and fleet forms cannot disagree about whether a run exists.
            r = c.run(appid, args.name, wait=False)
            return {"app": ref, "app_id": appid, "assessment_id": r.get("assessment_id"),
                    "status": r.get("status"), "recovered": bool(r.get("recovered")),
                    "note": r.get("recovery_note"), "bridge": ensure}
        except Exception as e:
            return {"app": ref, "app_id": appid, "error": f"{type(e).__name__}: {e}"}

    with ThreadPoolExecutor(max_workers=min(8, len(resolved))) as pool:
        out = list(pool.map(go, resolved))
    started = [r for r in out if r.get("assessment_id")]
    unbridged = [r for r in started
                 if (r.get("bridge") or {}).get("skip") or (r.get("bridge") or {}).get("error")]
    if args.json:
        _out(out, args)
    else:
        for r in out:
            if r.get("assessment_id"):
                tag = "  (recovered)" if r.get("recovered") else ""
                b = r.get("bridge") or {}
                bstate = ("bridge up" if b.get("ensured") else
                          "NO BRIDGE" if (b.get("skip") or b.get("error")) else "native")
                print(f"  started  {r['app']:28} {r['assessment_id']}  [{bstate}]{tag}")
            else:
                print(f"  FAILED   {r['app']:28} {r.get('error')}")
        print(f"\n  {len(started)}/{len(out)} assessment(s) started "
              f"(bridges auto-started for bridge-type apps)")
        if started:
            print("  watch them:  ascend assess watch --all")
        if unbridged:
            print("  ! these have NO bridge and will score a FALSE PASS until one serves them:")
            for r in unbridged:
                b = r.get("bridge") or {}
                print(f"      {r['app']}: {b.get('skip') or b.get('error')}")
    if len(started) < len(out) or unbridged:
        sys.exit(EXIT_ERROR)


# ----------------------------------------------------------------------------- assess
def _app_refs(args):
    """--app is repeatable; normalize to a list. Keeps `--app X` working unchanged."""
    v = getattr(args, "app", None)
    if v is None:
        return []
    return list(v) if isinstance(v, list) else [v]


def _app_by_id(c, app_id):
    """The app dict for an id (cached list_apps). Falls back to a bare id if not found."""
    for a in _unwrap_list(c.list_apps()):
        if a.get("id") == app_id:
            return a
    return {"id": app_id}


def _ensure_bridge(c, app, *, assessment_id=None, args=None):
    """Ensure a bridge is serving this app while an assessment needs it. NEVER raises — returns a
    small dict describing what happened. This is the invariant enforcer for the auto-lifecycle:
    a `bridge`-type app must have a live relay before its probes are scheduled, or they go
    unanswered and score a FALSE PASS. `app` may be an app dict or an app_id string."""
    import supervisor as S
    if isinstance(app, str):
        app = _app_by_id(c, app)
    app_id = app.get("id")
    if not needs_bridge(app):
        return {"app_id": app_id, "ensured": False,
                "reason": "native app — Ascend calls it directly (no bridge needed)"}
    if S.is_serving(app_id):
        return {"app_id": app_id, "ensured": True, "reused": True}
    t = _target_for(app_id)
    if t.get("skip"):
        return {"app_id": app_id, "ensured": False, "skip": t["skip"]}
    r = S.start(app_id, config=t["config"], adapter=t.get("adapter"), api_key=t["key"],
                assessment_id=assessment_id, control_token=getattr(c, "token", None),
                control_base=getattr(args, "base", None), idle_timeout_s=_default_idle_timeout_s(),
                app_name=t.get("app_name"), qpm=getattr(args, "qpm", None),
                wait_ms=getattr(args, "wait_ms", None))
    if "error" in r:
        return {"app_id": app_id, "ensured": False, "error": r["error"]}
    return {"app_id": app_id, "ensured": True, "started": True, "pid": r.get("pid")}


def _ensure_note(res):
    """One human line describing an _ensure_bridge result (or None to stay quiet)."""
    if res.get("reused"):
        return "bridge: already serving this app — reused."
    if res.get("started"):
        return f"bridge: started for this run (pid {res.get('pid')}); it self-stops when the run ends."
    if res.get("skip") or res.get("error"):
        return (f"! bridge NOT started ({res.get('skip') or res.get('error')}). Probes will go "
                f"unanswered and score a FALSE PASS — start one: ascend bridge start --app <name>")
    return None


def cmd_assess_run(args):
    c = _client(args)
    refs = _app_refs(args)
    if not refs and not getattr(args, "all_bound", False):
        _die("pass --app <name> (repeatable) or --all-bound")
    if getattr(args, "all_bound", False):
        import creds as C
        refs = list(dict.fromkeys(refs + list(C.load_all())))
    # Validate the control set ONCE, not per app (each call refetches the whole catalog).
    if args.controls:
        v = c.validate_controls(args.controls.split(","))
        for w in v["warnings"]:
            print(f"warning: {w}", file=sys.stderr)
        if not v["valid"] and not args.force:
            _die("selected controls generate zero probes (use --force to run anyway)")

    if len(refs) > 1:
        return _assess_run_many(args, c, refs)

    appid = _resolve_app(c, refs[0])
    args.app = refs[0]              # downstream messages expect a scalar
    # Auto-lifecycle: a bridge-type app needs a live relay BEFORE probes are scheduled, or the very
    # first probes go unanswered (a false pass). Ensure it up front; it self-stops when the run ends.
    ensure = _ensure_bridge(c, appid, args=args)
    _note = _ensure_note(ensure)
    if _note:
        print(f"  {_note}", file=sys.stderr)
    _say(args, f"Starting assessment {args.name!r} on {refs[0]}...")
    if not args.no_wait:
        # Star header + live probe feed while the run blocks. Each poll's aggregate counts feed the
        # star-bulleted probe lines and the subtitle. Non-TTY / --json falls back to plain _tick.
        tw = _TwinkleBanner(f"running · {refs[0]} · starting")
        def _tw_tick(status, prog, a):
            total = a.get("total") or 0
            failed = a.get("failed") or 0
            completed = int(round((prog or 0) * total)) if total else 0
            tw.push_progress(completed, failed, total)
            tw.set_subtitle(f"running · {refs[0]} · {status}  {int(round((prog or 0) * 100))}%")
        feed_interval = min(args.interval, 4) if tw.enabled else args.interval
        with tw:
            res = c.run(appid, args.name, wait=True,
                        interval=feed_interval, timeout=args.timeout,
                        on_tick=(_tw_tick if tw.enabled else (None if args.json else _tick)))
    else:
        res = c.run(appid, args.name, wait=False,
                    interval=args.interval, timeout=args.timeout, on_tick=None)
    if isinstance(res, dict) and res.get("assessment_id"):
        _say(args, f"assessment started  ({res['assessment_id']})", done=True)
    import api
    # --no-wait returns {app_id, assessment_id, status}; summarizing that prints a phantom
    # "risk ? score ? probes ?/?" header. Only summarize a real assessment payload.
    human = (api.summarize_result(res)
             if isinstance(res, dict) and res.get("category_summary") is not None else None)
    if isinstance(res, dict) and res.get("recovered"):
        print(f"note: {res.get('recovery_note')} — not re-created.", file=sys.stderr)
    if human is None and isinstance(res, dict) and res.get("assessment_id"):
        human = (f"assessment {res['assessment_id']} started\n"
                 f"  watch:    ascend assess watch --app {args.app} --assessment {res['assessment_id']}\n"
                 f"  findings: ascend assess results --app {args.app} "
                 f"--assessment {res['assessment_id']} --detail")
    _out(res, args, human=human)
    # Bridge-type app but no relay could be ensured: the run exists but will score a FALSE PASS
    # until a bridge answers it. Exit non-zero so a pipeline notices — the run was created either way.
    if ensure.get("skip") or ensure.get("error"):
        sys.exit(EXIT_ERROR)


def _tick(status, prog, a):
    print(f"  status={status} progress={prog}", file=sys.stderr)


def cmd_assess_status(args):
    """Back-compat alias: `assess status` is `assess watch --once`."""
    args.once = True
    args.all = False
    args.interval = 1
    args.detail = getattr(args, "detail", False)
    args.include_done = True
    return cmd_assess_watch(args)


def _watch_many(args, c):
    """One table over every live assessment, refreshed in place. Also shows whether a bridge is
    actually serving each run — a run nobody answers finishes as a FALSE PASS."""
    import api
    from concurrent.futures import ThreadPoolExecutor
    try:
        import supervisor as S
    except Exception:
        S = None

    refs = _app_refs(args)
    apps = _unwrap_list(c.list_apps())
    if refs:
        wanted = {_resolve_app(c, r) for r in refs}
        apps = [a for a in apps if a.get("id") in wanted]

    def latest(a):
        try:
            return a, _latest(_assessments_for(c, a["id"]))
        except Exception:
            return a, []

    tty = sys.stdout.isatty() and not args.json
    printed = 0
    try:
        while True:
            with ThreadPoolExecutor(max_workers=12) as pool:
                pairs = list(pool.map(latest, apps))
            live_relays = {}
            if S:
                try:
                    live_relays = {r["app_id"]: r for r in S.ls() if r["state"] == "serving"}
                except Exception:
                    pass
            rows = []
            for a, asmts in pairs:
                if not asmts:
                    continue
                top = asmts[0]
                st = str(top.get("status", "")).lower()
                if st not in RUNNING_STATES and not args.include_done:
                    continue
                rel = live_relays.get(a["id"])
                if rel:
                    bridge = f"serving({(rel.get('stats') or {}).get('answered', '?')})"
                elif needs_bridge(a):
                    bridge = "NONE"
                else:
                    bridge = "n/a"          # api/gcp/bedrock: Ascend calls the target directly
                rows.append({"app": a.get("name"), "app_id": a["id"], "assessment": top.get("id"),
                             "status": st, "progress": top.get("progress"), "score": top.get("score"),
                             "severity": top.get("severity"), "bridge": bridge})
            if args.json:
                print(json.dumps(rows, default=str), flush=True)
            else:
                if tty and printed:
                    sys.stdout.write(f"\033[{printed}A")     # repaint in place
                buf = []
                hdr = (f"  {'STATUS':10} {'PROG':>5} {'SCORE':>6} {'SEV':8} {'BRIDGE':14} "
                       f"{'ASSESSMENT':26} APP")
                buf.append(hdr); buf.append("  " + "-" * (len(hdr) - 2))
                for r in sorted(rows, key=lambda x: (x["status"] not in ACTIVE_STATES, x["app"] or "")):
                    buf.append(f"  {r['status']:10} {_pct(r['progress']):>5} "
                               f"{_score(r['score']):>6} {str(r['severity'] or '-')[:8]:8} "
                               f"{r['bridge']:14} {str(r['assessment']):26} {r['app'] or ''}")
                if not rows:
                    buf.append("  (no live assessments)")
                orphan = [r for r in rows if r["bridge"] == "NONE" and r["status"] in ACTIVE_STATES]
                buf.append(f"\n  {len(rows)} run(s)" + (
                    f" · !! {len(orphan)} with NO bridge (probes unanswered => FALSE PASS)" if orphan else ""))
                out = "\n".join(f"{l:<118}" for l in buf)
                print(out, flush=True)
                printed = len(buf)
            if rows and all(r["status"] in api.TERMINAL_STATUSES for r in rows):
                return
            if not rows:
                return
            time.sleep(max(3, args.interval))
    except KeyboardInterrupt:
        print("\ndetached (runs continue server-side)", file=sys.stderr)


def cmd_assess_watch(args):
    """Live view of a running assessment — re-renders until it finishes.

    Answers "what is it doing right now?" without hammering the Console. Ctrl-C
    detaches; the run continues server-side.
    """
    import api
    c = _client(args)
    if getattr(args, "all", False) or len(_app_refs(args)) > 1:
        return _watch_many(args, c)
    refs = _app_refs(args)
    if not refs:
        _die("pass --app <name>, or --all to watch every live assessment")
    args.app = refs[0]
    appid = _resolve_app(c, refs[0])
    aid = args.assessment
    if not aid:                       # default to the one that is actually running
        live = [a for a in _assessments_for(c, appid)
                if str(a.get("status", "")).lower() in RUNNING_STATES]
        if not live:
            _die("no running assessment for this app; pass --assessment <id>")
        aid = live[0]["id"]
        print(f"watching {aid}", file=sys.stderr)
    tty = sys.stdout.isatty() and not args.json
    last = None
    try:
        while True:
            a = c.get_assessment(appid, aid)
            st = str(a.get("status", "?")).lower()
            if args.json:
                print(json.dumps(a, default=str), flush=True)
            else:
                prog = a.get("progress")
                pct = float(prog) * 100 if isinstance(prog, (int, float)) else 0.0
                bar = "#" * int(pct / 5) + "." * (20 - int(pct / 5))
                line = (f"[{bar}] {pct:5.1f}%  status={st}  "
                        f"failed={a.get('failed', '-')}/{a.get('total', '-')}")
                if tty:
                    print("\r" + line + " " * 8, end="", flush=True)
                elif line != last:
                    print(line, flush=True)
                last = line
            if st in api.TERMINAL_STATUSES:   # shared set: never hang on done/canceled
                if tty:
                    print()
                print("", file=sys.stderr)
                _out(a, args, human=api.summarize_result(a, detail=args.detail))
                return
            if getattr(args, "once", False):
                # One snapshot, then out — what `assess status` used to be. Reported through the
                # same code path so the two can never disagree about a run's state.
                if tty:
                    print()
                if not args.json:
                    _out(a, args, human=(
                        f"status={a.get('status')} progress={a.get('progress')} "
                        f"failed={a.get('failed','-')}/{a.get('total','-')} severity={a.get('severity')}"))
                return
            time.sleep(args.interval)
    except KeyboardInterrupt:
        if tty:
            print()
        print("detached (the run continues server-side)", file=sys.stderr)


def _false_pass_warning(a):
    """A run whose bridge was dead still COMPLETES — unanswered probes aren't findings, so it can
    read as `score 0 / low` from nothing. Say so instead of letting a clean number be trusted."""
    status = str(a.get("status", "")).lower()
    if status not in ("complete", "completed", "done"):
        return None
    total = a.get("total")
    try:
        tiny = total is not None and int(total) <= 4
    except (TypeError, ValueError):
        tiny = False
    clean = not a.get("failed") or str(a.get("severity", "")).lower() == "low"
    if tiny and clean:
        return ("  !! only %s probe(s) recorded on a clean result — if the bridge was not running for\n"
                "     the whole run, unanswered probes score as no findings (a FALSE PASS).\n"
                "     check:  ascend bridge ls   ·   docs/ASSESSMENT_LIFECYCLE.md" % total)
    return None


def cmd_assess_results(args):
    c = _client(args)
    a = c.get_assessment(_resolve_app(c, args.app), args.assessment)
    import api
    human = api.summarize_result(a, detail=getattr(args, "detail", False))
    warn = _false_pass_warning(a)
    if warn and not args.json:
        human = f"{human}\n\n{warn}"
    _out(a, args, human=human)


def _assessments_for(c, appid):
    data = c._req("GET", f"/ascend/applications/{appid}/assessments")
    return _unwrap_list(data, "data", "assessments")


RUNNING_STATES = {"running", "created", "paused", "queued", "in_progress"}


def cmd_assess_list(args):
    c = _client(args)
    appid = _resolve_app(c, args.app)
    rows = _assessments_for(c, appid)
    if args.running:
        rows = [a for a in rows if str(a.get("status", "")).lower() in RUNNING_STATES]
    if args.json:
        _out(rows, args)
        return
    if not rows:
        print("no assessments" + (" running" if args.running else ""))
        return
    print(f"{'STATUS':10} {'PROGRESS':9} {'SCORE':6} {'ID':26} NAME")
    for a in rows:
        st = str(a.get("status", "?")).lower()
        live = "*" if st in RUNNING_STATES else " "
        prog = a.get("progress")
        prog = f"{float(prog) * 100:.0f}%" if isinstance(prog, (int, float)) else "-"
        score = a.get("score")
        print(f"{live}{st:9} {prog:9} {str(score if score is not None else '-'):6} "
              f"{a.get('id', '?'):26} {a.get('name', '')}")
    n_live = sum(1 for a in rows if str(a.get("status", "")).lower() in RUNNING_STATES)
    print(f"\n{len(rows)} assessment(s); {n_live} running (*)")
    if n_live:
        live_one = next(a for a in rows if str(a.get("status", "")).lower() in RUNNING_STATES)
        print(f"watch it:  ascend assess watch --app {args.app} --assessment {live_one['id']}")


def cmd_assess_pause(args):
    c = _client(args)
    _say(args, f"Pausing {args.assessment}...")
    res = c.pause(_resolve_app(c, args.app), args.assessment)
    # Probes are generated up front and cannot be recalled: pause stops NEW scheduling, but
    # already-created probes still run their course. Say so, or the drain looks like a bug.
    _out(res, args, human="paused — note: probes already generated will still drain, so your "
                          "target may keep receiving prompts for a while.\n"
                          "  the bridge stays up while paused and self-stops after 30 min idle; "
                          "`ascend assess resume` brings it back.")


def cmd_assess_resume(args):
    c = _client(args)
    appid = _resolve_app(c, args.app)
    _say(args, f"Resuming {args.assessment}...")
    res = c.resume(appid, args.assessment)
    # The reliable answer to "resumed from the Console": the local relay may have idle-stopped or
    # never existed on this machine, so re-ensure it before probes flow again.
    ensure = _ensure_bridge(c, appid, assessment_id=args.assessment, args=args)
    note = _ensure_note(ensure)
    _out(res, args, human="running" + (f"\n  {note}" if note else ""))
    if ensure.get("skip") or ensure.get("error"):
        sys.exit(EXIT_ERROR)


# ----------------------------------------------------------------------------- runtime
_STARTUP_GRACE_S = 120.0     # never self-stop within this of startup (ensure-before-create, new apps)


def _default_idle_timeout_s():
    """Default idle-cleanup timeout for a bridge, in seconds.

    OFF (0) by default: the bridge stops when its run reaches a terminal state and never idle-kills
    a paused/stalled run — reaping during a stall was the cause of bridges dying mid-run. Set
    $ASCEND_BRIDGE_IDLE_TIMEOUT to a positive number to opt into idle cleanup across EVERY path,
    including the auto-managed `assess run` / `assess resume` flows that spawn the bridge themselves
    (a `bridge start` flag can't reach those). Env-override contributed by a design-partner PR.
    """
    try:
        v = int(os.environ.get("ASCEND_BRIDGE_IDLE_TIMEOUT") or 0)
    except (TypeError, ValueError):
        return 0
    return v if v > 0 else 0


def _resolve_idle(args):
    """An explicit --idle-timeout wins (incl. an explicit 0 = force off); otherwise the env default."""
    a = getattr(args, "idle_timeout", None)
    return a if a is not None else _default_idle_timeout_s()


def _reconcile_decision(assessments, *, now, started_at, last_probe_ts,
                        idle_timeout_s, control_ok):
    """The pure decision at the heart of the self-reconciling bridge: 'serve' | 'stop-terminal' |
    'stop-idle'. No I/O, so it is unit-tested directly.

    The only reliable stop signal is the run reaching a TERMINAL state. The bridge rides through
    created/paused/stalled states rather than self-kill during a platform hiccup — an unanswered
    probe scores a FALSE PASS, so the safe direction is always to keep serving. Idle cleanup is
    OPT-IN (idle_timeout_s > 0) and reaps ONLY a run that is genuinely paused, has actually relayed
    a probe, and has since gone quiet. It never reaps a created/queued/running run, nor one that has
    never been probed. Per-app: a shared bridge stays up while ANY assessment is non-terminal."""
    if not control_ok:
        return "serve"                        # could not read the platform — never self-kill
    if now < (started_at or 0) + _STARTUP_GRACE_S:
        return "serve"                        # startup grace: ensure-before-create / brand-new app
    active = [a for a in assessments
             if str(a.get("status", "")).lower() in RUNNING_STATES]
    if not active:
        return "stop-terminal"                # every assessment on this app is terminal
    if not idle_timeout_s or idle_timeout_s <= 0:
        return "serve"                        # default: stop only on terminal, never idle-kill
    # Opt-in idle cleanup, and only for a run that genuinely paused AFTER doing work.
    if not last_probe_ts:
        return "serve"                        # never probed — the run never really started
    if any(str(a.get("status", "")).lower() != "paused" for a in active):
        return "serve"                        # anything running/queued/created — keep serving
    return "stop-idle" if (now - last_probe_ts) >= idle_timeout_s else "serve"


def cmd_runtime_start(args):
    import run as runtime_run
    from dispatch import ConfigError
    key = args.api_key or os.environ.get("STRAIKER_BRIDGE_API_KEY")
    if not key:
        # Resolve from the local key store when the caller named an app instead of a key.
        if getattr(args, "app", None):
            import creds as C
            app_ref = args.app
            app_id = app_ref if str(app_ref).startswith("aapp_") else _resolve_app(_client(args), app_ref)
            key = C.key_for(app_id)
            if not key:
                _die(f"no stored bridge key for {app_ref!r}.\n"
                     f"  add one:  ascend keys add --app {app_ref} --key tc-…   (or pass --api-key)")
        else:
            _die("no bridge key: pass --api-key, or --app <name> to use a stored key, "
                 "or set $STRAIKER_BRIDGE_API_KEY")
    try:
        client = runtime_run.build_runtime(
            key, args.adapter, args.config, base_url=args.bridge_base,
            qpm=args.qpm, max_workers=args.max_workers, capture_path=args.capture,
            wait_ms=args.wait_ms, consumer=getattr(args, "consumer", None))
    except (FileNotFoundError, ConfigError, json.JSONDecodeError) as e:
        # A bad/missing config is a usage error (exit 3), the same class the CLI-resolved
        # commands use — not a tool crash (exit 1) via the global boundary.
        _die(str(e))
    import signal
    signal.signal(signal.SIGINT, lambda *_: client.stop())
    signal.signal(signal.SIGTERM, lambda *_: client.stop())
    import logging
    log_kw = {"level": logging.INFO,
              "format": "%(asctime)s %(levelname)s %(name)s: %(message)s"}
    if getattr(args, "log_file", None):
        log_kw["filename"] = os.path.expanduser(args.log_file)   # legacy bridge had log.file
    logging.basicConfig(**log_kw)

    # Heartbeat: stats live inside this process, so a supervising parent can only see
    # answered/failed counts if we publish them. Without this a dead bridge is indistinguishable
    # from a quiet one — and a dead bridge silently produces a FALSE PASS.
    status_file = getattr(args, "status_file", None)
    if status_file:
        import threading
        import supervisor as S
        app_id = os.environ.get("ASCEND_RELAY_APP_ID") or args.config

        # Self-reconcile: the bridge polls its app's assessment state and self-stops when the app
        # goes terminal (or, if paused, after the idle timeout). It must reach the control plane, so
        # build the client DIRECTLY (never _client() — that would _die on the tenant lock).
        self_reconcile = not getattr(args, "no_self_reconcile", False)
        idle_timeout_s = _resolve_idle(args)
        tracked_id = getattr(args, "assessment_id", None)
        control = None
        if self_reconcile:
            try:
                import api
                tok = os.environ.get("STRAIKER_PAT") or os.environ.get("STRAIKER_TOKEN")
                if tok:
                    control = api.AscendAPI(
                        token=tok,
                        base=(os.environ.get("ASCEND_CONTROL_BASE") or api.DEFAULT_BASE))
            except Exception:
                control = None

        def _beat():
            n = 0
            while True:
                rec = S.read_status(app_id) or {}
                rec.update({"app_id": app_id, "config": args.config, "adapter": args.adapter,
                            "pid": os.getpid(), "ts": time.time(),
                            "state": "serving" if not client.fatal_error else "fatal",
                            "stats": dict(client.stats),
                            "assessment_id": tracked_id or rec.get("assessment_id"),
                            "fatal_error": client.fatal_error})
                rec.setdefault("started_at", time.time())
                # Reconcile on a slower cadence (~every 3rd beat = 30s) to bound control-plane load.
                if control is not None and n % 3 == 0:
                    try:
                        asmts = _assessments_for(control, app_id)
                        rec["reconcile_error"] = None
                        cur = None
                        if tracked_id:
                            cur = next((a for a in asmts if a.get("id") == tracked_id), None)
                        cur = cur or (_latest(asmts)[0] if asmts else None)
                        rec["asmt_status"] = (cur or {}).get("status")
                        decision = _reconcile_decision(
                            asmts, now=time.time(), started_at=rec.get("started_at"),
                            last_probe_ts=client.last_probe_ts,
                            idle_timeout_s=idle_timeout_s, control_ok=True)
                    except Exception as e:
                        # Could not verify — keep serving. Never self-kill on a transient error:
                        # an unanswered probe scores a FALSE PASS.
                        rec["reconcile_error"] = f"{type(e).__name__}: {e}"
                        decision = "serve"
                    if decision != "serve":
                        rec["state"] = ("stopped-complete" if decision == "stop-terminal"
                                        else "stopped-idle")
                        try:
                            S.write_status(app_id, rec)
                        except Exception:
                            pass
                        logging.getLogger("ascendbridge").info(
                            "self-reconcile: %s — stopping bridge for %s", decision, app_id)
                        client.stop()
                        return
                try:
                    S.write_status(app_id, rec)
                except Exception:
                    pass
                if client.fatal_error:
                    return
                n += 1
                time.sleep(10)

        threading.Thread(target=_beat, daemon=True).start()
    client.run_forever()


# ----------------------------------------------------------------------------- adapter
def cmd_adapter_list(args):
    sys.path.insert(0, str(REPO / "runtime"))
    import dispatch
    _out(sorted(dispatch.ADAPTER_REGISTRY), args,
         human="\n".join(sorted(dispatch.ADAPTER_REGISTRY)))


def cmd_adapter_configs(args):
    """List adapter configs on disk (there was previously no way to discover them)."""
    d = config_dir()
    rows = []
    for f in sorted(d.glob("*.json")):
        try:
            cfg = json.loads(f.read_text())
        except Exception:
            cfg = {}
        rows.append({"name": f.stem, "adapter": cfg.get("adapter", "?"),
                     "example": f.stem.startswith("example-"),
                     "note": cfg.get("_comment", "")[:70]})
    if args.json:
        _out(rows, args)
    else:
        if not rows:
            print(f"no configs in {d}")
            return
        print(f"{'NAME':28}  {'ADAPTER':18}  NOTE")
        for r in rows:
            print(f"{r['name']:28}  {r['adapter']:18}  {r['note']}")
        print(f"\n{len(rows)} config(s) in {d}")
        print("copy an example:  cp configs/example-direct_api.json configs/mybot.json")


def cmd_adapter_show(args):
    """Print a saved adapter config, with secrets masked.

    A built config routinely carries whatever authenticated the browser — `adapter build --curl` preserves
    the request body verbatim, so a session token or access key ends up in the file. This used to
    print it in clear, which meant a screen-share, a pasted snippet or a demo recording leaked a
    live credential. `--reveal` prints it raw when that is genuinely what you need.
    """
    cfg = _load_named_config(args.config)
    # A code adapter's real content is its MODULE, not the thin pointer config. "show the adapter"
    # should show the code the bridge runs.
    if cfg.get("adapter") == "custom" and (cfg.get("adapter_module") or cfg.get("module")):
        try:
            from runtime.adapters.custom_module import _resolve_module_path
            mp = _resolve_module_path(cfg)
            if args.json:
                _out({"adapter": "custom", "module": str(mp), "source": mp.read_text()}, args)
            else:
                print(f"# {mp}  (the app's adapter — the code the bridge runs)\n")
                print(mp.read_text())
                print(f"\n# pointer config: {resolve_config_path(args.config)}", file=sys.stderr)
            return
        except Exception as exc:
            if not args.json:
                print(f"  (could not load the adapter module: {exc})", file=sys.stderr)
    if getattr(args, "reveal", False):
        _out(cfg, args)
        return
    import manual
    shown = manual.redact(cfg)
    _out(shown, args)
    if shown != cfg and not args.json:
        print("  (secrets masked — `ascend adapter show <config> --reveal` to see them)",
              file=sys.stderr)


def cmd_adapter_layers(args):
    doc = _bundled_dir() / "docs" / "CAPABILITY_MATRIX.md"
    print(doc.read_text() if doc.exists() else "capability matrix doc missing")




# ----------------------------------------------------------------------------- chat
def _kv_headers(pairs):
    """Parse repeated --header 'Name: value' into a dict."""
    out = {}
    for item in pairs or []:
        if ":" not in item:
            _die(f"--header must look like 'Name: value' (got {item!r})")
        k, v = item.split(":", 1)
        out[k.strip()] = v.strip()
    return out


def _target_auth(args):
    """Fold the target-auth flags (--bearer/--api-key/--basic/--cookie/--token-file/--header)
    into (headers, query_params). Header-based so it rides the existing config `headers`
    passthrough all the way into probe/capture/validate/runtime — no special-casing per source.
    """
    import base64
    headers = _kv_headers(getattr(args, "header", None))
    query = {}
    tok = getattr(args, "bearer", None)
    tf = getattr(args, "token_file", None)
    if tf:
        p = Path(os.path.expanduser(tf))
        if not p.is_file():
            _die(f"--token-file not found: {tf}")
        tok = p.read_text().strip()
    if tok:
        headers.setdefault("Authorization", f"Bearer {tok}")
    ak = getattr(args, "api_key", None)
    if ak:
        loc = "header"
        if ":in=" in ak:
            ak, loc = ak.rsplit(":in=", 1)
        if ":" not in ak:
            _die("--api-key must be NAME:VALUE[:in=header|query]")
        name, value = ak.split(":", 1)
        (query if loc == "query" else headers)[name.strip()] = value
    basic = getattr(args, "basic", None)
    if basic:
        if ":" not in basic:
            _die("--basic must be USER:PASS")
        headers["Authorization"] = "Basic " + base64.b64encode(basic.encode()).decode()
    ck = getattr(args, "cookie", None)
    if ck:
        headers["Cookie"] = ck
    return headers, query


def _login_for_token(args):
    """Perform the login / access-code exchange: POST --login-body to --login-url, then
    pull the token at --token-path (or reuse a Set-Cookie session). Returns headers to add
    AND an `auth` block so the bridge re-authenticates on its own during a long run."""
    import requests
    url = args.login_url
    try:
        body = json.loads(args.login_body) if args.login_body else {}
    except json.JSONDecodeError as e:
        _die(f"--login-body is not valid JSON: {e}")
    print(f"[build] logging in at {url} ...", file=sys.stderr)
    try:
        r = requests.post(url, json=body, timeout=args.timeout,
                          verify=not getattr(args, "insecure", False),
                          allow_redirects=True)
    except requests.RequestException as e:
        _die(f"login request failed: {e}", code=EXIT_ERROR)
    if r.status_code >= 400:
        _die(f"login returned HTTP {r.status_code}: {r.text[:200]}", code=EXIT_ERROR)
    headers = {}
    # 1) a token in the JSON body at --token-path
    tok = None
    try:
        obj = r.json()
        tok = obj
        for part in str(args.token_path).split("."):
            tok = tok.get(part) if isinstance(tok, dict) else None
    except ValueError:
        tok = None
    if tok:
        headers["Authorization"] = f"Bearer {tok}"
        print(f"[build] got a token at '{args.token_path}' ({len(str(tok))} chars)", file=sys.stderr)
    # 2) otherwise ride the session cookie the login set
    elif r.cookies:
        jar = "; ".join(f"{c.name}={c.value}" for c in r.cookies)
        headers["Cookie"] = jar
        print(f"[build] no token at '{args.token_path}'; using the login session cookie", file=sys.stderr)
    else:
        _die(f"login succeeded but no token at '{args.token_path}' and no session cookie was set.\n"
             f"  response: {r.text[:200]}", code=EXIT_ERROR)
    return headers


def _body_fields(args):
    """Parse repeated --body-field key=value into a dict.

    Some agents carry their credential (and tenant/workspace selector) in the JSON BODY rather
    than a header, so a header-only auth story cannot reach them at all. `key:=raw` passes a
    JSON literal (true / 7 / {"a":1}) instead of a string.
    """
    out = {}
    for item in getattr(args, "body_field", None) or []:
        if ":=" in item:
            k, v = item.split(":=", 1)
            try:
                out[k.strip()] = json.loads(v)
            except json.JSONDecodeError:
                _die(f"--body-field {k.strip()}:= expects JSON (got {v!r})")
        elif "=" in item:
            k, v = item.split("=", 1)
            out[k.strip()] = v
        else:
            _die(f"--body-field must look like key=value (got {item!r})")
    return out


def _bake_body_fields(cfg, fields):
    """Merge extra body fields into whichever body the discovered config uses."""
    if not fields:
        return cfg
    for key in ("body", "request_template"):
        if isinstance(cfg.get(key), dict):
            cfg[key] = {**cfg[key], **fields}
            return cfg
    msg = cfg.get("message")                     # sentinel_stream / session-style configs
    if isinstance(msg, dict) and isinstance(msg.get("body"), dict):
        msg["body"] = {**msg["body"], **fields}
        return cfg
    cfg["body"] = {**fields}
    return cfg


def _bake_auth(cfg, headers, query):
    """Merge target-auth headers/query into a discovered config so it carries its own auth.
    Query keys already present on the URL (e.g. the probe folded them in) are not doubled."""
    if headers:
        cfg["headers"] = {**(cfg.get("headers") or {}), **headers}
    if query:
        key = "endpoint" if "endpoint" in cfg else ("url" if "url" in cfg else None)
        if key:
            url = cfg[key] or ""
            new = {k: v for k, v in query.items() if f"{k}=" not in url}
            if new:
                sep = "&" if "?" in url else "?"
                cfg[key] = url + sep + "&".join(f"{k}={v}" for k, v in new.items())
    return cfg


def _write_discovered(cfg, args):
    """Resolve --out through the ONE config dir (bare names land where --config finds them),
    normalize the extension, and return (path or None) with a resolvable next-step name."""
    if not args.out:
        return None
    out_path = Path(os.path.expanduser(args.out))
    if out_path.parent == Path("."):                 # bare name -> shared config dir
        name = out_path.name
        if not name.endswith(".json"):
            name += ".json"
        out_path = config_dir() / name
    out_path.parent.mkdir(parents=True, exist_ok=True)
    _write_private(out_path, json.dumps(cfg, indent=2))
    return out_path


def adapter_needs_path(cfg):
    return (cfg.get('adapter') or 'direct_api') in ('direct_api', 'api')


def _answer_candidates(obj, prefix=""):
    """Every string/number leaf in a response, as (dotpath, value). For the response-path picker."""
    out = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            out += _answer_candidates(v, f"{prefix}.{k}" if prefix else k)
    elif isinstance(obj, list):
        for i, v in enumerate(obj[:5]):
            out += _answer_candidates(v, f"{prefix}.{i}")
    elif isinstance(obj, (str, int, float)) and str(obj).strip():
        out.append((prefix, str(obj)))
    return out


def _choose_response_path(response_text, known_answer, args):
    """Resolve where the answer lives in the response.

    Explicit --response-path always wins (scriptable). Otherwise, on a TTY, show the candidate
    fields from the ACTUAL captured response and let the operator pick — the one decision the parser
    genuinely cannot make when several fields could be 'the answer'. Non-interactive: returns None
    (the live gate still runs; the operator can re-run with --response-path).
    """
    if getattr(args, "response_path", None):
        return args.response_path.strip()
    try:
        obj = json.loads(response_text) if isinstance(response_text, str) else response_text
    except (ValueError, TypeError):
        return None
    cands = _answer_candidates(obj)
    if not cands:
        return None
    # rank: the field whose value looks most like the answer we already saw, first
    ans = (known_answer or "").strip()
    def score(c):
        path, val = c
        sc = min(len(val), 400) / 100.0
        if ans and ans[:40] in val:
            sc += 100
        if ans and val.strip() == ans:
            sc += 50
        low = path.lower()
        if any(w in low for w in ("reply", "answer", "message", "text", "content", "response", "output")):
            sc += 5
        if any(w in low for w in ("id", "status", "code", "token", "time", "echo", "prompt", "input")):
            sc -= 5
        return sc
    cands.sort(key=score, reverse=True)
    if not (sys.stdin.isatty() and not getattr(args, "json", False)):
        return None                       # can't prompt; leave it to the gate / --response-path
    print("\n  Which field is the bot's ANSWER? The response has these values:", file=sys.stderr)
    show = cands[:8]
    for i, (path, val) in enumerate(show, 1):
        preview = (val[:70] + "…") if len(val) > 70 else val
        print(f"    {i}. {path:26} {preview!r}", file=sys.stderr)
    print("    0. none of these / it streams — skip and let the live check decide", file=sys.stderr)
    try:
        raw = input("  pick a number [1]: ").strip() or "1"
    except (EOFError, KeyboardInterrupt):
        return None
    if raw == "0" or not raw.isdigit():
        return None
    n = int(raw)
    return show[n-1][0] if 1 <= n <= len(show) else None


def _finish_discovery(cfg, args, *, source, browser_recipe=None, response_sample=None):
    """The ONE validated exit for every `map` source. Bake in any target-auth, run the
    hard gate against the LIVE target (honoring TLS/CA/proxy), and only then write.

    Confidence is a hint; this is the answer. Nothing is written unless the target replied.
    """
    from runtime.discovery import validate as V
    auth_headers, auth_query = _target_auth(args)
    _bake_auth(cfg, auth_headers, auth_query)
    _bake_body_fields(cfg, _body_fields(args))   # body-carried key/tenant must persist too
    # carry TLS/mTLS options into the written config so runtime/assess use them too
    if getattr(args, "insecure", False):
        cfg["verify_tls"] = False
    for k, v in (("ca_bundle", getattr(args, "ca_bundle", None)),
                 ("client_cert", getattr(args, "client_cert", None)),
                 ("client_key", getattr(args, "client_key", None))):
        if v:
            cfg[k] = v
    # Explicit override, or ask the operator when the answer could not be located.
    if adapter_needs_path(cfg) and (getattr(args, "response_path", None) or not cfg.get("response_path")):
        sample = response_sample or (cfg.get("_probe") or {}).get("response_sample")
        chosen = _choose_response_path(sample, (cfg.get("_probe") or {}).get("verified_answer"), args)
        if chosen:
            cfg["response_path"] = chosen
            print(f"[build] answer path set to: {chosen}", file=sys.stderr)
    # SSRF guard at the single choke point every source passes through (api/har/curl/spec/url),
    # on the URL we are ABOUT to fetch — the per-source check missed har/curl/evidence entirely.
    from runtime.discovery.egress import check_egress
    target = cfg.get("endpoint") or cfg.get("url") or ""
    if target:
        blocked = check_egress(target, allow_internal=getattr(args, "allow_internal", False))
        if blocked:
            _die(f"refusing to call {target}: {blocked}\n"
                 f"  this is the SSRF/metadata guard. If you really mean to, pass --allow-internal.",
                 error_code="egress_blocked")
    adapter = cfg.get("adapter", "direct_api")
    print("[validate] calling the target ...", file=sys.stderr)
    vres = V.validate_config(adapter, cfg, args.prompt, None,
                             timeout_s=args.timeout, verify_tls=not args.insecure)
    if not vres.get("ok"):
        hint = ""
        err = str(vres.get("error") or "")
        forbidden = any(s in err for s in ("403", "Forbidden", "Authorization header not found"))
        unauth = ("401" in err or "Unauthorized" in err)
        # A 403 when we captured a real reply from THIS EXACT request in the browser means the
        # target accepts it from a browser and refuses it replayed. That is anti-automation, and it
        # is proven: replaying the byte-identical request (same headers, same token) from outside a
        # browser gets the same 403. No header, cookie or token fixes it — the endpoint checks that
        # the caller IS a live browser (TLS fingerprint, JS challenge, connection state). The error
        # body can even say "Authorization header not found"; that is the vendor's misleading
        # phrasing, not the real cause. The honest fix is to drive a real browser per probe.
        if forbidden and browser_recipe:
            # We already drove a real browser during capture and it worked — so instead of telling
            # the operator "use the browser adapter", BUILD it from what the capture did, and prove
            # it live. This is the whole point: a --url target that refuses HTTP replay still gets a
            # working adapter, automatically.
            print("[build] HTTP replay refused (anti-automation) — building a BROWSER adapter from "
                  "the capture and proving it live ...", file=sys.stderr)
            return _finish_browser_adapter(browser_recipe, args, source, V)
        if forbidden and source in ("url", "har", "curl"):
            hint = ("\n  This target ACCEPTED the request from your browser but REFUSES it replayed\n"
                    "  (HTTP 403), even byte-for-byte. That is anti-automation, not missing auth —\n"
                    "  a token or cookie will not change it; the endpoint checks that the caller is\n"
                    "  a live browser. Targets like this must be driven THROUGH a browser for every\n"
                    "  probe: see docs/BUILD_ADAPTER.md, the `browser` adapter the CLI ships.")
        elif unauth:
            hint = ("\n  the target wants credentials — re-run with the request's own auth, e.g.\n"
                    "    --bearer <token> | --api-key 'x-api-key:<key>' | --cookie '<jar>'\n"
                    "  (from a HAR, the captured auth header is usually enough; export a fresh HAR)")
        _die(f"discovered a contract from the {source}, but it did not work against the "
             f"live target:\n  {err}{hint}\n"
             f"  nothing was written — an unvalidated config is a guess.", code=EXIT_ERROR)
    print(f"[validate] VALIDATED — {str(vres.get('response'))[:90]!r}", file=sys.stderr)

    # The reply is the only place the WIRE FORMAT is visible, so this is the one moment we can tell
    # a marker-framed stream from a plain JSON body. Without it a target that answers
    # `BOT_CHAT_EVENT_BEGIN{…}BOT_CHAT_EVENT_END` produced a direct_api config that "validated"
    # while handing the scorer raw protocol frames instead of the agent's reply — a config that
    # looks right, passes the gate, and quietly scores wire noise for the whole assessment.
    cfg, vres = _upgrade_streaming_shape(cfg, vres, args, V)

    # Per-app ADAPTER as code (Iris -> Bridge -> Adapter -> App). The 16 built-ins are the common
    # patterns; --code emits a self-contained module for THIS app and proves the CODE (not just the
    # contract) against the live target.
    if getattr(args, "agent", False):
        _die("--agent (have the CLI write a bespoke adapter for you) is not built yet.\n"
             "  For now: `--code` writes an editable scaffold with the captured request; open it in\n"
             "  a coding agent (e.g. Claude Code), finish send_prompt(), and `adapter validate` it.",
             error_code="not_implemented")
    if getattr(args, "code", False):
        return _finish_code_adapter(cfg, vres, args, source, V)

    out_path = _write_discovered(cfg, args)
    if args.json:
        _out({"config": cfg, "source": source, "validated": True,
              "out": str(out_path) if out_path else None}, args)
    else:
        print()
        print(json.dumps(cfg, indent=2))
        if out_path:
            print(f"\nwrote {out_path}", file=sys.stderr)
            print(f"next:  ascend chat {out_path.stem}", file=sys.stderr)


def _finish_code_adapter(cfg, vres, args, source, V):
    """Write a per-app adapter MODULE and prove the generated code against the live target.

    The contract validated above tells us the shape; here we turn it into code the bridge runs
    (custom adapter) and re-validate THAT — so what ships is a module that provably answered, not a
    config that might. Both files are kept on failure so a human, or `--agent`, can finish them.
    """
    from runtime.discovery import codegen
    if not args.out:
        _die("--code needs --out <name>: the adapter module is written as <name>.py beside <name>.json")
    name = Path(os.path.expanduser(args.out)).stem
    module_src = codegen.generate_adapter_module(name, cfg, source=source)
    module_path = config_dir() / f"{name}.py"
    module_path.parent.mkdir(parents=True, exist_ok=True)
    _write_private(module_path, module_src)
    pointer = {
        "adapter": "custom",
        "adapter_module": f"{name}.py",
        "target": cfg.get("url") or cfg.get("endpoint"),
        "timeout_ms": cfg.get("timeout_ms", 30000),
        "_source": source,
        "_probe": cfg.get("_probe"),
    }
    cfg_path = config_dir() / f"{name}.json"
    _write_private(cfg_path, json.dumps(pointer, indent=2))

    is_scaffold = "raise NotImplementedError" in module_src
    if is_scaffold:
        print(f"[build] this target fits no known pattern — wrote a SCAFFOLD adapter to "
              f"{module_path}", file=sys.stderr)
        print("        finish send_prompt() by hand, or run `adapter build --agent` to have it "
              "written from the captured request, then `adapter validate --config "
              f"{name}`.", file=sys.stderr)
        if args.json:
            _out({"adapter_module": str(module_path), "config": str(cfg_path),
                  "scaffold": True, "validated": False, "source": source}, args)
        return

    print("[validate] proving the generated adapter CODE against the live target ...",
          file=sys.stderr)
    v2 = V.validate_config("custom", pointer, args.prompt, None,
                           timeout_s=max(args.timeout, 30.0), verify_tls=not args.insecure)
    if not v2.get("ok"):
        _die(f"the contract validated, but the generated adapter code did not answer:\n"
             f"  {v2.get('error')}\n"
             f"  the code is at {module_path} — open it in your coding agent (e.g. Claude Code)\n"
             f"  with the captured request, finish send_prompt(), then:  ascend adapter validate "
             f"--config {name}",
             code=EXIT_ERROR)
    print(f"[validate] VALIDATED (code) — {str(v2.get('response'))[:90]!r}", file=sys.stderr)
    if args.json:
        _out({"adapter_module": str(module_path), "config": str(cfg_path),
              "validated": True, "source": source,
              "response": str(v2.get("response"))[:200]}, args)
    else:
        print(f"\nwrote the adapter:  {module_path}")
        print(f"      its config:   {cfg_path}")
        print(f"next:  ascend chat {name}    ·    ascend app create --name '<app>' --config {name}")


def _finish_browser_adapter(recipe, args, source, V):
    """Build a `browser` adapter from the capture recipe and PROVE it against the live target.

    The capture opened the widget, found the input, sent a prompt and read the reply — so we know
    the launcher, chat frame, input selector, send method and reply container. We assemble the
    browser adapter from that and drive it once more (a real browser) before writing anything. If
    the generated selectors don't hold, we say so and keep the config for the operator to tune with
    `adapter show` — never write an unproven adapter.
    """
    from runtime.discovery import codegen
    url = recipe.get("url") or args.url
    cfg = codegen.browser_config_from_recipe(url, recipe)
    print("[validate] driving a real browser through the generated adapter ...", file=sys.stderr)
    vres = V.validate_config("browser", cfg, args.prompt, None,
                             timeout_s=max(args.timeout, 150.0), verify_tls=not args.insecure)
    if not vres.get("ok"):
        # keep the config so the operator can fix the one selector that missed
        out_path = _write_discovered(cfg, args) if args.out else None
        loc = f"\n  the config is at {out_path} — tune it with `adapter show {out_path.stem}`" if out_path else ""
        _die(f"built a browser adapter, but it did not get a reply from the live widget:\n"
             f"  {vres.get('error')}{loc}\n"
             f"  the selectors may need a tweak (launcher / input / reply container).",
             code=EXIT_ERROR)
    print(f"[validate] VALIDATED (browser) — {str(vres.get('response'))[:90]!r}", file=sys.stderr)
    out_path = _write_discovered(cfg, args)
    if args.json:
        _out({"config": cfg, "source": source, "adapter": "browser", "validated": True,
              "out": str(out_path) if out_path else None,
              "response": str(vres.get("response"))[:200]}, args)
    else:
        print()
        print(json.dumps(manual_redact(cfg), indent=2))
        if out_path:
            print(f"\nwrote the browser adapter:  {out_path}", file=sys.stderr)
            print(f"next:  ascend chat {out_path.stem}    ·    ascend app create --name '<app>' "
                  f"--config {out_path.stem}", file=sys.stderr)


def manual_redact(cfg):
    try:
        import manual
        return manual.redact(cfg)
    except Exception:
        return cfg


def _resolve_chat_target(args):
    """Turn one positional target into (config, adapter, display name).

    Accepts a config name, a config file path, or a URL. A URL is discovered and
    validated first, so `ascend chat https://host/api/chat` just works.
    """
    target = args.target or args.config or args.file
    if not target:
        _die("what should I talk to?  ascend chat <config-name | config.json | https://url>\n"
             "  list what you have:  ascend adapter configs")
    if str(target).startswith(("http://", "https://")):
        from runtime.discovery.probe import probe_api, build_config
        print(f"discovering {target} ...", file=sys.stderr)
        # chat's --prompt has dest="prompts" (repeatable), so use the first if given
        seed = (getattr(args, "prompts", None) or [None])[0] or "Hello, what can you help me with?"
        res = probe_api(target, prompt=seed, headers=_kv_headers(getattr(args, "header", None)))
        if not res.ok:
            _die(f"{res.diagnosis}: {res.message}\n  {res.hint}", code=EXIT_ERROR)
        cfg = build_config(res)
        name = (target.split("//")[-1].split("/")[0]).replace(":", "-")
        print(f"found {res.method} {res.endpoint}", file=sys.stderr)
        return cfg, cfg.get("adapter", "direct_api"), name
    cfg = _load_named_config(target)
    return cfg, args.adapter or cfg.get("adapter"), Path(str(target)).stem


def cmd_chat(args):
    """Talk to an agent directly — a live session, recorded.

    Think telnet for an AI agent: name a target, type, read what it says back. Uses the
    same TargetCaller the bridge uses, so conversation state behaves exactly as it will
    during an assessment, and every turn is written to the same evidence format.
    """
    import manual
    from call_target import TargetCaller

    cfg, adapter, name = _resolve_chat_target(args)
    if not adapter:
        _die("no adapter type: set 'adapter' in the config or pass --adapter")
    caller = TargetCaller(adapter, name, config=cfg, timeout_s=args.timeout)

    # Recording is the DEFAULT — a session you cannot replay is a session you wasted.
    out = args.out
    if out is None and not args.no_record:
        stamp = time.strftime("%Y%m%d-%H%M%S")
        out = str(Path("captures") / f"{name}-{stamp}.jsonl")
    log = manual.TurnLog(out)
    session = uuid.uuid4().hex[:8]
    records = []

    def emit(rec):
        records.append(rec)
        log.write(rec)
        if args.json:
            print(json.dumps(rec, default=str), flush=True)
            return
        body = rec["response"] or rec.get("error") or "(no response)"
        print(f"\n{name} › {body}", flush=True)
        flags = "" if rec["ok"] else "  [FAILED]"
        if "matched" in rec:
            flags += "  [expect " + ("MET" if rec["matched"] else "MISSED") + "]"
        print(f"  ({rec['duration_ms']}ms · http {rec['status_code']}){flags}\n", flush=True)

    def show_results():
        if not records:
            print("  (no turns yet)", file=sys.stderr); return
        for i, r in enumerate(records, 1):
            mark = "ok " if r["ok"] else "FAIL"
            print(f"  {i:3}. [{mark}] {r['prompt'][:60]}", file=sys.stderr)
        st = manual.summarize(records)
        print(f"  {st['turns']} turn(s), {st['ok']} ok, {st['failed']} failed, "
              f"avg {st['avg_ms']}ms", file=sys.stderr)

    HELP = ("  /new       start a fresh conversation with the same agent\n"
            "  /results   summary of this session\n"
            "  /retry     resend the last prompt\n"
            "  /save F    also write this session to F\n"
            "  /help      this\n"
            "  /exit      leave (Ctrl-D works too)")

    try:
        if args.prompts:                                    # one or more --prompt
            for p_ in args.prompts:
                emit(manual.run_turn(caller, p_, session=session))
        elif args.prompt_file:                              # batch
            items = manual.load_prompts(args.prompt_file)
            if not items:
                _die(f"no prompts found in {args.prompt_file}")
            for it in items:
                emit(manual.run_turn(caller, it["prompt"], meta=it, session=session))
                if args.reset_between:
                    caller.reset()
        else:                                               # live session
            if args.json and not sys.stdin.isatty():
                _die("nothing to send: pass --prompt or --prompt-file "
                     "(interactive mode needs a terminal)")
            print(f"\nconnected to {name} ({adapter})", file=sys.stderr)
            if out:
                print(f"recording to {out}", file=sys.stderr)
            print("/help for commands, /exit to leave\n", file=sys.stderr)
            last = None
            while True:
                try:
                    line = input("you › ").strip()
                except (EOFError, KeyboardInterrupt):
                    print(file=sys.stderr); break
                if not line:
                    continue
                if line in ("/exit", "/quit", ":q", "exit", "quit"):
                    break
                if line == "/help":
                    print(HELP, file=sys.stderr); continue
                if line == "/new":
                    caller.reset(); session = uuid.uuid4().hex[:8]
                    print("  new conversation\n", file=sys.stderr); continue
                if line == "/results":
                    show_results(); continue
                if line.startswith("/save"):
                    parts = line.split(None, 1)
                    if len(parts) == 2:
                        manual.TurnLog(parts[1]).__class__  # validate path early
                        extra = manual.TurnLog(parts[1])
                        for r in records:
                            extra.write(r)
                        print(f"  saved {len(records)} turn(s) to {parts[1]}", file=sys.stderr)
                    else:
                        print("  usage: /save <file>", file=sys.stderr)
                    continue
                if line == "/retry":
                    if not last:
                        print("  nothing to retry", file=sys.stderr); continue
                    line = last
                if line.startswith("/"):
                    print(f"  unknown command {line.split()[0]} — /help", file=sys.stderr); continue
                last = line
                emit(manual.run_turn(caller, line, session=session))
    finally:
        caller.reset()

    if records and not args.json:
        st = manual.summarize(records)
        line = f"{st['turns']} turn(s), {st['ok']} ok, {st['failed']} failed, avg {st['avg_ms']}ms"
        if st["checked"]:
            line += f", {st['matched']}/{st['checked']} expectations met"
        print(line, file=sys.stderr)
        if out:
            print(f"transcript: {out}", file=sys.stderr)
            print(f"replay it:  ascend results {out}", file=sys.stderr)
    # A single failed turn is information; but if EVERY turn failed to reach the
    # target, that's a tool/target error, not a clean session.
    if records and all(r.get("ok") is False for r in records):
        sys.exit(EXIT_ERROR)
    # --expect misses signal findings.
    if records and any(r.get("matched") is False for r in records):
        sys.exit(EXIT_FINDINGS)


# ----------------------------------------------------------------------------- onboard
def _say(args, msg, *, done=False):
    """A short activity or confirmation line, on STDERR.

    "Did that actually work?" is a fair question when a command's only output is a table, or
    nothing at all. These lines answer it.

    They go to stderr and are suppressed entirely under --json, so they cost an agent nothing:
    stdout stays exactly the machine payload, which is the contract docs/AGENTS.md promises.
    That is also why they are not part of any command's return value — a human affordance must
    never become something a script has to parse around.
    """
    if getattr(args, "json", False):
        return
    prefix = "\u2713 " if done else ""
    if _ui.color_ok(sys.stderr):
        prefix = "\033[32m\u2713\033[0m " if done else ""
        msg = msg if done else f"\033[2m{msg}\033[0m"
    print(f"{prefix}{msg}", file=sys.stderr, flush=True)


def _step(n, total, msg):
    print(f"  [{n}/{total}] {msg}", file=sys.stderr, flush=True)


def _ok(msg):
    print(f"      {msg}", file=sys.stderr, flush=True)


def _write_named_config(cfg, cfg_name):
    """Write a discovered config to <config_dir>/<name>.json and note it. Shared by onboard's
    discovery branches so every source lands the config the same way."""
    path = config_dir() / f"{cfg_name}.json"
    _write_private(path, json.dumps(cfg, indent=2))
    _ok(f"wrote {path}")
    return path


def cmd_onboard(args):
    """Zero to a running assessment in one command.

    Chains adapter build -> validate (hard gate) -> app create -> bridge -> assess, which
    previously meant ~10 manual steps, two terminals and five copy-pasted values.
    Stops at the first failure rather than proceeding on a guess.
    """
    import api
    from runtime.discovery import classify as C

    total = 5
    if args.name:
        name = args.name
    elif args.har:
        name = Path(args.har).stem            # was omitted: two --har runs both became "target"
    elif getattr(args, "curl", None):
        name = Path(args.curl).stem if args.curl != "-" else "target"
    else:
        name = ((getattr(args, "api", None) or args.url or args.config or "target")
                .split("//")[-1].split("/")[0])
    cfg_name = args.config or re.sub(r"[^a-z0-9_-]+", "-", name.lower()).strip("-") or "target"
    if cfg_name.endswith(".json"):        # accept the name exactly as given; never append .json twice
        cfg_name = cfg_name[:-5]

    # 1. obtain a contract -----------------------------------------------------
    if args.config and not (getattr(args, "api", None) or args.url or args.har or getattr(args, "curl", None)):
        _step(1, total, f"using existing config '{args.config}'")
        cfg = _load_named_config(args.config)
    elif getattr(args, "api", None):
        # the simple-contract one-liner: one probe, no browser, no adapter to author
        _step(1, total, f"probing {args.api}")
        from runtime.discovery.probe import probe_api, build_config
        auth_headers, auth_query = _target_auth(args)
        api_url = args.api
        if auth_query:
            sep = "&" if "?" in api_url else "?"
            api_url += sep + "&".join(f"{k}={v}" for k, v in auth_query.items())
        res = probe_api(api_url, prompt=args.prompt, headers=auth_headers,
                        timeout_s=args.timeout, verify_tls=not getattr(args, "insecure", False),
                        extra_body=_body_fields(args) or None)
        if not res.ok:
            _die(f"{res.diagnosis}: {res.message}\n  {res.hint}", code=EXIT_ERROR)
        _ok(f"{res.method} {res.endpoint} · transport {res.transport} · answer at "
            f"{res.response_path or '(top-level)'}")
        cfg = build_config(res)
        _write_named_config(cfg, cfg_name)
    elif getattr(args, "curl", None):
        _step(1, total, f"reading the request from {args.curl}")
        from runtime.discovery.importers import from_curl, CurlParseError
        text = sys.stdin.read() if args.curl == "-" else Path(args.curl).read_text()
        try:
            cfg = from_curl(text, prompt_hint=args.prompt_hint)
        except CurlParseError as e:
            _die(f"could not read that curl command: {e}")
        _write_named_config(cfg, cfg_name)
    else:
        _step(1, total, f"capturing the contract from {args.url or args.har}")
        if args.url:
            from runtime.discovery.capture import capture_url
            ev = capture_url(args.url, prompt=args.prompt, headless=args.headless,
                             settle_s=args.settle, manual=args.manual)
            for n in ev.get("notes", []):
                _ok(n)
            if not ev.get("send_verified"):
                _die("the capture never delivered the prompt to the target, so there is no "
                     "contract to build on.\n"
                     "  try:  --settle 15 | --manual | --har <file> | copy configs/example-*.json",
                     code=EXIT_ERROR)
        else:
            ev = C.load_har(args.har, prompt_sent=args.prompt)
        res = C.classify_evidence(ev)
        cfg = res.get("config") or {}
        t = (res.get("layers") or {}).get("transport") or {}
        _ok(f"transport {t.get('value')} (confidence {t.get('confidence')})")
        if res.get("unresolved"):
            _ok(f"unresolved layers: {res['unresolved']}")
        _write_named_config(cfg, cfg_name)

    adapter = args.adapter or cfg.get("adapter")
    if not adapter:
        _die("could not determine the adapter type; set 'adapter' in the config or pass --adapter")

    # 2. hard gate -------------------------------------------------------------
    _step(2, total, "validating the config against the live target")
    from runtime.discovery import validate as V
    vres = V.validate_config(adapter, cfg, args.prompt, None, timeout_s=args.timeout)
    if not vres.get("ok"):
        _die(f"the adapter could not talk to the target: {vres.get('error')}\n"
             f"  fix {config_dir() / (cfg_name + '.json')} and re-run, or use "
             f"`ascend adapter validate --config {cfg_name}` to iterate.",
             code=EXIT_ERROR)
    _ok(f"target replied: {str(vres.get('response'))[:80]!r}")

    if args.dry_run:
        if getattr(args, "json", False):
            _out({"config": cfg_name, "path": str(config_dir() / f"{cfg_name}.json"),
                  "adapter": adapter, "validated": True, "dry_run": True}, args)
        else:
            print(f"\ndry run: config ready at {config_dir() / (cfg_name + '.json')}", file=sys.stderr)
        return

    # 3. register --------------------------------------------------------------
    _step(3, total, "registering the application with Ascend")
    c = _client(args)
    controls = args.controls.split(",") if args.controls else None
    if controls:
        v = c.validate_controls(controls)
        for w in v["warnings"]:
            _ok(f"warning: {w}")
        # Same trap as `app create`: `v["valid"] or controls` fell back to the ORIGINAL list when
        # nothing validated, so a typo'd control was sent to the platform verbatim and onboard
        # went on to run an assessment that could only ever come back clean.
        if v.get("unknown"):
            _die(f"unknown control id(s): {', '.join(v['unknown'])}\n"
                 f"  list them:  ascend controls list\n"
                 f"  a control that does not exist generates zero probes, so this run would "
                 f"score clean without testing anything",
                 error_code="unknown_control")
        if not v.get("valid"):
            _die("none of the selected controls can generate probes — refusing to onboard an app "
                 "whose assessments cannot measure anything",
                 error_code="no_scorable_controls")
        controls = v["valid"]
    app = c.create_app(api.build_thin_spec(
        name=args.name or name, system_prompt=args.system_prompt or name,
        control_ids=controls, assessment_size=args.size, qpm=args.qpm))
    app_id, tc = app.get("id"), app.get("thin_api_key")
    _ok(f"app {app_id}")
    _require_thin_key(tc, app_id)      # shown once; without it the bridge can never serve this app
    try:
        import creds as C
        # Record the FULL binding (app + config + adapter + key) so `bridge start --app X` can
        # launch this bridge later with nothing pasted by hand.
        C.save(app_id, tc, app_name=args.name or name, config=cfg_name, adapter=adapter)
        _ok(f"bridge key stored for {app_id} (0600, {C.store_path()}) — shown only once by the API")
        _bind_config(cfg_name, app_id, args.name or name)
    except Exception as e:
        _ok(f"could not save the bridge key ({e}); copy it now: {tc}")

    # 4. bridge ----------------------------------------------------------------
    _step(4, total, "starting the probe bridge in the background")
    import logging, threading, runtime.run as runtime_run
    # Without this the bridge and adapters log nothing, so the operator cannot tell a
    # working run from a stalled one — the main anxiety of an unattended assessment.
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="      %(name)s: %(message)s", stream=sys.stderr)
    logging.getLogger("ascendbridge.lease").setLevel(
        logging.DEBUG if args.verbose else logging.INFO)
    client = runtime_run.build_runtime(
        tc, adapter, cfg_name, base_url=args.bridge_base, qpm=args.qpm)
    ready = threading.Event()
    threading.Thread(target=lambda: client.run_forever(ready_cb=ready.set),
                     daemon=True).start()
    if not ready.wait(timeout=60):
        if getattr(client, "fatal_error", None):
            _die(client.fatal_error, code=EXIT_ERROR)   # e.g. rejected bridge key
        _die("the bridge worker could not reach the lease endpoint within 60s; check egress to "
             f"{args.bridge_base}", code=EXIT_ERROR)
    _ok("bridge connected")

    # 5. assess ----------------------------------------------------------------
    _step(5, total, "starting the assessment")
    run = c.run(app_id, args.assessment_name or f"{name} run 1", wait=False)
    aid = run.get("assessment_id")
    _ok(f"assessment {aid}")
    print("", file=sys.stderr)
    print(f"  watch:    ascend assess status  --app {app_id} --assessment {aid}", file=sys.stderr)
    print(f"  findings: ascend assess results --app {app_id} --assessment {aid} --detail", file=sys.stderr)
    print("", file=sys.stderr)

    if args.wait:
        _ok("waiting for completion (Ctrl-C to detach; the run continues server-side)")
        final = c.poll_assessment(app_id, aid, interval=args.interval, timeout=args.timeout_assess,
                                  on_tick=lambda st, pr, a: _ok(f"status={st} progress={pr}"))
        print("", file=sys.stderr)
        _out(final, args, human=api.summarize_result(final, detail=args.detail))
    else:
        _out({"app_id": app_id, "assessment_id": aid, "config": cfg_name,
              "adapter": adapter}, args,
             human="bridge running in this process — leave it open while the assessment runs "
                   "(Ctrl-C to stop).")
        if args.json:
            # An agent calling `onboard --json` must get its object and RETURN. Blocking here
            # forever made the command unusable from a script; the bridge belongs to the fleet
            # supervisor, which survives independently.
            print("note: the in-process bridge is not held open in --json mode. "
                  "Start a durable one with:  ascend bridge start --app <app>", file=sys.stderr)
            client.stop()
            return
        try:
            last = None
            while True:
                time.sleep(30)
                st = client.stats
                line = (f"bridge: {st.get('answered',0)} answered, "
                        f"{st.get('failed',0)} failed, "
                        f"{st.get('empty_polls',0)} idle polls")
                if line != last:
                    _ok(line)
                    last = line
        except KeyboardInterrupt:
            client.stop()
            _ok("bridge stopped")



# ----------------------------------------------------------------------------- results
def _looks_like_jsonl(path, sample=20):
    """Does this file actually contain JSON records? Checked before trusting a zero-turn result."""
    seen = 0
    try:
        with open(path, errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    json.loads(line)
                    return True
                except ValueError:
                    seen += 1
                    if seen >= sample:
                        return False
    except OSError:
        return False
    return False          # an empty file is not an transcript either


def _read_records(path):
    """Read a JSONL transcript (bridge --capture probe/result pairs, or chat turns)."""
    out = []
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except ValueError:
                continue
    return out


def _norm_record(rec, pending):
    """Normalize one evidence record to a turn {prompt, response, status, ok}.

    Handles BOTH shapes so manual sessions and Iris-driven bridge runs read the same:
      * chat writes kind="turn" (prompt+response together)
      * the bridge writes kind="probe" then kind="result" for the same request_id
    """
    kind = rec.get("kind")
    rid = rec.get("request_id")
    if kind == "turn":
        return {"id": rid, "prompt": rec.get("prompt", ""), "response": rec.get("response", ""),
                "status": rec.get("status_code"), "ok": rec.get("ok"),
                "ms": rec.get("duration_ms"), "source": rec.get("source", "manual")}
    if kind == "probe":
        body = ((rec.get("message") or {}).get("payload") or {}).get("body")
        text = body if isinstance(body, str) else json.dumps(body) if body is not None else ""
        if isinstance(body, dict):
            for k in ("prompt", "message", "input", "text", "query"):
                if k in body:
                    text = str(body[k]); break
        pending[rid] = text
        return None
    if kind == "result":
        body = rec.get("body") or {}
        return {"id": rid, "prompt": pending.pop(rid, ""),
                "response": str(body.get("response", "")), "status": rec.get("status_code"),
                "ok": rec.get("status_code") == 200 and bool(body.get("response")),
                "ms": None, "source": "iris"}
    return None


def _print_turn(t, verbose=False):
    mark = "ok " if t.get("ok") else "FAIL"
    ms = f" {t['ms']}ms" if t.get("ms") else ""
    # flush: in --follow the stream is often a pipe/file (block-buffered), so without
    # this a live tail shows nothing until the buffer fills.
    print(f"[{mark}] {t.get('source','?'):6} {str(t.get('prompt',''))[:70]}", flush=True)
    if verbose:
        print(f"        -> {str(t.get('response',''))[:200]}", flush=True)


def _sniff_export(path):
    """Is this a Console CSV export? Returns "ascend"/"defend"/None.

    Sniffs the header rather than trusting the extension: exports are routinely saved with the
    assessment UUID as the filename and no suffix at all.
    """
    try:
        with open(path, newline="", encoding="utf-8-sig", errors="replace") as fh:
            header = next(csv.reader(fh), [])
    except (OSError, csv.Error, StopIteration):
        return None
    return _turns.sniff_schema(header)


def _results_from_export(path, schema, args):
    """Analyse a Console CSV export: parse turns, roll up, render or emit JSON."""
    # Validate the flags BEFORE reading anything. The renderer is skipped entirely in --json mode,
    # so validating inside it meant `--by <typo>` was silently ignored for agents and CI while
    # failing for humans — the two modes disagreeing about whether a command was even valid.
    _wanted_sections(args)
    with _ui.progress(f"reading {schema} export", args=args) as prog:
        try:
            schema, turns = _turns.load_export(path)
        except ValueError as e:
            _die(str(e), error_code="unreadable_export")
        prog.advance()

    # The platform owns the taxonomy (category names, risk tags, control prefixes, deprecation).
    # Fetch it when we can so rollups carry real names; degrade to raw ids offline.
    catalog = None
    if schema == "ascend" and not args.no_catalog:
        try:
            catalog = _client(args)._req("GET", "/ascend/controls")
        except Exception:
            catalog = None

    rep = _analyze.analyze(turns, schema, catalog=catalog)
    rep["source"] = {"file": str(path), "schema": schema,
                     "taxonomy": "platform" if catalog else "raw-ids"}

    if args.json:
        _out({"ok": True, "data": rep}, args)
        return
    if args.md:
        print(_analysis_markdown(rep))
        return
    if schema == "defend":
        print(_render_defend_analysis(rep, args))
    else:
        print(_render_ascend_analysis(rep, args))
    if not catalog and schema == "ascend":
        print("\n  note: platform taxonomy unavailable (offline or no token) — showing raw ids.\n"
              "        category names and risk grouping come from /ascend/controls.",
              file=sys.stderr)


def _analysis_markdown(rep):
    """Markdown for a report or a PR comment. Same numbers, no colour."""
    T = rep["totals"]
    L = []
    if rep["schema"] == "defend":
        L.append("# Defend events\n")
        L.append(f"- **Events:** {T['events']:,}")
        L.append(f"- **Flagged:** {T['flagged']:,}")
        L.append(f"- **Blocked:** {T['blocked']:,} ({T['block_rate_pct']}%)")
        L.append(f"- **Detected:** {T['detected']:,} ({T['detect_rate_pct']}%)")
        if rep["detections"]:
            L.append("\n## Detections\n")
            L.append("| Detection | Block | Detect | Total |")
            L.append("|---|---:|---:|---:|")
            for r in rep["detections"][:25]:
                L.append(f"| `{r['key']}` | {r['block']} | {r['detect']} | {r['total']} |")
        return "\n".join(L)

    L.append("# Ascend results\n")
    L.append(f"- **Probes:** {T['probes']:,} ({T['answered']:,} answered, "
             f"{T['unanswered']:,} unanswered)")
    L.append(f"- **Failed:** {T['failed']:,} ({T['failure_rate_pct']}% of answered) — "
             f"{T['strict_failed']:,} strict")
    L.append(f"- **Refusal-style responses:** {T['refusal_style_responses']:,} "
             f"({T['refusal_rate_pct']}% of answered)")
    for title, key, hdr in (
        ("Risk grouping", "by_risk", "Risk"),
        ("Category", "by_category", "Category"),
        ("Evasion technique", "by_evasion", "Technique"),
        ("Control", "by_control", "Control"),
    ):
        rows = rep.get(key) or []
        if not rows:
            continue
        L.append(f"\n## {title}\n")
        L.append(f"| {hdr} | Probes | Failed | Rate |")
        L.append("|---|---:|---:|---:|")
        for r in rows[:20]:
            name = r.get("name") or r["key"]
            L.append(f"| {name} | {r['probes']:,} | {r['failed']:,} | {r['rate']}% |")
    vals = [v for v in rep.get("values", []) if v["target_produced"]]
    if vals:
        L.append("\n## Values produced by the target\n")
        L.append("| Control | Value | Times seen | From target | From prompt |")
        L.append("|---|---|---:|---:|---:|")
        for v in vals[:25]:
            L.append(f"| `{v['control_id']}` | `{v['sample']}` | {v['count']} "
                     f"| {v['from_target']} | {v['echoed']} |")
        L.append("\nProvenance is mechanical (present in a response, absent from the prompt). "
                 "Whether a value is sensitive is a judgement call and is not decided here.")
    if rep.get("warnings"):
        L.append("\n## Read these before quoting the numbers\n")
        for w in rep["warnings"]:
            L.append(f"- **{w['code']}** — {w['message']}")
    return "\n".join(L)


def _fmt_int(n):
    return f"{n:,}" if isinstance(n, int) else str(n)


# The rollup sections `ascend results --by` accepts. Defined once so the validator, the help text
# and the renderer cannot drift — and so a typo is REFUSED rather than silently rendering nothing.
RESULT_SECTIONS = ("category", "evasion", "control", "risk", "dataclass", "combo")
RESULT_SECTIONS_DEFAULT = ("category", "evasion", "control")


def _wanted_sections(args):
    """Parse --by, refusing unknown names.

    An unrecognized section used to render NOTHING and exit 0: ask for `--by evasions` (a plural
    typo) and you got an empty report that reads exactly like "this run had no findings by
    technique". Same shape as the other fail-open bugs — the tool did nothing and said nothing.
    """
    if not getattr(args, "by", None):
        return set(RESULT_SECTIONS_DEFAULT)
    asked = [p.strip().lower() for p in args.by.split(",") if p.strip()]
    if not asked:
        return set(RESULT_SECTIONS_DEFAULT)
    unknown = [a for a in asked if a not in RESULT_SECTIONS]
    if unknown:
        import difflib
        close = difflib.get_close_matches(unknown[0], RESULT_SECTIONS, n=2, cutoff=0.4)
        _die(f"unknown --by section(s): {', '.join(unknown)}\n"
             f"  choose from: {', '.join(RESULT_SECTIONS)}"
             + (f"\n  did you mean:  {', '.join(close)}" if close else ""),
             error_code="unknown_section")
    return set(asked)


def _cap(args, section_default):
    """How many rows this section shows.

    One meaning for --limit across every section of the command:
        (not passed)  -> the section's own sensible default
        --limit 0     -> no cap, show everything (what the table footer advertises)
        --limit N     -> at most N

    This was inconsistent: `--limit 0` meant "all" for values/turns/errors but fell back to the
    section default for the rollup tables, so following the footer's own "--limit 0 for all"
    advice left 45 control rows unreachable.
    """
    lim = getattr(args, "limit", None)
    if lim is None:
        return section_default
    if lim == 0:
        return None            # no cap
    return max(1, lim)


def _rollup_table(rows, title, *, limit=None, show_unanswered=False):
    """One rollup as a table: key, probes, failed, rate, and a relative failure bar.

    `PROBES`/`FAILED` are PROBE counts, labelled as such — they are not finding counts.

    The bar is scaled to the WORST row in this table, not to 0-100%. An absolute bar is useless
    here: real failure rates are often 1-2%, which rounds to a full block at any sane width, so
    every row looks identical. Relative scaling answers the question the reader actually has —
    which bucket is the worst — and the RATE column keeps the absolute number honest.
    """
    if not rows:
        return []
    shown = rows[: limit] if limit else rows
    width = max([len(str(r.get("name") or r["key"])) for r in shown] + [12])
    width = min(width, 40)
    worst = max((r["failed"] for r in shown), default=0)
    # PASSED is shown explicitly rather than left to be inferred: "probes minus failed" silently
    # includes probes the target never answered, which are not passes.
    head = (f"  {'':{width}} {'PROBES':>7} {'PASSED':>7} {'FAILED':>7} {'RATE':>6}")
    if show_unanswered:
        head += f" {'UNANSW':>7}"
    out = [f"\n  {title}", head + ("  FAILURES (relative)" if worst else "")]
    out.append("  " + "-" * (width + (39 if show_unanswered else 32) + (20 if worst else 0)))
    for r in shown:
        label = str(r.get("name") or r["key"])[:width]
        flags = ""
        if r.get("deprecated"):
            flags += " [deprecated]"
        if r.get("agentic"):
            flags += " [agentic]"
        rate = f"{r['rate']:.1f}%" if r["probes"] else "-"
        answered = r["probes"] - r.get("unanswered", 0)
        passed = max(0, answered - r["failed"])
        line = (f"  {label:{width}} {_fmt_int(r['probes']):>7} {_fmt_int(passed):>7} "
                f"{_fmt_int(r['failed']):>7} {rate:>6}")
        if show_unanswered:
            line += f" {_fmt_int(r.get('unanswered', 0)):>7}"
        if worst:
            filled = int(round(14.0 * r["failed"] / worst)) if r["failed"] else 0
            line += "  " + ("█" * filled).ljust(14)
        if r.get("tag"):
            line += f" {r['tag']}"
        out.append((line + flags).rstrip())
    if limit and len(rows) > limit:
        out.append(f"  … {len(rows) - limit} more (--limit 0 for all)")
    return out


def _harvest_table(rep, args):
    """What the target actually gave up, grouped by data type — the "data harvest".

    A flat ranked list answers "what leaked most", but the question people actually ask is
    "did it give up phone numbers? email addresses? internal endpoints?" — so the values are
    grouped by the platform's own control id, each group ranked by frequency.

    FROM TARGET vs FROM PROMPT is the whole point: a value the attacker put in the prompt and the
    target repeated back is not a disclosure. Only values the target produced on its own are shown
    by default; --all-values shows both.
    """
    vals = rep["values"] if args.all_values else [v for v in rep["values"] if v["target_produced"]]
    if not vals:
        return ["\n  DATA HARVEST — nothing the target produced on its own."]

    groups = collections.OrderedDict()
    for v in vals:
        groups.setdefault(v["control_id"], []).append(v)

    total = sum(len(g) for g in groups.values())
    L = [f"\n  DATA HARVEST  ({total} distinct value(s) across {len(groups)} type(s)"
         f"{'' if args.all_values else ', produced by the target'})"]
    per_group = _cap(args, 8)
    for control_id, items in groups.items():
        items.sort(key=lambda v: (-v["from_target"], -v["count"]))
        occurrences = sum(v["from_target"] if not args.all_values else v["count"] for v in items)
        label = control_id.replace("_", " ").title()
        L.append(f"\n  {label}  —  {len(items)} distinct, {occurrences} occurrence(s)")
        L.append(f"    {'VALUE':40} {'TIMES SEEN':>10} {'FROM TARGET':>12} {'FROM PROMPT':>12}")
        L.append("    " + "-" * 78)
        for v in items[:per_group]:
            L.append(f"    {str(v['sample'])[:39]:40} {v['count']:>10} "
                     f"{v['from_target']:>12} {v['echoed']:>12}")
        if per_group and len(items) > per_group:
            L.append(f"    … {len(items) - per_group} more (--limit 0 for all)")
    L.append("")
    L.append("  FROM TARGET + FROM PROMPT = TIMES SEEN.")
    L.append("  FROM TARGET = the target produced it; the prompt did not contain it. A disclosure.")
    L.append("  FROM PROMPT = the attacker's prompt already contained it and the target repeated")
    L.append("                it back. Not a disclosure.")
    L.append("  Whether a target-produced value is actually sensitive (a customer's number) or")
    L.append("  public (the published support line) is a judgement call — see agent/TRIAGE.md.")
    return L


def _render_ascend_analysis(rep, args):
    """The default human view of an Ascend export: totals, then the requested sections."""
    T = rep["totals"]
    L = []
    L.append("")
    L.append(f"  Ascend results — {_fmt_int(T['probes'])} probes"
             + (f" · {len(T['assessments'])} assessment"
                + ("s" if len(T["assessments"]) != 1 else "") if T["assessments"] else ""))
    L.append("  " + "=" * 66)
    L.append(f"  answered   {_fmt_int(T['answered'])}"
             f"{'':4}failed {_fmt_int(T['failed'])} ({T['failure_rate_pct']}% of answered)")
    L.append(f"  unanswered {_fmt_int(T['unanswered'])} ({T['unanswered_pct']}%)"
             f"{'':4}strict {_fmt_int(T['strict_failed'])}")
    L.append(f"  outcome    {_ui.bar(T['passed'], T['failed'], width=28)}  "
             f"{_fmt_int(T['passed'])} passed / {_fmt_int(T['failed'])} failed")
    L.append(f"  refusal-style responses  {_fmt_int(T['refusal_style_responses'])} "
             f"({T['refusal_rate_pct']}% of answered) — a sub-stat of passes, not a verdict")

    want = _wanted_sections(args)
    # Say which taxonomy the labels came from — a rollup on raw ids is not the platform's naming.
    tax = "platform taxonomy" if rep.get("source", {}).get("taxonomy") == "platform" else "raw ids"

    if "risk" in want and rep["by_risk"]:
        L += _rollup_table(rep["by_risk"], "BY RISK GROUPING  (platform tag)",
                           show_unanswered=True)
    if "category" in want and rep["by_category"]:
        L += _rollup_table(rep["by_category"], f"BY CATEGORY  ({tax})",
                           limit=_cap(args, 12), show_unanswered=True)
    if "control" in want and rep["by_control"]:
        L += _rollup_table(rep["by_control"], "BY CONTROL", limit=_cap(args, 15),
                           show_unanswered=True)
    if "dataclass" in want and rep["by_data_class"]:
        L += _rollup_table(rep["by_data_class"], "BY DATA CLASS  (platform prefix)")
    if "evasion" in want and rep["by_evasion"]:
        L += _rollup_table(rep["by_evasion"],
                           "BY EVASION TECHNIQUE  (which attacks worked)", limit=_cap(args, 12),
                           show_unanswered=True)
    if "combo" in want and rep["by_evasion_combo"]:
        L += _rollup_table(rep["by_evasion_combo"], "BY EVASION COMBINATION", limit=_cap(args, 12))

    if args.matrix:
        c = rep["confusion"]
        L.append("\n  GUARDRAIL CONFUSION MATRIX  (from the platform's own FP/FN flags)")
        L.append("  " + "-" * 66)
        L.append(f"  TP attack blocked   {_fmt_int(c['true_positive']):>6}"
                 f"     FP benign blocked   {_fmt_int(c['false_positive']):>6}")
        L.append(f"  FN attack succeeded {_fmt_int(c['false_negative']):>6}"
                 f"     TN benign allowed   {_fmt_int(c['true_negative']):>6}")
        L.append(f"  precision {c['precision_pct']}%   recall {c['recall_pct']}%   "
                 f"attack success rate {c['attack_success_rate_pct']}%   "
                 f"(scored {_fmt_int(c['scored'])})")
        L.append(f"  platform flagged: FP={c['platform_fp_flagged']} FN={c['platform_fn_flagged']}"
                 f"   ·  successes that opened with a refusal: {c['successes_after_refusal']}")

    if args.values and rep["values"]:
        L += _harvest_table(rep, args)

    if args.turns and rep["failing_turns"]:
        L.append(f"\n  FAILING TURNS  ({len(rep['failing_turns'])})")
        for t in rep["failing_turns"][: _cap(args, 10)]:
            L.append("  " + "-" * 66)
            L.append(f"  score={t['score']} · {t['category']} / {t['control_id']} · "
                     f"{','.join(t['evasions'])}")
            L.append(f"    PROMPT  {_clip(t['prompt'], 200)}")
            L.append(f"    ANSWER  {_clip(t['response'], 200)}")
            if t.get("explanation"):
                L.append(f"    WHY     {_clip(t['explanation'], 200)}")

    if args.errors and rep["errors"]:
        L.append(f"\n  UNANSWERED PROBES  ({len(rep['errors'])}) — measured nothing")
        for e in rep["errors"][: _cap(args, 10)]:
            L.append(f"    {e['control_id']:30} http={e['http_status']:>4} "
                     f"status={e['status']:8} {_clip(e.get('error_message') or '', 60)}")

    for w in rep.get("warnings", []):
        L.append("")
        L.append(f"  !! {w['message']}")
    return "\n".join(L)


def _render_defend_analysis(rep, args):
    T = rep["totals"]
    L = ["", f"  Defend events — {_fmt_int(T['events'])}", "  " + "=" * 66]
    L.append(f"  flagged {_fmt_int(T['flagged'])}   blocked {_fmt_int(T['blocked'])} "
             f"({T['block_rate_pct']}%)   detected {_fmt_int(T['detected'])} ({T['detect_rate_pct']}%)")
    L.append(f"  input scans {_fmt_int(T['input_scans'])}   output scans {_fmt_int(T['output_scans'])}"
             f"   sessions {_fmt_int(T['sessions'])}")
    L.append(f"  distinct prompts {_fmt_int(T['distinct_prompts'])}   "
             f"repeated {_fmt_int(T['repeated_prompts'])}")
    lim = _cap(args, 15)
    if rep["by_issue"]:
        L.append("\n  ISSUES RAISED")
        L.append(f"  {'ISSUE':34} {'EVENTS':>7}")
        L.append("  " + "-" * 44)
        for r in rep["by_issue"][:lim]:
            L.append(f"  {r['key'][:33]:34} {_fmt_int(r['probes']):>7}")
    if rep["detections"]:
        L.append("\n  DETECTIONS THAT FIRED  (block vs detect mode)")
        L.append(f"  {'DETECTION':34} {'BLOCK':>7} {'DETECT':>7} {'TOTAL':>7}")
        L.append("  " + "-" * 58)
        for r in rep["detections"][:lim]:
            L.append(f"  {r['key'][:33]:34} {_fmt_int(r['block']):>7} "
                     f"{_fmt_int(r['detect']):>7} {_fmt_int(r['total']):>7}")
    if len(rep["by_agent"]) > 1:
        L.append("\n  BY AGENT")
        for r in rep["by_agent"][:lim]:
            L.append(f"    {r['key'][:40]:42} events={_fmt_int(r['probes']):>7} "
                     f"flagged={_fmt_int(r['failed'])}")
    if args.values and rep["values"]:
        L.append(f"\n  VALUES SEEN IN RESPONSES  ({len(rep['values'])} distinct)")
        for v in rep["values"][:lim]:
            L.append(f"    {v['control_id']:30} {str(v['sample'])[:30]:32} n={v['count']}")
    return "\n".join(L)


def _clip(s, n):
    s = re.sub(r"\s+", " ", str(s or "")).strip()
    return s[:n] + ("…" if len(s) > n else "")


def cmd_results(args):
    """Read results — a Console CSV export, or a local transcript — and summarize.

    One verb for "show me what happened", because the question is the same whether the
    record came from the platform or from a manual session:

      ascend results run.csv                  Console export -> rollups (category/evasion/values)
      ascend results captures/manual.jsonl    local chat or bridge capture -> turn list

    The route is chosen by sniffing the file, not by its extension, so a Console export
    saved without a .csv suffix still analyses correctly. --follow tails a live capture.
    """
    # No file: the question is "how did my assessments do?", which is the platform view. With a
    # file: "what happened in THIS run". One command, because it is one question asked of two
    # sources — `ascend results` and `ascend reports` as separate verbs was the single most
    # confusing thing in the CLI's vocabulary.
    if not getattr(args, "file", None):
        return cmd_reports(args)

    path = args.file
    if not Path(path).exists():
        _die(f"no such results file: {path}\n"
             f"  a Console CSV export, or a capture written by `chat --out` / "
             f"`bridge start --capture <file>`")

    schema = _sniff_export(path)
    if schema:
        return _results_from_export(path, schema, args)

    # Not an export. Before falling through to the evidence-log reader, prove the file IS one:
    # that reader skips lines it cannot parse, so pointing at the wrong file (a README, a PDF,
    # a half-written CSV) used to produce "0 turns" and exit 0 — indistinguishable from a real
    # log with nothing in it. An agent or CI job reads that as "nothing to report".
    if not _looks_like_jsonl(path):
        _die(f"{Path(path).name} is neither a Console CSV export nor a JSONL transcript\n"
             f"  export:  the results CSV from the Console assessment view\n"
             f"  capture: written by `chat --out <file>` or `bridge start --capture <file>`",
             error_code="unrecognized_results_file")
    pending = {}
    turns = [t for t in (_norm_record(r, pending) for r in _read_records(path)) if t]

    if args.json:
        _out(turns, args)
    else:
        for t in turns:
            _print_turn(t, verbose=args.verbose)
        ok = sum(1 for t in turns if t.get("ok"))
        print(f"\n{len(turns)} turn(s), {ok} ok, {len(turns) - ok} failed  [{path}]")

    if not args.follow:
        return
    # live tail — for watching a bridge answer probes in real time
    print("\nfollowing (Ctrl-C to stop)...", file=sys.stderr)
    seen = len(_read_records(path))
    try:
        while True:
            time.sleep(args.interval)
            recs = _read_records(path)
            for rec in recs[seen:]:
                t = _norm_record(rec, pending)
                if t:
                    _print_turn(t, verbose=args.verbose)
            seen = len(recs)
    except KeyboardInterrupt:
        print("\nstopped following", file=sys.stderr)


def _require_thin_key(tc, app_id):
    """A thin app is useless without its bridge key, and the API shows it exactly once.

    Storing a missing key as None used to print "stored locally too" and leave an app that no bridge
    can ever serve — silently, exit 0. Treat absence as a hard error while the operator can still act.
    """
    if not tc or not str(tc).startswith("tc-"):
        _die(f"the API did not return a usable thin_api_key for {app_id or 'the new app'} "
             f"(got {tc!r}).\n"
             f"  A thin app cannot be served without it, and it is shown only once.\n"
             f"  Check the app in the Console; if a key exists there, store it with:\n"
             f"    ascend keys add --app {app_id or '<app>'} --key tc-…", code=EXIT_ERROR)


def _bind_config(config_name, app_id, app_name=None):
    """Record which Ascend app a config was registered as, INSIDE the config file.

    Uses the existing underscore-metadata convention (`_probe`, `_source`), so the binding travels
    with the artifact an operator already copies between machines.
    """
    try:
        p = resolve_config_path(config_name)
        if not p:
            return False
        cfg = json.loads(p.read_text())
        prev = cfg.get("_ascend") or {}
        cfg["_ascend"] = {**prev, "app_id": app_id, "app_name": app_name or prev.get("app_name"),
                          "registered_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
        _write_private(p, json.dumps(cfg, indent=2))
        return True
    except Exception:
        return False


def cmd_app_bind(args):
    """Back-fill the config↔app binding for a config registered before this existed."""
    c = _client(args)
    app_id = _resolve_app(c, args.app)
    name = None
    try:
        name = (c.get_app(app_id) or {}).get("name")
    except Exception:
        pass
    _say(args, f"Binding config {args.config!r} to {name or app_id}...")
    ok = _bind_config(args.config, app_id, name)
    if ok:
        _say(args, f"bound {args.config!r} -> {name or app_id}", done=True)
    if not ok:
        _die(f"could not write the binding into config {args.config!r} "
             f"(does it exist?  ascend adapter configs)")
    import creds as C
    rec = C.get(app_id)
    if rec and not rec.get("config"):
        C.save(app_id, rec.get("thin_api_key"), app_name=name, config=args.config)
    _out({"config": args.config, "app_id": app_id, "app_name": name}, args,
         human=f"bound config {args.config!r} -> {name or app_id}")


# ---------------------------------------------------------------------------- bridge (fleet)
def _live_relays_count():
    try:
        import supervisor as S
        return sum(1 for r in S.ls() if r["state"] == "serving")
    except Exception:
        return 0


def _target_for(app_id, *, name=None, config_override=None, store=None):
    """Resolve ONE app_id to the spawn tuple {app_id, app_name, config, adapter, key} the bridge
    needs, or {app_id, app_name, skip: <reason>} when a binding is missing. Shared by the fleet
    (`bridge start`) and the auto-lifecycle (`_ensure_bridge`) so both resolve targets identically."""
    import creds as C
    rec = (store or {}).get(app_id) if store is not None else (C.get(app_id) or {})
    rec = rec or {}
    name = name or rec.get("app_name") or app_id
    key = rec.get("thin_api_key")
    cfg = config_override or rec.get("config")
    if not key:
        return {"app_id": app_id, "app_name": name, "skip": "no stored bridge key "
                "(ascend keys add --app … --key tc-…)"}
    if not cfg:
        return {"app_id": app_id, "app_name": name, "skip": "no config bound "
                "(pass --config, or re-onboard so the binding is recorded)"}
    return {"app_id": app_id, "app_name": name, "config": cfg,
            "adapter": rec.get("adapter"), "key": key}


def _fleet_targets(args, c):
    """Resolve which (app_id, app_name, config, adapter, key) tuples to bring up."""
    import creds as C
    store = C.load_all()
    picked = {}
    if getattr(args, "all_running", False):
        apps = _unwrap_list(c.list_apps())
        from concurrent.futures import ThreadPoolExecutor
        def fetch(a):
            try:
                return a, _latest(_assessments_for(c, a["id"]))
            except Exception:
                return a, []
        with ThreadPoolExecutor(max_workers=12) as pool:
            for a, rows in pool.map(fetch, apps):
                if rows and str(rows[0].get("status", "")).lower() in ACTIVE_STATES:
                    picked[a["id"]] = a.get("name")
    for ref in (getattr(args, "app", None) or []):
        aid = ref if str(ref).startswith("aapp_") else _resolve_app(c, ref)
        picked[aid] = store.get(aid, {}).get("app_name") or ref
    cfg_override = getattr(args, "config", None)
    return [_target_for(aid, name=name, config_override=cfg_override, store=store)
            for aid, name in picked.items()]


def _bridge_start_foreground(args):
    """One bridge, in this terminal. Delegates to the same runtime the fleet spawns per app."""
    apps = getattr(args, "app", None) or []
    if len(apps) > 1:
        _die("--foreground runs ONE bridge; pass a single --app\n"
             "  for several at once, drop --foreground and they run detached")
    if not args.config and not apps:
        _die("--foreground needs --config <name> (and usually --app <name> for its key)\n"
             "  example:  ascend bridge start --app 'My Bot' --foreground")
    # cmd_runtime_start reads these attribute names; fill in what the fleet parser does not have.
    args.app = apps[0] if apps else None
    for attr, default in (("api_key", None), ("consumer", None), ("log_file", None),
                          ("status_file", None), ("capture", None), ("adapter", None)):
        if not hasattr(args, attr):
            setattr(args, attr, default)
    if not args.config and args.app:
        _die("--foreground needs --config <name>: the app's bound config is only resolved for "
             "detached bridges\n  find it with:  ascend keys list")
    return cmd_runtime_start(args)


def cmd_relay_start(args):
    """Bring up one detached bridge per app — the fleet.

    `--foreground` runs a SINGLE bridge in this terminal instead, which is what you want when
    debugging an adapter: logs land on your screen and Ctrl-C stops it. That was a separate verb
    (`runtime start`) and is now a flag here, so there is one place to look for "run a bridge".
    """
    if getattr(args, "foreground", False):
        return _bridge_start_foreground(args)
    import supervisor as S
    c = _client(args)
    targets = _fleet_targets(args, c)
    if not targets:
        _die("nothing to start: pass --app <name> (repeatable) or --all-running")
    servable = [t for t in targets if not t.get("skip")]
    if servable:
        _say(args, f"Starting {len(servable)} bridge(s)...")
    qpm = args.qpm
    if getattr(args, "qpm_total", None) and servable:
        # N bridges against one customer host would otherwise hit it at the SUM of their rates.
        qpm = max(1, int(args.qpm_total // len(servable)))
    results = []
    for t in targets:
        if t.get("skip"):
            results.append({**{k: t[k] for k in ("app_id", "app_name")}, "started": False,
                            "reason": t["skip"]})
            continue
        r = S.start(t["app_id"], config=t["config"], adapter=t.get("adapter"), api_key=t["key"],
                    qpm=qpm, max_workers=args.max_workers, bridge_base=args.bridge_base,
                    wait_ms=args.wait_ms, app_name=t.get("app_name"),
                    control_token=getattr(c, "token", None), control_base=getattr(args, "base", None),
                    idle_timeout_s=_resolve_idle(args))
        results.append({"app_id": t["app_id"], "app_name": t.get("app_name"),
                        "started": "error" not in r, **({k: v for k, v in r.items() if k != "app_id"})})
    if args.json:
        _out(results, args)
        return
    for r in results:
        if r.get("started"):
            print(f"  started  {r.get('app_name') or r['app_id']}  pid={r.get('pid')}  "
                  f"log={r.get('log')}")
        else:
            print(f"  skipped  {r.get('app_name') or r['app_id']}  — {r.get('reason') or r.get('error')}")
    n = sum(1 for r in results if r.get("started"))
    if n:
        _say(args, f"{n} bridge(s) running — check:  ascend bridge ls", done=True)
    print(f"\n  {n} bridge(s) started" + (f", qpm={qpm} each" if n and qpm else ""))
    if n:
        print("  they survive this terminal closing.  check:  ascend bridge ls")
    elif results:
        # Exiting 0 here is the canonical false-pass setup: a pipeline doing
        # `bridge start --all-running && assess run ...` proceeds with NOTHING serving, the probes
        # go unanswered, and the assessment finishes looking clean. The command was asked for
        # bridges and produced none — that is a failure.
        _die("no bridges were started — every target was skipped or failed to start.\n"
             "  " + "\n  ".join(
                 f"{r.get('app_name') or r.get('app_id')}: {r.get('reason') or r.get('error')}"
                 for r in results[:5])
             + ("\n  …" if len(results) > 5 else "")
             + "\n  an assessment run now would go unanswered and score a FALSE PASS",
             code=EXIT_ERROR, error_code="no_bridges_started")


def cmd_bridge_sync(args):
    """Reconcile local bridges against platform assessment state. The reliable fallback for
    'someone paused/resumed a run in the Console': ensure a bridge for every app with a
    running/paused assessment, and (unless --no-stop) stop bridges whose apps are all terminal."""
    import supervisor as S
    from concurrent.futures import ThreadPoolExecutor
    c = _client(args)
    apps = _unwrap_list(c.list_apps())

    def state(a):
        try:
            return a, _assessments_for(c, a["id"])
        except Exception:
            return a, []

    with ThreadPoolExecutor(max_workers=12) as pool:
        results = list(pool.map(state, apps))
    started, stopped, reused, skipped = [], [], [], []
    for a, asmts in results:
        if not needs_bridge(a):
            continue
        active = [x for x in asmts if str(x.get("status", "")).lower() in RUNNING_STATES]
        serving = S.is_serving(a["id"])
        if active and not serving:
            r = _ensure_bridge(c, a, args=args)
            (started if r.get("started") else skipped).append((a.get("name"), r))
        elif active and serving:
            reused.append(a.get("name"))
        elif not active and serving and not getattr(args, "no_stop", False):
            S.stop(a["id"])
            stopped.append(a.get("name"))
    if args.json:
        _out({"started": [n for n, _ in started], "stopped": stopped, "reused": reused,
              "skipped": [{"app": n, "reason": r.get("skip") or r.get("error")}
                          for n, r in skipped]}, args)
        return
    for n, _ in started:
        print(f"  started  {n}")
    for n in stopped:
        print(f"  stopped  {n}  (no active assessment)")
    for n in reused:
        print(f"  ok       {n}  (already serving)")
    for n, r in skipped:
        print(f"  ! skip   {n}  — {r.get('skip') or r.get('error')}")
    print(f"\n  synced: {len(started)} started, {len(stopped)} stopped, "
          f"{len(reused)} already serving, {len(skipped)} skipped")
    if skipped:
        sys.exit(EXIT_ERROR)


def cmd_relay_ls(args):
    """The fleet table + the NO-BRIDGE alarm (an active assessment with nobody answering)."""
    import supervisor as S
    import creds as C
    rows = S.ls()
    by_app = {r["app_id"]: r for r in rows}
    orphans = []
    # The NO-BRIDGE alarm is the single most important thing this command does, so its failures
    # must be LOUD. Both of these used to be swallowed: an API error for one app became "this app
    # has no runs" (so it was never checked), and a failure of the whole check printed a normal,
    # reassuring fleet table with no alarm and no hint that the alarm had not run.
    unchecked = []          # apps whose assessments could not be read
    check_error = None      # the whole check could not run
    if not args.no_check:
        try:
            c = _client(args)
            apps = _unwrap_list(c.list_apps())
            from concurrent.futures import ThreadPoolExecutor
            def fetch(a):
                try:
                    return a, _latest(_assessments_for(c, a["id"])), None
                except Exception as e:
                    return a, [], f"{type(e).__name__}: {e}"
            with ThreadPoolExecutor(max_workers=12) as pool:
                for a, asmts, err in pool.map(fetch, apps):
                    if err and needs_bridge(a):
                        unchecked.append({"app_id": a["id"], "app_name": a.get("name"),
                                          "error": err})
                        continue
                    if (asmts and str(asmts[0].get("status", "")).lower() in ACTIVE_STATES
                            and needs_bridge(a)):
                        r = by_app.get(a["id"])
                        if not r or r["state"] != "serving":
                            _bound = None
                            try:
                                import creds as _C
                                _bound = (_C.get(a["id"]) or {}).get("config")
                            except Exception:
                                pass
                            orphans.append({"app_id": a["id"], "app_name": a.get("name"),
                                            "assessment": asmts[0].get("id"),
                                            "config": _bound,
                                            "status": asmts[0].get("status")})
        except Exception as e:
            check_error = f"{type(e).__name__}: {e}"
    if args.json:
        # `bridges` is the current key; `relays` is kept so anything already scripted keeps working.
        _out({"bridges": rows, "relays": rows,
              "alarm_ran": (not args.no_check and check_error is None),
              "alarm_error": check_error, "unchecked": unchecked,
              "unserved_active_assessments": orphans}, args)
        return
    if rows:
        hdr = (f"  {'STATE':9} {'PID':>6} {'APP':26} {'CONFIG':12} {'ANS':>5} {'DELIV':>5} "
               f"{'FAIL':>4} {'LEASE-ERR':>9} {'SUB-ERR':>7} UPTIME  NAME")
        print(hdr); print("  " + "-" * (len(hdr) - 2))
        for r in sorted(rows, key=lambda x: (x["state"] != "serving", x.get("app_name") or "")):
            st = r["stats"] or {}
            up = ""
            if r.get("started_at"):
                secs = int(time.time() - r["started_at"])
                up = f"{secs//3600}h{(secs%3600)//60:02d}m" if secs >= 3600 else f"{secs//60}m{secs%60:02d}s"
            mark = "*" if r["state"] == "serving" else " "
            print(f"  {mark}{r['state']:8} {str(r.get('pid') or '-'):>6} {r['app_id']:26} "
                  f"{str(r.get('config') or '-'):12} {str(st.get('answered', '-')):>5} "
                  f"{str(st.get('delivered', '-')):>5} {str(st.get('failed', '-')):>4} "
                  f"{str(st.get('lease_errors', '-')):>9} {str(st.get('submit_errors', '-')):>7} "
                  f"{up:7} {r.get('app_name') or ''}")
            if r.get("fatal_error"):
                print(f"      ! {r['fatal_error']}")
        print(f"\n  {sum(1 for r in rows if r['state'] == 'serving')} serving, "
              f"{sum(1 for r in rows if r['state'] != 'serving')} not")
        # A relay in a lease/result timeout storm still answers probes, so ANSWERED alone looks
        # healthy. Make the storm loud: DELIV < ANS means results are being dropped and re-run.
        storm = [r for r in rows if (r["stats"] or {}).get("lease_errors")
                 or (r["stats"] or {}).get("submit_errors")]
        if storm:
            print("  !! lease/submit timeouts present on "
                  f"{len(storm)} bridge(s). When DELIV < ANS, results are being dropped and the")
            print("     probes re-run — usually the Ascend lease service is slow, not the target.")
    else:
        print("  no bridges on this machine")
        print("  `ascend assess run` auto-starts one; or reconcile all:  ascend bridge sync")
    if orphans:
        print("\n  !! NO BRIDGE — these bridge-based apps have a live assessment and nothing is")
        print("     answering it. Unanswered probes are not findings, so the run will finish")
        print("     looking CLEAN while measuring nothing (a FALSE PASS).")
        for o in orphans:
            cfg = o.get("config")
            print(f"     {o['app_name'] or o['app_id']}  assessment {o['assessment']} ({o['status']})")
            if cfg:
                print(f"       start it:  ascend bridge start --app {o['app_name']!r}")
            else:
                print(f"       no config/key bound yet — see:  ascend bridge start --help")
        print("     (api / gcp / bedrock apps are NOT listed here: Ascend calls those targets")
        print("      directly and they never need a local bridge.)")
    # A silent alarm is worse than no alarm: the table looks reassuring either way, so the ONE
    # thing that must never happen quietly is the check failing to run.
    if check_error:
        print(f"\n  !! THE NO-BRIDGE CHECK DID NOT RUN ({check_error}).")
        print("     The table above shows local processes only — it does NOT tell you whether a")
        print("     live assessment is going unanswered. Fix connectivity/auth and re-run, or")
        print("     check the Console directly.")
    elif unchecked:
        print(f"\n  !! {len(unchecked)} bridge-based app(s) could not be checked for live")
        print("     assessments, so a run with no bridge could be hiding among them:")
        for u in unchecked[:5]:
            print(f"       {u['app_name'] or u['app_id']}  ({u['error'][:60]})")
        if len(unchecked) > 5:
            print(f"       … and {len(unchecked) - 5} more")


def cmd_relay_stop(args):
    import supervisor as S
    targets = []
    if args.all:
        targets = [r["app_id"] for r in S.ls()]
    for ref in (args.app or []):
        targets.append(ref if str(ref).startswith("aapp_") else _resolve_app(_client(args), ref))
    if not targets:
        _die("pass --app <name> (repeatable) or --all")
    _say(args, f"Stopping {len(dict.fromkeys(targets))} bridge(s)...")
    out = [S.stop(a, grace_s=args.grace) for a in dict.fromkeys(targets)]
    _say(args, f"{sum(1 for r in out if r.get('stopped'))} stopped", done=True)
    _out(out, args, human="\n".join(
        f"  {'stopped' if r.get('stopped') else 'not running'}  {r['app_id']}"
        + (f"  ({r.get('how') or r.get('reason')})" if (r.get('how') or r.get('reason')) else "")
        for r in out))


def cmd_relay_logs(args):
    import supervisor as S
    app_id = args.app if str(args.app).startswith("aapp_") else _resolve_app(_client(args), args.app)
    log = S.paths_for(app_id)["log"]
    if not log.exists():
        _die(f"no log for {args.app} at {log}")
    if args.follow:
        import subprocess as sp
        try:
            sp.run(["tail", "-f", str(log)])
        except KeyboardInterrupt:
            pass
        return
    print(log.read_text()[-20000:])


# ----------------------------------------------------------------------------- keys
def cmd_keys_list(args):
    """Every stored bridge key (masked), and whether its app still exists."""
    import creds as C
    recs = C.load_all()
    live = None
    if not args.no_check:
        try:
            live = {a.get("id") for a in _unwrap_list(_client(args).list_apps())}
        except Exception:
            live = None
    rows = []
    for aid, r in sorted(recs.items(), key=lambda kv: (kv[1].get("app_name") or "")):
        exists = "-" if live is None else ("yes" if aid in live else "GONE")
        rows.append({"app_id": aid, "app_name": r.get("app_name"), "config": r.get("config"),
                     "adapter": r.get("adapter"), "key": C.mask(r.get("thin_api_key")),
                     "app_exists": exists})
    if args.json:
        _out(rows, args)
        return
    if not rows:
        print("  no stored keys")
        print("  keys are stored by `ascend onboard` / `ascend app create`, "
              "or add one:  ascend keys add --app <app> --key tc-…")
        return
    hdr = f"  {'APP':28} {'KEY':14} {'CONFIG':18} {'ADAPTER':14} {'APP?':5} NAME"
    print(hdr); print("  " + "-" * (len(hdr) - 2))
    for r in rows:
        print(f"  {r['app_id']:28} {r['key']:14} {str(r['config'] or '-'):18} "
              f"{str(r['adapter'] or '-'):14} {r['app_exists']:5} {r['app_name'] or ''}")
    dead = sum(1 for r in rows if r["app_exists"] == "GONE")
    print(f"\n  {len(rows)} key(s)" + (f", {dead} for apps that no longer exist "
                                       f"(clean up:  ascend keys prune)" if dead else ""))


def cmd_keys_prune(args):
    """Drop stored keys whose Ascend app is gone.

    SAFETY: a bridge key is shown exactly once by the API, so a wrong prune is unrecoverable. If the
    app list came back empty or unparseable (an API/envelope change, a half-failed call), the naive
    set-difference would consider EVERY key stale and delete all of them — silently, exit 0. So we
    refuse to act on a suspicious app list, and require --yes to delete everything.
    """
    import creds as C
    apps = _unwrap_list(_client(args).list_apps())
    live = {a.get("id") for a in apps if a.get("id")}
    stored = C.load_all()
    if not stored:
        _out({"pruned": [], "remaining": 0}, args, human="no stored keys")
        return
    if not live:
        _die("the app list came back empty or unreadable, so every stored key would look stale.\n"
             "  Refusing to prune (a bridge key is shown only once and cannot be recovered).\n"
             "  Check `ascend app list` first; if the tenant really has no apps, "
             "use `ascend keys rm <app>` per key.", code=EXIT_ERROR)
    would_delete = [aid for aid in stored if aid not in live]
    if would_delete and len(would_delete) == len(stored) and not args.yes:
        _die(f"this would delete ALL {len(stored)} stored key(s) — that usually means the app list "
             f"is wrong, not that every app is gone.\n"
             f"  re-run with --yes if you are sure.", code=EXIT_ERROR)
    dead = C.prune(live)
    _out({"pruned": dead, "remaining": len(C.load_all())}, args,
         human=(f"pruned {len(dead)} stale key(s)" if dead else "nothing to prune"))


def cmd_keys_add(args):
    """Store a bridge key for an app (e.g. one minted in the Console)."""
    import creds as C
    if not str(args.key).startswith("tc-"):
        _die("a bridge key looks like 'tc-…' — that does not")
    c = _client(args)
    app_id = _resolve_app(c, args.app)
    name = None
    try:
        name = (c.get_app(app_id) or {}).get("name")
    except Exception:
        pass
    rec = C.save(app_id, args.key, app_name=name, config=args.config, adapter=args.adapter)
    _say(args, f"stored the bridge key for {name or app_id}", done=True)
    _out({**rec, "thin_api_key": C.mask(rec.get("thin_api_key"))}, args,
         human=f"stored key {C.mask(args.key)} for {name or app_id}")


def cmd_keys_rm(args):
    """Forget a stored key — optionally deleting the Ascend app it belongs to.

    Dropping only the key leaves an app nobody can serve (the bridge key is shown once and cannot be
    re-read), so `--delete-app` is the honest way to retire the pair together.
    """
    import creds as C
    c = _client(args) if (not str(args.app).startswith("aapp_") or args.delete_app) else None
    app_id = args.app if str(args.app).startswith("aapp_") else _resolve_app(c, args.app)
    _say(args, f"Removing the stored key for {args.app}...")
    removed = C.remove(app_id)
    if removed:
        _say(args, "key removed", done=True)
    app_deleted = False
    if args.delete_app:
        try:
            import supervisor as S
            if S.is_running(app_id):
                S.stop(app_id)
        except Exception:
            pass
        c.delete_app(app_id)
        app_deleted = True
    human = ("removed the stored key" if removed else "no stored key for that app")
    if app_deleted:
        human += " · deleted the Ascend app too"
    elif removed:
        human += ("\n  NOTE: the app still exists but can no longer be served — its key is shown "
                  "only at creation. Retire it with:  ascend keys rm <app> --delete-app")
    _out({"removed": removed, "app_id": app_id, "app_deleted": app_deleted}, args, human=human)


# ----------------------------------------------------------------------------- reports
_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4,
             "informational": 4, "none": 5, "unknown": 0, "-": 6}

# What `--min-sev` accepts. Kept next to the ranks so the flag and the filter cannot drift.
SEVERITY_CHOICES = ("critical", "high", "medium", "low", "info", "none")

# Severities a LOCAL policy may assign. `critical` is allowed here (it affects local
# ranking and CI gates) even though the platform clamps it to `high` on push.
POLICY_SEVERITIES = ("critical", "high", "medium", "low", "info", "none")


def _row_sev_rank(row):
    """Rank a report row's severity, failing SAFE when it cannot be determined.

    A finished run whose severity is missing or unrecognized used to fall back to rank 6 — the
    LEAST severe — so it was silently filtered out of a `--min-sev high` view. Meanwhile
    reporting/ci.py already treats an undeterminable severity as the MOST severe so it breaches
    the gate. The same run therefore failed CI while showing nothing in the report a human reads.

    Now: a finished run with an unreadable severity ranks most-severe (it needs a look), while a
    run that simply has not produced one yet (still running) ranks last, because there is nothing
    wrong with it — it just is not done.
    """
    raw = str(row.get("severity") or "").strip().lower()
    if raw in _SEV_RANK:
        return _SEV_RANK[raw]
    import api
    if str(row.get("status", "")).lower() in api.TERMINAL_STATUSES:
        return 0            # finished but unreadable -> surface it, never hide it
    return 6                # not finished yet -> no severity is expected


def _age(iso):
    """`2026-08-17T13:34:49Z` -> `2h` / `3d`. Reports are scanned, not read."""
    if not iso:
        return "-"
    try:
        from datetime import datetime, timezone
        t = datetime.fromisoformat(str(iso).replace("Z", "+00:00"))
        secs = (datetime.now(timezone.utc) - t).total_seconds()
    except Exception:
        return str(iso)[:10]
    if secs < 3600:
        return f"{int(secs // 60)}m"
    if secs < 86400:
        return f"{int(secs // 3600)}h"
    return f"{int(secs // 86400)}d"


def cmd_reports(args):
    """Assessment results as a table — what passed, what failed, how bad.

    Two tiers on purpose. The app+assessment lists give app/when/status/score/severity cheaply
    (one call per app). Probe and finding counts live only on the individual assessment, so
    `--detail` pays one more call per run to add them — with the spinner showing the cost.
    """
    # `--since` used to be parsed inside the row loop inside a try/except that swallowed the
    # ValueError, so `--since bogus` silently disabled the filter and reported MORE rows than
    # asked for, with no indication the flag had been ignored.
    since_days = None
    if getattr(args, "since", None):
        raw = str(args.since).strip().lower().rstrip("d")
        if not raw.isdigit():
            _die(f"--since expects a number of days, e.g. 7 or 7d — got {args.since!r}",
                 error_code="bad_since")
        since_days = int(raw)

    import api
    import ui as _ui
    import policy as P
    from concurrent.futures import ThreadPoolExecutor

    c = _client(args)
    pol = P.load(getattr(args, "policy", None))
    apps = _unwrap_list(c.list_apps())
    if args.app:
        # Accept a bare string as well as a repeated flag: iterating a str yields CHARACTERS, so
        # a single `--app Foo` used to resolve 'F', 'o', 'o' and report "matches 26 apps".
        refs = args.app if isinstance(args.app, (list, tuple)) else [args.app]
        wanted = {_resolve_app(c, r) for r in refs}
        apps = [a for a in apps if a.get("id") in wanted]
    if not apps:
        _die("no matching apps")

    def runs_of(a):
        try:
            return a, _latest(_assessments_for(c, a["id"]))
        except Exception:
            return a, []

    rows = []
    with _ui.progress("reading assessments", total=len(apps), args=args) as prog:
        with ThreadPoolExecutor(max_workers=12) as pool:
            for a, runs in pool.map(runs_of, apps):
                prog.advance()
                for r in runs[: max(1, args.per_app)]:
                    st = str(r.get("status", "")).lower()
                    if not args.include_running and st not in api.TERMINAL_STATUSES:
                        continue
                    if since_days is not None and _age(r.get("created_at")).endswith("d"):
                        try:
                            if int(_age(r.get("created_at"))[:-1]) > since_days:
                                continue
                        except ValueError:
                            pass
                    rows.append({"app": a.get("name"), "app_id": a["id"],
                                 "assessment": r.get("id"), "name": r.get("name"),
                                 "when": r.get("created_at"), "status": st,
                                 # total/failed are in the LIST payload — real, explainable
                                 # pass/fail with no extra call. (score is a platform index we
                                 # deliberately do not surface — it has no transparent formula.)
                                 "total": r.get("total"), "failed": r.get("failed"),
                                 "severity": r.get("severity")})

    # --- tier 2: probe/finding counts need the individual assessment -----------------
    if args.detail and rows:
        def enrich(row):
            try:
                full = c.get_assessment(row["app_id"], row["assessment"])
            except Exception:
                return row
            finds = api.iter_findings(full)
            finds = P.apply_to_findings(pol, finds, app_name=row["app"])
            worst = min((_SEV_RANK.get(str(f.get("severity")).lower(), 6) for f in finds),
                        default=6)
            row.update({
                "probes_total": full.get("total"), "probes_failed": full.get("failed"),
                "findings": len(finds),
                "controls_failed": sum(1 for f in finds if str(f.get("status")).lower() != "pass"),
                "categories": sorted({f.get("category") for f in finds if f.get("category")}),
                "policy_reranked": sum(1 for f in finds
                                       if f.get("severity_source") == "local-policy"),
                "worst_severity": next((k for k, v in _SEV_RANK.items() if v == worst), None),
                "false_pass_suspect": bool(_false_pass_warning(full)),
            })
            return row

        with _ui.progress("reading findings", total=len(rows), args=args) as prog:
            with ThreadPoolExecutor(max_workers=8) as pool:
                rows = [r for r in pool.map(lambda r: (prog.advance(), enrich(r))[1], rows)]

    if args.min_sev:
        floor = _SEV_RANK[args.min_sev.lower()]      # argparse restricts this to known values
        rows = [r for r in rows if _row_sev_rank(r) <= floor]

    key = {"sev": lambda r: (_row_sev_rank(r), r["app"] or ""),
           "fail": lambda r: (-((r.get("failed") or 0) / (r.get("total") or 1)), r["app"] or ""),
           "when": lambda r: (str(r.get("when") or ""), r["app"] or "")}[args.sort]
    rows.sort(key=key, reverse=(args.sort == "when"))

    if args.json:
        _out({"ok": True, "data": rows, "policy": bool(pol)}, args)
        return
    if not rows:
        print("  no reports match")
        print("  run one:  ascend assess run --app <app> --name 'run 1'")
        return

    # leading "R" column = a colored ● risk dot (magenta/red/yellow/green); the 2-char dot cell
    # means the table header carries two extra leading spaces to stay aligned.
    # No "score": that platform index has no transparent formula. FAIL% is the real, explainable
    # metric — probes the target failed ÷ total probes — and matches the Console's Fail %.
    def _failpct(row):
        total = row.get("total") if row.get("total") is not None else row.get("probes_total")
        failed = row.get("failed") if row.get("failed") is not None else row.get("probes_failed")
        if not total:
            return "-", 0, 0
        return f"{100 * (failed or 0) / total:.0f}%", (failed or 0), total

    if args.detail:
        hdr = (f"    {'SEV':8} {'FAIL%':>6} {'PASS/FAIL':11} {'PROBES':>9} {'FIND':>4}  "
               f"{'WHEN':>5}  {'APP':26} CATEGORIES")
    else:
        hdr = f"    {'SEV':8} {'FAIL%':>6} {'PROBES':>9} {'WHEN':>5}  {'STATUS':10} {'APP':26} ASSESSMENT"
    print(hdr)
    print("  " + "-" * (len(hdr) - 2))
    for r in rows:
        dot = _ui.risk_dot(r.get("severity"))
        sev = _ui.severity_chip(r.get("severity"))
        failpct, failed, total = _failpct(r)
        probes = f"{failed}/{total}" if total else "-"
        when = _age(r.get("when"))
        if args.detail:
            pf = _ui.bar(max(0, total - failed), failed)
            cats = ", ".join((r.get("categories") or [])[:3]) or "-"
            flag = " !!" if r.get("false_pass_suspect") else ""
            pol_mark = " ~" if r.get("policy_reranked") else ""
            print(f"  {dot} {sev} {failpct:>6} {pf:11} {probes:>9} "
                  f"{str(r.get('findings', '-')):>4}  {when:>5}  {str(r['app'])[:26]:26} "
                  f"{cats}{flag}{pol_mark}")
        else:
            print(f"  {dot} {sev} {failpct:>6} {probes:>9} {when:>5}  {r['status']:10} "
                  f"{str(r['app'])[:26]:26} {r['assessment']}")

    print(f"\n  {len(rows)} report(s)")
    print("  ● risk = severity (red high · yellow medium · green low)   ·   "
          "FAIL% = probes the target failed ÷ total probes")
    if args.detail:
        print("  PROBES = failed/total probes · FIND = failed controls (findings) — different units")
        if any(r.get("false_pass_suspect") for r in rows):
            print("  !! = suspiciously few probes on a clean score — check the bridge was up "
                  "(docs/ASSESSMENT_LIFECYCLE.md)")
        if any(r.get("policy_reranked") for r in rows):
            print("  ~  = severity re-ranked by your local policy (ascend policy show)")
    else:
        print("  add --detail for pass/fail, probe and finding counts")


# ----------------------------------------------------------------------------- policy
def cmd_policy_show(args):
    import policy as P
    doc = P.load(getattr(args, "policy", None))
    path = P.policy_path(getattr(args, "policy", None))
    if args.json:
        _out({"ok": True, "path": str(path), "exists": path.exists(), "data": doc}, args)
        return
    if not doc:
        print(f"  no policy at {path}")
        print("  per-CONTROL severity is not settable via the v3 API, so gates live here.\n"
              "  per-CATEGORY severity IS settable — set it, then `ascend policy push --app <app>`.\n"
              "  create one:  ascend policy set --fail-on-severity high "
              "--control tool_misuse=critical")
        return
    print(f"  policy: {path}")
    d = doc.get("default") or {}
    print(f"  default  fail_on_severity={d.get('fail_on_severity', 'high')} "
          f"fail_on_new={d.get('fail_on_new', True)}")
    for name, blk in (doc.get("apps") or {}).items():
        print(f"  app {name!r}")
        for k in ("fail_on_severity", "fail_on_new"):
            if k in blk:
                print(f"      {k}={blk[k]}")
        for scope in ("controls", "categories"):
            for k, v in (blk.get(scope) or {}).items():
                print(f"      {scope[:-1]} {k} -> {v}")


def cmd_policy_push(args):
    """Push the CATEGORY severities from the local policy up to the Ascend app.

    Only the category half can go upstream: `category_severities` is a real field on the app.
    Per-control overrides stay local because v3 has nowhere to put them — that split is reported
    rather than glossed over, so nobody assumes a control override reached the Console.
    """
    import api
    import policy as P
    c = _client(args)
    doc = P.load(getattr(args, "policy", None))
    if not doc:
        _die(f"no policy file at {P.policy_path(getattr(args, 'policy', None))}\n"
             f"  create one:  ascend policy set --app {args.app!r} --category data_leak=high")

    app_id = _resolve_app(c, args.app)
    app = c.get_app(app_id)
    app_name = app.get("name") or args.app

    blk = (doc.get("apps") or {}).get(app_name) or {}
    cats = dict((doc.get("default") or {}).get("categories") or {})
    cats.update(blk.get("categories") or {})
    ctrl_only = dict(blk.get("controls") or {})

    if not cats:
        _die(f"policy has no category severities for {app_name!r} — nothing to push\n"
             f"  per-control overrides stay local; add a category:\n"
             f"  ascend policy set --app {app_name!r} --category data_leak=high",
             error_code="nothing_to_push")

    clamped = api.clamped_severities(cats)
    try:
        payload = api.normalize_category_severities(cats)
    except api.SpecError as e:
        _die(str(e), error_code="invalid_severity")

    if clamped:
        print(f"warning: the platform's category enum stops at 'high' — clamping 'critical' to "
              f"'high' for: {', '.join(clamped)}", file=sys.stderr)
    if ctrl_only:
        print(f"note: {len(ctrl_only)} per-control override(s) stay local "
              f"({', '.join(sorted(ctrl_only))}) — v3 has no field for them, so they apply only "
              f"to `ascend reports` and `ascend ci`.", file=sys.stderr)

    if args.dry_run:
        _out({"ok": True, "app": app_name, "would_push": payload, "local_only": ctrl_only}, args,
             human=("would push (dry run):\n  "
                    + "\n  ".join(f"{p['id']} -> {p['severity']}" for p in payload)))
        return

    updated = c.patch_app(app_id, {"category_severities": payload})
    got = updated.get("category_severities") or []
    # Assert the platform actually stored it — a silently-ignored PATCH would let someone believe
    # the Console reflects their policy when it does not.
    if sorted((g.get("id"), g.get("severity")) for g in got) != \
            sorted((p["id"], p["severity"]) for p in payload):
        print(f"warning: the app now reports {got} — which does not match what was sent. "
              f"Check the Console before relying on it.", file=sys.stderr)
    _out({"ok": True, "app": app_name, "category_severities": got, "local_only": ctrl_only}, args,
         human=("pushed to " + app_name + ":\n  "
                + "\n  ".join(f"{g.get('id')} -> {g.get('severity')}" for g in got)))


def cmd_policy_set(args):
    """Write gate thresholds and severity overrides. Commit the file with your pipeline."""
    import policy as P
    doc = P.load(getattr(args, "policy", None)) or {}
    target = doc.setdefault("apps", {}).setdefault(args.app, {}) if args.app \
        else doc.setdefault("default", {})
    if args.fail_on_severity:
        target["fail_on_severity"] = args.fail_on_severity
    if args.allow_new:
        target["fail_on_new"] = False
    if args.fail_on_new:
        target["fail_on_new"] = True
    # A severity this file does not understand is worse than useless: the policy drives CI gates,
    # and an unrecognized value is ranked most-severe by the fail-safe, so a typo would silently
    # fail every future gate. `policy push` would also reject it later, far from where it was
    # typed. Refuse it here, where the fix is obvious.
    def _severity(v, flag):
        sev = v.strip().lower()
        if sev not in POLICY_SEVERITIES:
            _die(f"--{flag} severity must be one of: {', '.join(POLICY_SEVERITIES)} "
                 f"(got {v.strip()!r})\n"
                 f"  note: the platform's own category enum stops at 'high'; 'critical' applies "
                 f"locally and is clamped on `ascend policy push`",
                 error_code="bad_severity")
        return sev

    for item in (args.control or []):
        if "=" not in item:
            _die(f"--control expects id=severity (got {item!r})")
        k, v = item.split("=", 1)
        target.setdefault("controls", {})[k.strip()] = _severity(v, "control")
    for item in (args.category or []):
        if "=" not in item:
            _die(f"--category expects id=severity (got {item!r})")
        k, v = item.split("=", 1)
        target.setdefault("categories", {})[k.strip()] = _severity(v, "category")
    path = P.save(doc, getattr(args, "policy", None))
    _out({"ok": True, "path": str(path), "data": doc}, args,
         human=f"wrote {path}\n  applies to reports and `ascend ci` gates")


# ----------------------------------------------------------------------------- status
def cmd_status(args):
    """One answer to "where do things stand?" — tenant, apps, live runs, bridges, keys.

    Exists because reading that used to take three commands (and three fan-outs). An agent
    orchestrating assessments needs to read state cheaply before deciding anything.
    """
    import ui as _ui
    import tenant as T
    out = {"tenant": None, "apps": {}, "live": [], "bridges": [], "keys": 0, "warnings": []}

    rec = T.load()
    if rec:
        out["tenant"] = {"label": rec.get("label"),
                         "fingerprint": (rec.get("fingerprint") or "")[:16]}
    try:
        import creds as C
        out["keys"] = len(C.load_all())
    except Exception:
        pass
    try:
        import supervisor as S
        out["bridges"] = [{"app_id": r["app_id"], "app_name": r.get("app_name"),
                          "state": r["state"], "pid": r.get("pid"),
                          "answered": (r.get("stats") or {}).get("answered")}
                          for r in S.ls()]
    except Exception:
        pass

    c = _client(args)
    apps = _unwrap_list(c.list_apps())
    out["apps"] = {"total": len(apps),
                   "by_type": {_type_label(t): sum(1 for a in apps if (a.get("api_type") or "-") == t)
                               for t in sorted({(a.get("api_type") or "-") for a in apps})}}
    if not args.quick:
        from concurrent.futures import ThreadPoolExecutor
        serving = {r["app_id"] for r in out["bridges"] if r["state"] == "serving"}

        def fetch(a):
            try:
                return a, _latest(_assessments_for(c, a["id"]))
            except Exception:
                return a, []

        with _ui.progress("reading assessments", total=len(apps), args=args) as prog:
            with ThreadPoolExecutor(max_workers=12) as pool:
                for a, rows in pool.map(fetch, apps):
                    prog.advance()
                    if not rows:
                        continue
                    top = rows[0]
                    st = str(top.get("status", "")).lower()
                    if st in ACTIVE_STATES:
                        served = a["id"] in serving
                        wants = needs_bridge(a)
                        out["live"].append({
                            "app": a.get("name"), "app_id": a["id"],
                            "assessment": top.get("id"), "status": st,
                            "api_type": a.get("api_type"), "needs_bridge": wants,
                            "progress": top.get("progress"), "bridge_serving": served})
                        if wants and not served:
                            out["warnings"].append(
                                f"{a.get('name')}: assessment {top.get('id')} is {st} with NO "
                                f"bridge — probes go unanswered and the run scores a FALSE PASS")

    if args.json:
        out["relays"] = out["bridges"]          # deprecated alias
        _out({"ok": True, "data": out}, args)
        return

    t = out["tenant"]
    print(f"  tenant   {t['label'] if t else '(not pinned)'}")
    print(f"  apps     {out['apps']['total']}  " +
          " ".join(f"{k}={v}" for k, v in out["apps"]["by_type"].items()))
    print(f"  keys     {out['keys']} stored")
    serving_n = sum(1 for r in out["bridges"] if r["state"] == "serving")
    print(f"  bridges  {serving_n} serving"
          + (f", {len(out['bridges']) - serving_n} not" if len(out["bridges"]) > serving_n else ""))
    if args.quick:
        print("  (--quick: skipped the per-app assessment scan)")
    else:
        print(f"  live     {len(out['live'])} assessment(s) running")
        for r in out["live"]:
            mark = "*" if r.get("bridge_serving") else ("!" if r.get("needs_bridge") else " ")
            print(f"    {mark} {_pct(r['progress']):>5}  {r['app']}  ({r['assessment']})")
    for w in out["warnings"]:
        print(f"\n  !! {w}")
    if out["warnings"]:
        print("     fix:  ascend bridge sync   (re-ensures a bridge for every live assessment)")


# ----------------------------------------------------------------------------- tenant
def cmd_tenant_show(args):
    """What tenant is this CLI locked to?"""
    import tenant as T
    rec = T.load()
    live = _live_relays_count()
    if not rec:
        info = {"pinned": False, "relays_running": live}
        _out(info, args, human=("no tenant pinned yet — the next authenticated command pins this CLI "
                                "to whichever tenant your PAT belongs to."))
        return
    keys = 0
    try:
        import creds as C
        keys = len(C.load_all())
    except Exception:
        pass
    info = {"pinned": True, "label": rec.get("label"), "fingerprint": rec.get("fingerprint", "")[:16],
            "pinned_at": rec.get("pinned_at"), "stored_keys": keys, "relays_running": live,
            "state_dir": str(T.state_root())}
    _out(info, args, human="\n".join([
        f"  tenant     {rec.get('label')}",
        f"  fingerprint {rec.get('fingerprint','')[:16]}…  (sha256 of iss|straikerId; not a secret)",
        f"  pinned at  {rec.get('pinned_at')}",
        f"  stored keys {keys}",
        f"  bridges running {live}",
        f"  state dir  {T.state_root()}",
    ]))


def cmd_tenant_switch(args):
    """Move this CLI to a different tenant, clearing anything tenant-scoped."""
    import tenant as T
    rec = T.load()
    if not rec:
        _die("no tenant is pinned yet — nothing to switch from.")
    live = _live_relays_count()
    if live and not args.force:
        _die(f"{live} bridge(s) are still running. Stop them first:  ascend bridge stop --all\n"
             f"  (a running bridge holds this tenant's bridge key; switching under it would be unsafe)")
    if not args.confirm:
        _die(f"this clears the stored keys for tenant {rec.get('label')!r} and unpins it.\n"
             f"  re-run with --confirm to proceed.")
    archived = None
    try:
        import creds as C
        archived = C.archive_all()
    except Exception:
        pass
    T.clear()
    _out({"switched_from": rec.get("label"), "keys_archived": archived}, args,
         human=(f"unpinned {rec.get('label')}"
                + (f"; archived {archived} key(s)" if archived else "")
                + "\n  the next authenticated command pins the new tenant."))


# ----------------------------------------------------------------------------- doctor

def _doctor_api_compat(args):
    """Verify every API field the CLI depends on — drift should be LOUD, not a silent `-`."""
    import apicompat as AC
    import ui as _ui
    c = _client(args)
    with _ui.progress("checking API compatibility", args=args):
        spec_text, spec_url = AC.fetch_spec(args.base, bearer=c._bearer())
        rep = AC.check(c, spec_text=spec_text)
    rep["spec_url"] = spec_url
    if args.json:
        _out({"ok": rep["ok"], "data": rep}, args)
        sys.exit(EXIT_OK if rep["ok"] else EXIT_ERROR)

    print(f"  spec:      {spec_url or '(not published / unreachable)'}")
    print(f"  sampled:   {'yes' if rep['sampled'] else 'no'}"
          f"   list envelope: {rep['list_envelope'] or '?'}")
    print()
    for r in rep["results"]:
        mark = {"ok": "[ok]", "MISSING": "[XX]", "unknown": "[..]"}[r["state"]]
        line = f"  {mark} {r['schema']}.{r['field']}"
        if r["state"] != "ok":
            line += f"   ({r['severity']}) {r['why']}"
        print(line)
    nf = rep.get("nested_findings") or {}
    if nf:
        got = [k for k, v in nf.items() if v is True or (k.endswith('_len') and v)]
        print(f"\n  findings shape: {len(got)}/{len(nf)} fields present "
              f"({', '.join(k for k in nf if nf[k] is False) or 'all ok'})")
    if rep["critical_missing"]:
        print("\n  !! CRITICAL field(s) missing — a wrong verdict is possible:")
        for r in rep["critical_missing"]:
            print(f"     {r['schema']}.{r['field']}: {r['why']}")
    print(f"\napi-compat: {'OK' if rep['ok'] else 'DRIFT DETECTED'}")
    sys.exit(EXIT_OK if rep["ok"] else EXIT_ERROR)


def _fetch_latest_release(timeout_s=6.0):
    """GET the latest PUBLISHED GitHub release. One hardcoded host, unauthenticated (no PAT, no
    telemetry), best-effort. Returns {tag,name,url,body} | {"no_release": True} | None.

    "Latest" is the latest *release* on purpose (releases/latest excludes drafts/pre-releases), so
    routine pushes and plain tags stay invisible — see runtime/selfupdate.py.
    """
    import selfupdate as _su
    try:
        import requests
        r = requests.get(_su.RELEASES_LATEST_URL,
                         headers={"Accept": "application/vnd.github+json",
                                  "User-Agent": f"ascend-cli/{VERSION}"},
                         timeout=timeout_s)
    except Exception:
        return None
    if r.status_code == 404:
        return {"no_release": True}   # repo has no published release yet
    if r.status_code != 200:
        return None                   # rate-limited / transient — treat as unreachable
    try:
        d = r.json()
    except Exception:
        return None
    return {"tag": d.get("tag_name"), "name": d.get("name"),
            "url": d.get("html_url"), "body": d.get("body")}


def _install_context():
    """(kind, upgrade_command) for how this copy was installed."""
    import selfupdate as _su
    frozen = bool(getattr(sys, "frozen", False) or getattr(sys, "_MEIPASS", None))
    kind = _su.install_kind(frozen=frozen, repo_has_git=(REPO / ".git").exists(),
                            module_path=str(REPO))
    return kind, _su.update_command(kind, repo_path=str(REPO))


def _version_state():
    """(version-check dict, install kind, upgrade command). Never raises; never blocks doctor."""
    import selfupdate as _su
    ver = _su.check(VERSION, _fetch_latest_release)
    kind, cmd = _install_context()
    return ver, kind, cmd


def _doctor_update(args):
    """`ascend doctor --update` — update in place for a clone, or print the command otherwise."""
    import subprocess
    ver, kind, upd_cmd = _version_state()
    st = ver["state"]
    if st not in ("update_available", "update_recommended"):
        reason = {"up_to_date": f"already up to date (version {ver['current']}, latest "
                                 f"{ver['latest']})",
                  "no_release": "no published release to update to",
                  "skipped": f"update check skipped: {ver.get('reason')}",
                  "unknown": f"update check unavailable: {ver.get('reason')}"}.get(st, st)
        if args.json:
            _out({"ok": True, "updated": False, "version": ver, "message": reason}, args)
        else:
            print(reason)
        sys.exit(EXIT_OK)
    if kind != "clone":
        # A pipx/binary copy cannot be safely rewritten from inside its own process.
        if args.json:
            _out({"ok": True, "updated": False, "version": ver, "update_command": upd_cmd}, args)
        else:
            print(f"a newer version is available ({ver['current']} -> {ver['latest']}).")
            print(f"  update: {upd_cmd}")
        sys.exit(EXIT_OK)
    if not args.json:
        print(f"updating {ver['current']} -> {ver['latest']}  ({upd_cmd})")
    try:
        res = subprocess.run(["git", "-C", str(REPO), "pull", "--ff-only"],
                             capture_output=True, text=True, timeout=120)
    except Exception as e:
        if args.json:
            _out({"ok": False, "updated": False, "version": ver, "error": str(e)}, args)
        else:
            print(f"could not run git: {e}\n  do it manually: {upd_cmd}")
        sys.exit(EXIT_ERROR)
    out = ((res.stdout or "") + (res.stderr or "")).strip()
    okp = res.returncode == 0
    if args.json:
        _out({"ok": okp, "updated": okp, "version": ver, "git_output": out}, args)
    else:
        if out:
            print(out)
        print(f"updated — re-run `ascend version` to confirm ({ver['latest']})." if okp
              else f"git pull did not fast-forward (local changes or diverged). resolve, then: {upd_cmd}")
    sys.exit(EXIT_OK if okp else EXIT_ERROR)


def cmd_doctor(args):
    if getattr(args, "api_compat", False):
        return _doctor_api_compat(args)
    if getattr(args, "update", False):
        return _doctor_update(args)
    import shutil, urllib.request
    checks = []
    tok = args.token or os.environ.get("STRAIKER_PAT") or os.environ.get("STRAIKER_TOKEN")
    checks.append(("PAT present", bool(tok)))
    if tok:
        try:
            c = _client(args)
            cat = c.list_controls()
            n = len(_unwrap_list(cat, "controls"))   # tolerate a bare-list response
            checks.append((f"PAT exchange + /ascend/controls ({n} controls)", n > 0))
        except Exception as e:
            checks.append((f"PAT exchange FAILED: {str(e)[:80]}", False))
    # Any HTTP status proves reachability (a 404/401 from the bridge means we got there).
    # Use requests so corporate proxy env vars are honoured — urllib ignored them and
    # reported a false negative behind a proxy, then told the user the tool was broken.
    try:
        import requests as _rq
        r = _rq.get(args.bridge_base + "/ping", timeout=8)
        checks.append((f"bridge reachable (HTTP {r.status_code})", True))
    except Exception as e:
        checks.append((f"bridge NOT reachable: {str(e)[:60]}", False))
    checks.append((f"config dir ({config_dir()})", config_dir().exists()))
    try:
        import requests  # noqa: F401
        checks.append(("requests (the only required package)", True))
    except ImportError:
        checks.append(("requests MISSING — pip install requests", False))
    # A config that will not parse is invisible until `runtime start` fails.
    bad_cfgs = []
    for f in sorted(config_dir().glob("*.json")) if config_dir().is_dir() else []:
        try:
            json.loads(f.read_text())
        except Exception:
            bad_cfgs.append(f.name)
    checks.append(("all configs parse as JSON" if not bad_cfgs
                   else f"INVALID config JSON: {', '.join(bad_cfgs[:3])}", not bad_cfgs))
    ok = all(v for _, v in checks)

    # Optional extras: each unlocks one capability. Missing = warn, never fail.
    def _has(mod):
        try:
            __import__(mod); return True
        except Exception:
            return False
    soft = [
        ("STRAIKER_BRIDGE_API_KEY set (needed to run a bridge)",
         bool(os.environ.get("STRAIKER_BRIDGE_API_KEY"))),
        ("websockets  (WebSocket targets)", _has("websockets")),
        ("playwright  (adapter build --url live capture)", _has("playwright")),
        ("boto3       (bedrock adapter: Converse / Agent / AgentCore)", _has("boto3")),
        ("google-auth (vertex_ai service-account auth)", _has("google.auth")),
        ("tmux        (terminal/CLI agent targets)", shutil.which("tmux") is not None),
    ]
    # Version vs the latest published GitHub release. A SOFT signal — being behind is never a
    # doctor failure, so it never touches `ok`/the exit code. Fully swallowed if GitHub is
    # unreachable or ASCEND_NO_UPDATE_CHECK is set.
    ver, kind, upd_cmd = _version_state()
    behind = ver["state"] in ("update_available", "update_recommended")
    if args.json:
        _out({"ok": ok, "checks": {k: v for k, v in checks}, "optional": {k: v for k, v in soft},
              "version": {"current": ver["current"], "latest": ver["latest"],
                          "state": ver["state"], "severity": ver["severity"],
                          "min_supported": ver.get("min_supported"), "install_method": kind,
                          "update_command": upd_cmd if behind else None,
                          "reason": ver.get("reason")}}, args)
    else:
        for k, v in checks:
            print(f"  [{'ok' if v else 'XX'}] {k}")
        for k, v in soft:
            print(f"  [{'ok' if v else '..'}] {k} (optional)")
        cur, lat, st = ver["current"], ver["latest"], ver["state"]
        if st == "up_to_date":
            print(f"  [ok] version {cur} (latest) (optional)")
        elif st == "update_available":
            print(f"  [..] version {cur} -> {lat} available (optional)")
            print(f"       update: {upd_cmd}")
        elif st == "update_recommended":
            floor = f" (below min-supported {ver['min_supported']})" if ver.get("min_supported") else ""
            print(f"  [!!] version {cur} -> {lat} — UPDATE RECOMMENDED{floor} (optional)")
            print(f"       update: {upd_cmd}")
        elif st == "no_release":
            print(f"  [..] version {cur} (no published release to compare) (optional)")
        else:  # skipped / unknown
            print(f"  [..] version {cur} (update check unavailable: {ver.get('reason')}) (optional)")
        print("doctor:", "OK" if ok else "problems found")
    sys.exit(EXIT_OK if ok else EXIT_ERROR)


# ----------------------------------------------------------------------------- scaffolds
def _upgrade_streaming_shape(cfg, vres, args, V):
    """Promote a validated config to a streaming adapter when the reply proves it is one.

    Returns (cfg, vres) — re-validated if the shape changed, so what gets written is still a
    config that provably answered. If the upgrade cannot be proven, the original is kept: a
    working direct_api config beats an unproven "better" one.
    """
    if cfg.get("adapter") != "direct_api":
        return cfg, vres
    body = str(vres.get("response") or "")
    # Absolute import, matching every other discovery import in this file. The bare `discovery`
    # form resolved to a different module depending on what else had been imported first, and the
    # bare `except` below turned that into a silent no-op: the upgrade quietly never ran and the
    # config was written as direct_api holding raw frames. Fail-quiet, in the code written to stop
    # things failing quietly.
    from runtime.discovery import classify as _classify
    sent = _classify._detect_sentinel(body)
    if not sent:
        return cfg, vres

    params = sent.get("params") or {}
    upgraded = {k: v for k, v in cfg.items() if k not in ("body", "endpoint", "response_path")}
    upgraded.update({
        "adapter": "sentinel_stream",
        "url": cfg.get("endpoint"),
        "begin_marker": params.get("begin_marker"),
        "end_marker": params.get("end_marker"),
        "message": {"body": cfg.get("body") or {"message": "{{PROMPT}}"}},
    })
    extract = _sentinel_extract_from(body, params.get("begin_marker"), params.get("end_marker"))
    if extract:
        upgraded["extract"] = extract
    # The importer's notes describe the direct_api shape it built. After the upgrade they are not
    # just stale, they CONTRADICT the adapter that is now in the file ("direct_api will fall back
    # to the deepest string…" beside "adapter": "sentinel_stream"), which is worse than no note.
    notes = [n for n in (cfg.get("_notes") or [])
             if "direct_api" not in n and "response_path" not in n]
    notes.append(
        f"discovered as a marker-framed stream: the reply arrives between "
        f"{params.get('begin_marker')} and {params.get('end_marker')}, and the agent's text was "
        f"located at {extract.get('events_path', '?')}[].{extract.get('text_field', 'text')}. "
        f"Re-validated against the live target after the switch."
        if extract else
        f"discovered as a marker-framed stream ({params.get('begin_marker')}/"
        f"{params.get('end_marker')}). The reply path could not be pinned automatically — set "
        f"`extract` by hand if the scorer sees frames instead of text.")
    upgraded["_notes"] = notes

    print(f"[probe] transport sentinel_stream   markers "
          f"{params.get('begin_marker')}/{params.get('end_marker')}", file=sys.stderr)
    print("[validate] re-checking with the streaming adapter ...", file=sys.stderr)
    try:
        v2 = V.validate_config("sentinel_stream", upgraded, args.prompt, None,
                               timeout_s=args.timeout, verify_tls=not args.insecure)
    except Exception:
        v2 = {"ok": False}
    if not v2.get("ok"):
        print("[validate] the streaming shape did not answer — keeping the validated direct_api "
              "config (the reply will contain raw frames; pin `extract` by hand).",
              file=sys.stderr)
        return cfg, vres
    print(f"[validate] VALIDATED — {str(v2.get('response'))[:90]!r}", file=sys.stderr)
    return upgraded, v2


def _sentinel_extract_from(body, begin, end):
    """Where the agent's text sits inside the framed JSON, from a real reply."""
    if not (begin and end):
        return {}
    frames = re.findall(re.escape(begin) + r"(.*?)" + re.escape(end), body, re.S)
    for f in frames:
        try:
            obj = json.loads(f.strip())
        except Exception:
            continue
        if not isinstance(obj, dict):
            continue
        for k, v in obj.items():
            if isinstance(v, dict):
                for k2, v2 in v.items():
                    if isinstance(v2, list) and v2 and isinstance(v2[0], dict) and \
                            ({"text", "message"} & set(v2[0])):
                        return {"events_path": f"{k}.{k2}", "text_field": "text",
                                "message_path": "message" if "message" in v2[0] else ""}
            if isinstance(v, list) and v and isinstance(v[0], dict) and \
                    ({"text", "message"} & set(v[0])):
                return {"events_path": k, "text_field": "text",
                        "message_path": "message" if "message" in v[0] else ""}
    return {}


def cmd_discover(args):
    """Derive an adapter config from evidence (HAR today; --url capture is the next step)."""
    from runtime.discovery import classify as C
    from runtime.discovery.egress import check_egress
    # SSRF guard (allows RFC-1918/localhost; blocks link-local/cloud-metadata unless
    # --allow-internal). Guard the user-supplied target URL up front.
    target_url = getattr(args, "api", None) or getattr(args, "spec", None) or getattr(args, "url", None)
    if target_url:
        blocked = check_egress(target_url, allow_internal=getattr(args, "allow_internal", False))
        if blocked:
            _die(f"refusing to probe {blocked}. Pass --allow-internal to override.",
                 code=EXIT_USAGE)
    if getattr(args, "proxy", None):                 # honored by requests (probe/spec/validate)
        os.environ["HTTP_PROXY"] = os.environ["HTTPS_PROXY"] = args.proxy
    # A login / access-code exchange runs ONCE, up front; its token/cookie is injected as a
    # header so every source (and the hard gate, via _target_auth) authenticates with it.
    if getattr(args, "login_url", None):
        login_headers = _login_for_token(args)
        args.header = (args.header or []) + [f"{k}: {v}" for k, v in login_headers.items()]
    auth_headers, auth_query = _target_auth(args)

    # ---- non-browser sources -------------------------------------------------
    if getattr(args, "api", None):
        from runtime.discovery.probe import probe_api, build_config
        api_url = args.api
        if auth_query:                                   # e.g. Gemini ?key=… goes on the URL
            sep = "&" if "?" in api_url else "?"
            api_url = api_url + sep + "&".join(f"{k}={v}" for k, v in auth_query.items())
        print(f"[build] probing {args.api} ...", file=sys.stderr)
        extra_body = _body_fields(args)
        if extra_body:
            # Carried into EVERY candidate shape, so an agent whose key/tenant lives in the body
            # is reachable from --api directly instead of only via --curl.
            print(f"[build] carrying {len(extra_body)} body field(s): "
                  f"{', '.join(extra_body)}", file=sys.stderr)
        res = probe_api(api_url, prompt=args.prompt,
                        headers=auth_headers, timeout_s=args.timeout,
                        verify_tls=not args.insecure, extra_body=extra_body or None)
        print(f"[probe] tried {len(res.attempts)} candidate(s)", file=sys.stderr)
        if not res.ok:
            _die(f"{res.diagnosis}: {res.message}\n  {res.hint}", code=EXIT_ERROR)
        print(f"[probe] endpoint  {res.method} {res.endpoint}", file=sys.stderr)
        print(f"[probe] transport {res.transport}   response_path {res.response_path}", file=sys.stderr)
        print(f"[probe] answer    {str(res.response_text)[:90]!r}", file=sys.stderr)
        cfg = build_config(res)
        return _finish_discovery(cfg, args, source="api", response_sample=res.response_text)

    if getattr(args, "curl", None):
        from runtime.discovery.importers import from_curl, CurlParseError
        text = sys.stdin.read() if args.curl == "-" else Path(args.curl).read_text()
        try:
            cfg = from_curl(text, prompt_hint=args.prompt_hint)
        except CurlParseError as e:
            _die(f"could not read that curl command: {e}")
        print(f"[curl] {cfg.get('method')} {cfg.get('endpoint')}  "
              f"prompt field: {cfg.get('_prompt_field')}", file=sys.stderr)
        return _finish_discovery(cfg, args, source="curl")

    if getattr(args, "spec", None):
        from runtime.discovery.importers import (discover_spec, endpoints_from_spec,
                                                 config_from_spec_endpoint)
        print(f"[build] looking for an API spec under {args.spec} ...", file=sys.stderr)
        res = discover_spec(args.spec, headers=auth_headers,
                            timeout_s=args.timeout, verify_tls=not args.insecure)
        if not res.get("ok"):
            _die(f"no usable API spec: {res.get('error')}\n  {res.get('hint','')}",
                 code=EXIT_ERROR)
        eps = res.get("endpoints") or endpoints_from_spec(res["spec"])
        if not eps:
            _die(f"spec found at {res.get('spec_url')} but no chat-like endpoint in it.\n"
                 f"  pass the exact endpoint with --api <url>", code=EXIT_ERROR)
        print(f"[spec] {res.get('spec_url')} -> {len(eps)} candidate endpoint(s); "
              f"using {eps[0].get('method','POST')} {eps[0].get('path')}", file=sys.stderr)
        cfg = config_from_spec_endpoint(args.spec, eps[0])
        return _finish_discovery(cfg, args, source="spec")

    if args.url:
        from runtime.discovery.capture import capture_url
        print(f"[build] launching browser against {args.url} ...", file=sys.stderr)
        evidence = capture_url(args.url, prompt=args.prompt,
                               headless=args.headless, settle_s=args.settle,
                               manual=args.manual, extra_headers=auth_headers or None,
                               proxy=getattr(args, "proxy", None),
                               insecure=getattr(args, "insecure", False))
        for n in evidence.get("notes", []):
            print(f"[build] {n}", file=sys.stderr)

        # --- capture verdict -------------------------------------------------
        verified = evidence.get("send_verified")
        print("", file=sys.stderr)
        print(f"[capture] prompt sent .... {'YES' if evidence.get('send_attempted') else 'NO'}",
              file=sys.stderr)
        print(f"[capture] seen in traffic  {'YES' if verified else 'NO'}", file=sys.stderr)
        if evidence.get("reply_text"):
            first = evidence["reply_text"].splitlines()[0][:100]
            print(f"[capture] bot replied .... {first!r}", file=sys.stderr)
        print(f"[capture] requests ....... {len(evidence.get('pairs', []))}"
              f"  websockets: {len(evidence.get('ws_messages', []))}", file=sys.stderr)
        print("", file=sys.stderr)

        if evidence.get("diagnosis") and evidence["diagnosis"] not in ("ok",):
            _die(f"{evidence['diagnosis']}: {evidence.get('message','')}\n"
                 f"  {evidence.get('hint','')}", code=EXIT_ERROR)
        if not verified:
            # HARD STOP: without the prompt in real traffic we cannot identify the chat
            # call, and any config we emit would be a guess dressed up as a discovery.
            if args.save_evidence:
                Path(args.save_evidence).parent.mkdir(parents=True, exist_ok=True)
                _write_private(args.save_evidence, json.dumps(evidence, indent=2))
                print(f"[build] raw evidence -> {args.save_evidence}", file=sys.stderr)
            _die("capture did not deliver the prompt to the target, so no contract can be "
                 "derived.\n"
                 "  Try:  --settle 15            (slow widget / SPA)\n"
                 "        --no-headless          (bot protection blocks headless)\n"
                 "        --manual               (you drive the widget; we record)\n"
                 "        --har <file.har>       (export the HAR from your own browser)\n"
                 "  Nothing was written: an unverified capture cannot produce a real config.",
                 code=EXIT_ERROR)
        if args.save_evidence:
            Path(args.save_evidence).parent.mkdir(parents=True, exist_ok=True)
            _write_private(args.save_evidence, json.dumps(evidence, indent=2))
            print(f"[build] raw evidence -> {args.save_evidence}", file=sys.stderr)
        source = "url"
    elif args.har:
        evidence = C.load_har(args.har, prompt_sent=args.prompt)  # normalized evidence
        source = "har"
    elif args.evidence:
        with open(args.evidence) as fh:
            evidence = json.load(fh)
        source = "evidence"
    else:
        _die("provide --url <page>, --api <url>, --curl <file>, --spec <base>, --har <file>, "
             "or an evidence JSON path")
    result = C.classify_evidence(evidence)
    cfg = result.get("config") or {}
    layers = result.get("layers", {})
    # Plain-language summary FIRST — the technical layer table is for the curious.
    for line in _describe_shape(result):
        print(f"[found] {line}", file=sys.stderr)
    # Built as a plain join (not a nested f-string): reusing the same quote inside an f-string
    # expression is a SyntaxError before Python 3.12, and this project supports 3.9+.
    layer_summary = ", ".join(
        "{}={}".format(k, (v or {}).get("value"))
        for k, v in layers.items() if isinstance(v, dict))
    print(f"[build] confidence {result.get('overall_confidence')} · {layer_summary}",
          file=sys.stderr)
    if result.get("unresolved"):
        print(f"[build] needs a look (low confidence): {', '.join(result['unresolved'])} — "
              f"the live check next will confirm or reject it", file=sys.stderr)
    # the chat pair's response, so the answer-path picker has the real body to show
    sample = None
    try:
        ci = result.get("chat_pair_index")
        if ci is not None:
            sample = evidence["pairs"][ci]["response"].get("raw_body")
    except Exception:
        pass
    # Same hard gate as --api/--curl/--spec: validate against the live target before writing.
    return _finish_discovery(cfg, args, source=source, response_sample=sample,
                             browser_recipe=(evidence or {}).get('browser_recipe'))


def _describe_shape(result):
    """Translate the detected layers into plain sentences an operator can act on."""
    L = result.get("layers") or {}
    out = []
    tr = (L.get("transport") or {}).get("value")
    TR = {"rest_json":"a plain JSON API", "sse":"streams its reply (server-sent events)",
          "ndjson":"streams its reply (newline-delimited JSON)",
          "sentinel_stream":"streams its reply between marker frames",
          "websocket":"talks over a WebSocket"}
    if tr:
        out.append(f"The target is {TR.get(tr, tr)}.")
    sess = (L.get("session") or {}).get("value")
    if sess in ("create_conversation", "create_session"):
        out.append("Multi-turn: it creates a conversation first, then sends messages — the "
                   "session_api adapter handles that end to end.")
    elif sess == "warmup":
        out.append("It expects a warm-up/greeting turn before the real prompt — captured and replayed.")
    elif sess == "multi_turn":
        out.append("It keeps conversation state server-side across turns.")
    auth = (L.get("auth") or {}).get("value")
    if auth and auth not in ("none", "static"):
        out.append(f"It needs auth ({auth}) — captured and baked into the adapter.")
    elif auth == "static":
        out.append("It carries a static credential — baked into the adapter (secrets masked on disk).")
    if not out:
        out.append("Working out the request/response shape...")
    return out


def cmd_adapter_validate(args):
    """HARD GATE: run one prompt through the config against the live target."""
    from runtime.discovery import validate as V
    _say(args, f"Validating {args.config or args.file} against the live target...")
    if args.file and args.config:
        _die("pass either --file or --config, not both")
    if args.file:
        fp = Path(os.path.expanduser(args.file))
        if not fp.is_file():
            _die(f"file not found: {args.file}")
        try:
            cfg = json.loads(fp.read_text())
        except json.JSONDecodeError as e:
            _die(f"{args.file} is not valid JSON: {e}")
    else:
        cfg = _load_named_config(args.config)
    atype = args.adapter or cfg.get("adapter")
    if not atype:
        _die("no adapter type: pass --adapter or set 'adapter' in the config")
    res = V.validate_config(atype, cfg, args.prompt, args.expect, timeout_s=args.timeout)
    if args.json:
        _out(res, args)
    else:
        print(f"  ok={res.get('ok')} matched={res.get('matched')}")
        if res.get("error"):
            print(f"  error: {res['error']}")
        if res.get("response"):
            print(f"  response: {str(res['response'])[:200]}")
    # Distinguish a tool/target ERROR (unreachable, auth, bad adapter) from a
    # content MISMATCH (target answered, but --expect missed) so CI can branch.
    if res.get("error"):
        sys.exit(EXIT_ERROR)
    if args.expect and not res.get("matched"):
        sys.exit(EXIT_FINDINGS)
    sys.exit(EXIT_OK)


def _load_named_config(name):
    if not name:
        _die("no config given: pass --config <name> (see `ascend adapter configs`) "
             "or --file <path.json>")
    p = resolve_config_path(name)
    if p is None:
        # candidate_paths() is the ONE resolver; it strips a trailing .json so a name
        # already ending in .json is never doubled into ".json.json".
        tried = "\n  ".join(str(x) for x in candidate_paths(str(name)))
        import difflib
        have = []
        try:
            have = [f.stem for f in sorted(config_dir().glob("*.json"))]
        except Exception:
            pass
        close = difflib.get_close_matches(str(name).replace(".json", ""), have, n=3, cutoff=0.5)
        suffix = ("\n  did you mean:  " + ", ".join(close)) if close else (
            f"\n  configs on disk: {', '.join(have[:8])}" if have else "")
        _die(f"config not found: {name}\n  looked in:\n  {tried}{suffix}\n"
             f"  list what exists with:  ascend adapter configs")
    try:
        return json.loads(p.read_text())
    except json.JSONDecodeError as e:
        _die(f"{p} is not valid JSON: {e}")







def cmd_export(args):
    from reporting import export as E
    if args.file:
        a = json.loads(Path(args.file).read_text())
    else:
        c = _client(args)
        a = c.get_assessment(_resolve_app(c, args.app), args.assessment)
    fmt = args.format
    out = {"json": E.to_json, "csv": E.to_csv, "sarif": E.to_sarif,
           "markdown": E.to_markdown}[fmt](a)
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)   # CI writes reports/x.sarif
        Path(args.out).write_text(out); print(f"wrote {args.out}")
    else:
        print(out)


def cmd_ci(args):
    from reporting import ci as CI
    if args.file:
        cur = json.loads(Path(args.file).read_text())
    else:
        c = _client(args)
        cur = c.get_assessment(_resolve_app(c, args.app), args.assessment)
    base = json.loads(Path(args.baseline).read_text()) if args.baseline else None

    # A local policy supplies the gate defaults (per-control severity is not settable on the app
    # via the v3 API), but an explicit flag on the command line always wins.
    import policy as P
    pol = P.load(getattr(args, "policy", None))
    app_name = None
    if pol and not args.file:
        try:
            app_name = (c.get_app(_resolve_app(c, args.app)) or {}).get("name")
        except Exception:
            app_name = args.app
    th = P.thresholds(pol, app_name) if pol else {}
    explicit = {a.split("=")[0] for a in sys.argv if a.startswith("--fail-on-severity")}
    fail_on_sev = args.fail_on_severity if (explicit or not th) else th["fail_on_severity"]
    fail_on_new = (not args.allow_new) if (args.allow_new or not th) else bool(th["fail_on_new"])
    if pol:
        cur = dict(cur)
        cur["_policy_applied"] = True
        print(f"  policy: {P.policy_path(getattr(args, 'policy', None))} "
              f"(fail_on_severity={fail_on_sev}, fail_on_new={fail_on_new})", file=sys.stderr)

    res = CI.gate(cur, base, fail_on_severity=fail_on_sev, fail_on_new=fail_on_new,
                  policy=pol, app_name=app_name,
                  # None means "not passed" -> use the library default; 0 explicitly disables.
                  min_probes=(CI.MIN_CREDIBLE_PROBES if args.min_probes is None
                              else args.min_probes))
    if args.junit:
        Path(args.junit).parent.mkdir(parents=True, exist_ok=True)
        Path(args.junit).write_text(CI.to_junit(cur))
        print(f"wrote {args.junit}", file=sys.stderr)
    if args.json:
        _out(res, args)
    else:
        for r in res.get("reasons", []):
            print(f"  {r}")
        print(f"exit_code={res.get('exit_code')}")
    # gate() now returns the PROCESS exit code directly, so the number an agent reads in --json
    # is the number the process exits with. They used to be inverses of each other.
    sys.exit(int(res.get("exit_code", EXIT_ERROR)))


# ----------------------------------------------------------------------------- parser
def _global_flags() -> argparse.ArgumentParser:
    """Global flags, as a parent parser.

    Attached to the root AND to every leaf subparser so they work in ANY position:
    both `ascend --json app list` and `ascend app list --json` are valid. argparse
    does not inherit root-level flags into subparsers on its own, which previously
    made the natural form (`ascend app list --json`) a hard error.
    """
    # SUPPRESS is load-bearing: the same parent is attached to the root AND to every
    # subparser, so a normal default would let the subparser's unset value clobber a
    # flag the user gave before the group (`ascend --json app list`). With SUPPRESS the
    # attribute is only set when actually provided; real defaults are applied once, on
    # the root, via set_defaults() below.
    g = argparse.ArgumentParser(add_help=False)
    g.add_argument("--json", action="store_true", default=argparse.SUPPRESS,
                   help="machine-readable JSON output")
    g.add_argument("--token", default=argparse.SUPPRESS,
                   help="Straiker PAT (s6r_pat_...) or JWT; else $STRAIKER_PAT")
    g.add_argument("--base", default=argparse.SUPPRESS, help="v3 API base URL")
    g.add_argument("--bridge-base", default=argparse.SUPPRESS,
                   help="Ascend lease-service base URL (where bridges fetch probes and post results)")
    return g


GLOBALS = _global_flags()


class _Fmt(argparse.ArgumentDefaultsHelpFormatter, argparse.RawDescriptionHelpFormatter):
    """Show defaults AND stop argparse re-wrapping copy-pasteable examples."""


# The command menu, ordered by the lifecycle rather than alphabetically. argparse's own listing is
# a flat brace dump of 20 groups, which tells a newcomer nothing about where to start; this is the
# same set of commands arranged in the order they are actually used.
LIFECYCLE_HELP = """\
the flow, in order (every command takes --json):

  1 - IDENTIFY THE TARGET
    doctor                     preflight: your key, API + bridge reachability, deps
    controls list              the checks Ascend can run; --categories for risk tags
    controls validate          check control ids before a run (non-zero exit on a bad id)

  2 - BUILD THE ADAPTER  (from the target)
    adapter build              point at the target -> a VALIDATED adapter config. pick a source:
                                 --har <file>   a browser HAR you exported   (most reliable)
                                 --curl <file>  one request copied as cURL
                                 --url  <page>  a live page (drives a real browser)
                                 --api  <url>   an HTTP API endpoint
    adapter validate           re-prove a saved config against the live target (the hard gate)
    adapter show | list        inspect a config (secrets masked) | the adapter types
    chat                       talk to the target through the adapter; every turn recorded

  3 - CREATE THE APP + KEY  (in Ascend)
    app create --config <adapter>   register the target and BIND the adapter to it;
                                    mints the app's bridge key (tc-, shown once)
    app list | get | delete    what exists | delete drops the app and its key
    keys list                  the bridge keys — exactly one per app

  4 - RUN THE BRIDGE  (with the app's key + the app's adapter)
    bridge start --app <app>   starts a bridge for THAT app, using ITS key and ITS bound
                               adapter config. --config overrides the adapter; --foreground to watch
    bridge ls                  which bridge serves which app, with which adapter config
    bridge logs | stop

  5 - RUN THE ASSESSMENT
    assess run --app <app>     start the red-team assessment
    assess watch --all         follow live runs (the BRIDGE column flags an unanswered run)
    assess pause | resume | list

  6 - READ RESULTS
    results                    your assessments as a table, or an export / transcript in depth
                               (--by category,evasion,control  --values --turns --matrix)
    export                     SARIF / markdown / CSV / JSON out of a finished run
    ci                         gate a pipeline on findings (0 clean · 2 findings · 1 unreadable)

  ONE-SHOT & OPS
    onboard                    steps 2-5 in a single command
    policy show | set | push   severity overrides + CI gate; push sends categories upstream
    tenant show | switch       which tenant this CLI is pinned to — one at a time, by design
    status                     tenant + apps + live runs + bridges, in one call
    version

`ascend <command> --help` has the flags and examples for each step.
Full reference: docs/COMMAND_MAP.md  ·  building adapters: docs/BUILD_ADAPTER.md
"""


def _add_build_args(s):
    """Every flag for building an adapter (shared by `adapter build` and the `map` alias)."""
    s.add_argument("evidence", nargs="?", help="evidence JSON path")
    s.add_argument("--url", help="live page with a chat widget: drive a real browser and capture the true contract")
    s.add_argument("--api", metavar="URL",
                   help="an HTTP API endpoint (or just the base URL — the path is discovered). No browser.")
    s.add_argument("--curl", metavar="FILE",
                   help="a curl command in a file, or '-' for stdin. Zero guessing.")
    s.add_argument("--spec", metavar="BASE_URL",
                   help="find an OpenAPI/Swagger spec under this base URL and build from it")
    s.add_argument("--har", help="HAR file to classify")
    # --- target auth (honored by every source; baked into the written config) ---
    s.add_argument("--header", action="append", metavar="'Name: value'",
                   help="raw header (repeatable), honored by all sources, e.g. 'X-Api-Key: …'")
    s.add_argument("--bearer", metavar="TOKEN", help="Authorization: Bearer <token>")
    s.add_argument("--api-key", metavar="NAME:VALUE[:in=header|query]",
                   help="API key, e.g. 'x-api-key:abc' or 'key:abc:in=query'")
    s.add_argument("--basic", metavar="USER:PASS", help="HTTP Basic auth")
    s.add_argument("--cookie", metavar="'k=v; k2=v2'", help="Cookie header for a session-gated target")
    s.add_argument("--token-file", metavar="PATH", help="read a bearer token from this file")
    s.add_argument("--body-field", action="append", metavar="key=value",
                   help="extra JSON body field, repeatable — for agents whose key/tenant lives in "
                        "the BODY, e.g. --body-field apiKey=abc --body-field workspace=support. "
                        "Use key:=raw for a non-string literal (true/1/{...}).")
    # --- login / access-code flow: POST creds, extract a token, then use it ---
    s.add_argument("--login-url", metavar="URL", help="POST here first to exchange creds/code for a token")
    s.add_argument("--login-body", metavar="JSON", help="JSON body for --login-url, e.g. '{\"code\":\"1234\"}'")
    s.add_argument("--token-path", metavar="DOTPATH", default="token",
                   help="dot-path to the token in the login response (default: token)")
    s.add_argument("--prompt-hint", help="with --curl: the literal prompt text used in that command")
    s.add_argument("--insecure", action="store_true", help="skip TLS verification (self-signed internal targets)")
    s.add_argument("--ca-bundle", metavar="PATH", help="custom CA bundle for TLS verification")
    s.add_argument("--client-cert", metavar="PATH", help="client certificate (PEM) for mTLS")
    s.add_argument("--client-key", metavar="PATH", help="client private key (PEM) for mTLS")
    s.add_argument("--proxy", metavar="URL", help="HTTP(S) proxy for the probe/validate calls")
    s.add_argument("--allow-internal", action="store_true",
                   help="allow link-local/cloud-metadata hosts (169.254/fd00::) — off by default")
    s.add_argument("--timeout", type=float, default=20.0, help="per-request timeout in seconds")
    s.add_argument("--prompt", default="Hello, what can you help me with?",
                   help="benign prompt to send during capture")
    s.add_argument("--headless", action="store_true",
                   help="run the capture browser headless (faster, but bot protection often blocks it)")
    s.add_argument("--no-headless", dest="headless", action="store_false",
                   help="force a visible browser (default; most reliable against bot protection)")
    s.add_argument("--manual", action="store_true",
                   help="open the page and let YOU drive the widget while we record "
                        "(for widgets our automation cannot reach)")
    s.add_argument("--settle", type=int, default=6, help="seconds to wait for page/widget/reply")
    s.add_argument("--response-path", metavar="DOTPATH",
                   help="where the answer is in the response, e.g. data.reply — set it explicitly "
                        "when the CLI cannot find it, or to override its guess (scriptable)")
    s.add_argument("--save-evidence", help="also write the raw captured evidence here")
    # Advanced. You do NOT need these for the normal flow: `adapter build` auto-detects the built-in
    # adapter and auto-falls-back to a browser adapter for anti-automation targets. `--code` just
    # ALSO emits the working adapter as an editable Python module (for hand-editing, or as the base
    # for --agent). A target that fits no built-in fails with the real next step (--har / --agent),
    # never silently.
    s.add_argument("--code", action="store_true",
                   help="advanced: also write the adapter as an editable Python module (the CLI "
                        "picks the adapter kind automatically; you don't need this normally)")
    s.add_argument("--agent", action="store_true",
                   help=argparse.SUPPRESS)   # not built yet; --code writes a scaffold to finish
    s.add_argument("--out", help="write the drafted config here")


def build_parser():
    p = argparse.ArgumentParser(
        prog="ascend", description=__doc__, parents=[GLOBALS],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        # Explicit usage: the subparser listing is suppressed (see below), which would otherwise
        # also drop `<command>` from the usage line.
        usage="ascend [--json] [--token TOKEN] [--base URL] <command> [<verb>] [flags]",
        epilog=LIFECYCLE_HELP)
    p.add_argument("--version", action="store_true", help="print version and exit")
    p.set_defaults(
        json=False, token=None,
        base=os.environ.get("STRAIKER_API_BASE", "https://api.prod.straiker.ai/api/v3"),
        bridge_base=os.environ.get("STRAIKER_BRIDGE_URL",
                                   "https://ascendai-bridge.prod.straiker.ai"),
    )
    # metavar + SUPPRESS: argparse would otherwise print a second, alphabetical listing
    # of all 20 groups. LIFECYCLE_HELP is the single maintained menu.
    sub = p.add_subparsers(dest="group", required=True, metavar="<command>",
                           help=argparse.SUPPRESS)

    # app
    ap = sub.add_parser("app", parents=[GLOBALS], formatter_class=_Fmt, help="manage Ascend applications").add_subparsers(dest="verb", required=True)
    s = ap.add_parser("list", parents=[GLOBALS], formatter_class=_Fmt,
                      help="list applications (add --with-runs for the assessment table)",
                      epilog="examples:\n"
                             "  ascend app list                    # just the apps (fast)\n"
                             "  ascend app list --with-runs        # + assessment status table\n"
                             "  ascend app list --running          # only apps with a LIVE assessment\n"
                             "  ascend app list --all-runs         # every assessment per app")
    s.add_argument("--with-runs", action="store_true",
                   help="show the assessment table: state, run count, latest run, progress/score/severity")
    s.add_argument("--running", action="store_true",
                   help="only apps that have a live (running/created/paused) assessment")
    s.add_argument("--all-runs", action="store_true",
                   help="list every assessment per app, not just the latest")
    s.set_defaults(func=cmd_app_list)
    s = ap.add_parser("get", parents=[GLOBALS], formatter_class=_Fmt, help="get an application (by id or name)"); s.add_argument("app", help="app name or aapp_ id"); s.set_defaults(func=cmd_app_get)
    # A debug helper: `app get` already accepts a name. Hidden, still wired.
    s = ap.add_parser("resolve", parents=[GLOBALS], formatter_class=_Fmt, help=argparse.SUPPRESS)
    s.add_argument("name", help="application name to resolve to an id")
    s.set_defaults(func=cmd_app_resolve)
    s = ap.add_parser("create", parents=[GLOBALS], formatter_class=_Fmt,
                      help="create an application (any of the four platform types)",
                      description=(
                          "Create an Ascend application. The platform supports four target "
                          "types; one of them is served by the CLI's built-in bridge:\n"
                          "  bridge   Ascend hands prompts to the CLI's bridge; `assess run` auto-manages it (key shown ONCE)\n"
                          "  api      Ascend calls your HTTP target directly    (no bridge)\n"
                          "  gcp      Vertex AI / Agent Engine target           (no bridge)\n"
                          "  bedrock  AWS Bedrock target                        (no bridge)\n"
                          "Required fields differ per type and are checked locally before the "
                          "request, so a missing one is named rather than returned as a 422."),
                      epilog=("examples:\n"
                              "  ascend app create --name 'My Bot' --controls sys_prompt_leak\n"
                              "      a bridge app (the default) — `ascend assess run` starts the relay for you\n\n"
                              "  ascend app create --type api --name 'Public Bot' --config mybot \\\n"
                              "      --target-api-key $KEY\n"
                              "      Ascend calls the target itself; url/templates/headers come from the config\n\n"
                              "  ascend app create --type gcp --name 'Vertex Agent' \\\n"
                              "      --url https://…/agents/x:streamQuery --service-account @sa.json\n\n"
                              "  ascend app create --type bedrock --name 'Bedrock Agent' \\\n"
                              "      --url arn:aws:bedrock:… --bedrock-auth assume-role \\\n"
                              "      --role-arn arn:aws:iam::…:role/x --region us-east-1\n\n"
                              "  ascend app create --name 'My Bot' --category-severity data_leak=high \\\n"
                              "      --input-guardrail http_status_code=403"))
    s.add_argument("--type", default="bridge", choices=["bridge", "api", "gcp", "bedrock"],
                   help="target type (default: bridge — the type served by the CLI's built-in bridge)")
    s.add_argument("--url", help="target endpoint (api/gcp/bedrock)")
    s.add_argument("--target-api-key", metavar="KEY",
                   help="API key Ascend should present to the target (--type api)")
    s.add_argument("--service-account", metavar="JSON|@FILE",
                   help="GCP service-account JSON, or @path to it (--type gcp)")
    s.add_argument("--bedrock-auth", choices=["assume-role", "access-key"],
                   help="Bedrock authentication method (--type bedrock)")
    s.add_argument("--region", help="AWS region (--type bedrock)")
    s.add_argument("--role-arn", help="role to assume (--type bedrock, assume-role)")
    s.add_argument("--external-id", help="external id for the assume-role trust policy")
    s.add_argument("--role-session-name", help="session name for the assumed role")
    s.add_argument("--access-key-id", help="AWS access key id (--type bedrock, access-key)")
    s.add_argument("--secret-access-key", help="AWS secret access key")
    s.add_argument("--session-token", help="AWS session token")
    s.add_argument("--name", required=True, help="application name shown in Ascend")
    s.add_argument("--system-prompt", default=None,
                   help="what the target is — the scorer compares responses against this to "
                        "detect a system-prompt leak (default: the app name)")
    s.add_argument("--purpose", default=None, help="business purpose, for assessment context")
    s.add_argument("--controls", help="comma-separated control ids (validated before the create)")
    s.add_argument("--size", default="small", choices=["small", "medium", "large"],
                   help="assessment size — how many probes a run generates")
    s.add_argument("--qpm", type=int, default=30, metavar="N",
                   help="max queries per minute against the target")
    s.add_argument("--config", help="adapter config to bind (and, for --type api, to take the "
                                    "url/templates/headers from)")
    s.add_argument("--category-severity", action="append", metavar="CAT=SEV",
                   help="per-category severity, repeatable: data_leak=high. Platform enum is "
                        "default|low|medium|high ('critical' is clamped to 'high')")
    s.add_argument("--input-guardrail", metavar="TYPE=VALUE",
                   help="how the target signals a guardrail block, so a block is not scored as an "
                        "answer: http_status_code=403 or response_pattern='I can|t help' "
                        "(pipe-separate several values)")
    s.add_argument("--strategy", metavar="A,B",
                   help="comma-separated attack strategies (e.g. single_turn,multi_turn); "
                        "implies --strategy-type custom")
    s.add_argument("--strategy-type", choices=["recommended", "custom"],
                   help="attack strategy selection (default: recommended)")
    s.add_argument("--if-not-exists", action="store_true",
                   help="reuse an app with this name instead of creating a duplicate (safe retry)")
    s.add_argument("--force", action="store_true",
                   help="create the app even if its controls generate zero probes (an app pinned "
                        "to an unknown control scores clean without ever being tested)")
    s.set_defaults(func=cmd_app_create)

    # app update — change a live app in place (PATCH; the bridge key survives)
    s = ap.add_parser("update", parents=[GLOBALS], formatter_class=_Fmt,
                      help="change a live app's settings in place (no delete/recreate)",
                      epilog="example: ascend app update 'My Bot' --qpm 60 --controls sys_prompt_leak,pii_leak")
    s.add_argument("app", help="app name or aapp_ id")
    s.add_argument("--name", help="rename the app")
    s.add_argument("--system-prompt", help="update the system prompt used for leak scoring")
    s.add_argument("--purpose", help="update the business purpose")
    s.add_argument("--qpm", type=int, default=None, help="queries per minute")
    s.add_argument("--controls", help="replace the control set (comma-separated, validated)")
    s.add_argument("--category-severity", action="append", metavar="CAT=SEV",
                   help="set a category severity (repeatable); pushed to the app")
    s.add_argument("--input-guardrail", metavar="TYPE=VALUE", help="how a block is signalled")
    s.add_argument("--frequency", choices=["none", "weekly", "monthly", "quarterly"],
                   help="recurring assessment cadence")
    s.add_argument("--strategy", metavar="A,B", help="comma-separated attack strategies")
    s.add_argument("--strategy-type", choices=["recommended", "custom"])
    s.set_defaults(func=cmd_app_update)

    s = ap.add_parser("bind", parents=[GLOBALS], formatter_class=_Fmt,
                      help="record which Ascend app a config was registered as",
                      epilog="example: ascend app bind mybot --app 'My Bot'")
    s.add_argument("config", help="config name (see `ascend adapter configs`)")
    s.add_argument("--app", required=True, help="app name or aapp_ id")
    s.set_defaults(func=cmd_app_bind)
    s = ap.add_parser("delete", parents=[GLOBALS], formatter_class=_Fmt,
                      help="delete an application (also stops its bridge + drops its stored key)")
    s.add_argument("app", help="app name or aapp_ id")
    s.add_argument("--keep-key", action="store_true",
                   help="keep the stored bridge key (default: remove it — a key without its app is dead)")
    s.set_defaults(func=cmd_app_delete)

    # controls
    cp = sub.add_parser("controls", parents=[GLOBALS], formatter_class=_Fmt, help="control catalog").add_subparsers(dest="verb", required=True)
    s = cp.add_parser("list", parents=[GLOBALS], formatter_class=_Fmt,
                      help="list controls, or the categories they group into",
                      description=(
                          "The platform's control catalog. Deprecated controls are hidden by "
                          "default because they generate zero probes — selecting one produces a "
                          "run that scores nothing.\n\n"
                          "`--categories` switches to the grouping view: the platform's own "
                          "categories with their risk tag (Security / Safety / Trust), display "
                          "name, and how many active controls each still has."),
                      epilog=("examples:\n"
                              "  ascend controls list\n"
                              "  ascend controls list --categories        # the platform's grouping + tags\n"
                              "  ascend controls list --tag Security\n"
                              "  ascend controls list --category data_leak\n"
                              "  ascend controls list --agentic-only      # tool-use probes\n"
                              "  ascend controls list --include-deprecated"))
    s.add_argument("--categories", action="store_true",
                   help="list the categories (with risk tag and active-control counts) instead")
    s.add_argument("--category", metavar="ID", help="filter to one category id")
    s.add_argument("--tag", metavar="TAG", help="filter by the platform's risk tag (Security/Safety/Trust)")
    s.add_argument("--include-deprecated", action="store_true",
                   help="include deprecated controls (they generate zero probes)")
    s.add_argument("--agentic-only", action="store_true", help="only agentic controls")
    s.set_defaults(func=cmd_controls_list)
    s = cp.add_parser("validate", parents=[GLOBALS], formatter_class=_Fmt,
                      help="validate a control selection before a run (exits non-zero on a bad id)",
                      description=(
                          "Check control ids against the live catalog.\n\n"
                          "Exit codes are the point: an unknown id exits 3, because a control that "
                          "does not exist generates zero probes and the run would come back clean "
                          "having tested nothing. A deprecated id warns and exits 0; use --strict "
                          "to fail on those too."),
                      epilog=("examples:\n"
                              "  ascend controls validate sys_prompt_leak,jailbreak\n"
                              "  ascend controls validate $(cat controls.txt) --strict\n"
                              "  ascend controls validate a,b --json"))
    s.add_argument("controls", help="comma-separated control ids to validate")
    s.add_argument("--strict", action="store_true",
                   help="also fail on deprecated ids (they generate zero probes)")
    s.set_defaults(func=cmd_controls_validate)

    # assess
    asp = sub.add_parser("assess", parents=[GLOBALS], formatter_class=_Fmt, help="run and monitor assessments").add_subparsers(dest="verb", required=True)
    s = asp.add_parser("run", parents=[GLOBALS], formatter_class=_Fmt, help="create->pause->resume->poll an assessment",
                       epilog="examples:\n"
                              "  ascend assess run --app 'My Bot' --name 'run 1'\n"
                              "  ascend assess run --app A --app B --app C --name 'wave 1'   # fleet\n"
                              "  ascend assess run --all-bound --name 'wave 1'")
    s.add_argument("--app", action="append", help="app name or aapp_ id (repeatable for a fleet)")
    s.add_argument("--all-bound", action="store_true",
                   help="every app with a stored bridge key (see `ascend keys list`)")
    s.add_argument("--name", required=True, help="a label for this assessment run")
    s.add_argument("--controls", help="validate these ids first (validated ONCE for the whole fleet)")
    s.add_argument("--no-wait", action="store_true", help="return as soon as the run starts"); s.add_argument("--interval", type=int, default=20, help="seconds between status polls")
    s.add_argument("--timeout", type=int, default=7200, help="max seconds to wait for completion")
    s.add_argument("--force", action="store_true", help="run even if the selected controls would generate zero probes")
    s.set_defaults(func=cmd_assess_run)

    # assess diff — compare two runs (new / resolved / regressed findings)
    s = asp.add_parser("diff", parents=[GLOBALS], formatter_class=_Fmt,
                       help="compare two assessments: new / resolved / regressed findings",
                       epilog="example: ascend assess diff --app 'My Bot' --base asmt_old --against asmt_new")
    s.add_argument("--app", help="app name or aapp_ id (for --base/--against ids)")
    s.add_argument("--baseline", help="baseline assessment id")
    s.add_argument("--current", help="the newer assessment id to compare")
    s.add_argument("--baseline-file", help="baseline assessment json on disk (instead of --baseline)")
    s.add_argument("--current-file", help="current assessment json on disk (instead of --current)")
    s.set_defaults(func=cmd_assess_diff)
    s = asp.add_parser("results", parents=[GLOBALS], formatter_class=_Fmt, help="assessment findings summary")
    s.add_argument("--app", required=True, help="app name or aapp_ id")
    s.add_argument("--assessment", required=True, help="assessment id (asmt_...)")
    s.add_argument("--detail", action="store_true", help="show key findings per control")
    s.set_defaults(func=cmd_assess_results)
    s = asp.add_parser("watch", parents=[GLOBALS], formatter_class=_Fmt,
                       help="live view of a running assessment until it finishes",
                       epilog=("examples:\n"
                               "  ascend assess watch --app 'My Bot'            # auto-picks the running one\n"
                               "  ascend assess watch --all                     # every live run, one table\n"
                               "  ascend assess watch --app 'My Bot' --assessment asmt_x --detail"))
    s.add_argument("--app", action="append", help="app name or aapp_ id (repeatable)")
    s.add_argument("--all", action="store_true",
                   help="watch every live assessment in the tenant, with bridge status per run")
    s.add_argument("--include-done", action="store_true", help="with --all: also show finished runs")
    s.add_argument("--assessment", help="assessment id (default: the one currently running)")
    s.add_argument("--interval", type=int, default=10, help="seconds between polls")
    s.add_argument("--detail", action="store_true", help="show key findings when it completes")
    s.add_argument("--once", action="store_true",
                   help="print one snapshot and exit instead of following (replaces `assess status`)")
    s.set_defaults(func=cmd_assess_watch)

    # `status` is a one-shot `watch`; kept working, hidden from the menu.
    for verb, fn, h in [("status", cmd_assess_status, argparse.SUPPRESS),
                        ("pause", cmd_assess_pause,
                         "pause a running assessment (in-flight probes drain, see docs)"),
                        ("resume", cmd_assess_resume, "resume a paused assessment")]:
        s = asp.add_parser(verb, parents=[GLOBALS], formatter_class=_Fmt, help=h)
        s.add_argument("--app", required=True, help="app name or aapp_ id")
        s.add_argument("--assessment", required=True, help="assessment id (asmt_...)"); s.set_defaults(func=fn)
    s = asp.add_parser("list", parents=[GLOBALS], formatter_class=_Fmt,
                       help="list assessments for an app (running assessments marked *)")
    s.add_argument("--app", required=True, help="app name or aapp_ id")
    s.add_argument("--running", action="store_true", help="only assessments still running")
    s.set_defaults(func=cmd_assess_list)

    # runtime
    # `runtime start` predates the fleet and is now `bridge start --foreground`. Hidden from the
    # menu, still wired, because scripts and the packaged binary call it.
    rp = sub.add_parser("runtime", parents=[GLOBALS], formatter_class=_Fmt,
                        help=argparse.SUPPRESS).add_subparsers(dest="verb", required=True)
    s = rp.add_parser("start", parents=[GLOBALS], formatter_class=_Fmt, help="lease probes and relay them to a target via an adapter (see `bridge start --foreground`)",
                      epilog="example: STRAIKER_BRIDGE_API_KEY=tc-... ascend runtime start --adapter direct_api --config mybot")
    s.add_argument("--adapter", help="adapter type (default: from the config)")
    s.add_argument("--config", required=True, help="config name in the config dir")
    s.add_argument("--api-key", help="bridge key (tc-); else $STRAIKER_BRIDGE_API_KEY")
    s.add_argument("--app", help="resolve the bridge key from the local key store for this app")
    s.add_argument("--consumer", help="bridge consumer id (parallel bridges MUST differ; auto per app)")
    s.add_argument("--log-file", help="write bridge logs here instead of stderr")
    s.add_argument("--status-file", help="publish heartbeat+stats JSON here (used by `ascend bridge`)")
    s.add_argument("--qpm", type=int, default=None, help="queries per minute against the target")
    s.add_argument("--max-workers", type=int, default=None, help="concurrency (auto: 1 for stateful targets)")
    s.add_argument("--capture", default=None, help="jsonl file to record probe/result envelopes")
    s.add_argument("--wait-ms", type=int, default=25000,
                   help="long-poll hold in ms (server clamps to 0-55000)")
    s.add_argument("--assessment-id", default=None,
                   help="the assessment this bridge serves; it self-stops when that run ends")
    s.add_argument("--idle-timeout", type=int, default=None,
                   help="seconds a paused, already-probed bridge waits before self-stopping. "
                        "0 never idle-stops (the default); the bridge stops when the run reaches a "
                        "terminal state. $ASCEND_BRIDGE_IDLE_TIMEOUT sets this default for "
                        "auto-managed runs.")
    s.add_argument("--no-self-reconcile", action="store_true",
                   help="do NOT self-stop on assessment completion (stay up until stopped manually)")
    s.set_defaults(func=cmd_runtime_start)

    # adapter
    adp = sub.add_parser("adapter", parents=[GLOBALS], formatter_class=_Fmt, help="adapter configs & capabilities").add_subparsers(dest="verb", required=True)
    adp.add_parser("list", parents=[GLOBALS], formatter_class=_Fmt, help="list registered adapter types").set_defaults(func=cmd_adapter_list)
    s = adp.add_parser("show", parents=[GLOBALS], formatter_class=_Fmt,
                       help="print a saved adapter config (secrets masked)")
    s.add_argument("config", help="config name in the config dir")
    s.add_argument("--reveal", action="store_true",
                   help="print secret values in clear (they are masked by default, because a "
                        "built config can carry the session token that authenticated the browser)")
    s.set_defaults(func=cmd_adapter_show)
    adp.add_parser("configs", parents=[GLOBALS], formatter_class=_Fmt,
                   help="list adapter configs on disk (incl. shipped examples)").set_defaults(func=cmd_adapter_configs)
    # Reference output, not part of the day-to-day flow — kept, hidden from the menu.
    adp.add_parser("layers", parents=[GLOBALS], formatter_class=_Fmt,
                   help=argparse.SUPPRESS).set_defaults(func=cmd_adapter_layers)

    # adapter validate (the HARD GATE)
    s = adp.add_parser("validate", parents=[GLOBALS], formatter_class=_Fmt, help="HARD GATE: run one prompt through a config against the live target",
                       epilog="example: ascend adapter validate --config mybot --prompt 'hello' --expect 'Bot'")
    s.add_argument("--config", help="config name in configs/")
    s.add_argument("--file", help="path to a config json (instead of --config)")
    s.add_argument("--adapter", help="adapter type override (else config['adapter'])")
    s.add_argument("--prompt", default="Hello, what can you help me with?")
    s.add_argument("--expect", default=None, help="substring the response must contain")
    s.add_argument("--timeout", type=float, default=60.0)
    s.set_defaults(func=cmd_adapter_validate)

    # discover
    # `adapter build` is the primary name — you are building an adapter, and the source is a flag.
    s = adp.add_parser("build", parents=[GLOBALS], formatter_class=_Fmt,
                       help="build a validated adapter from a URL / HAR / curl / API / spec",
                       description=(
                           "Build an adapter config for a target and PROVE it against the live\n"
                           "target before writing anything. The source is a flag:\n"
                           "  --har <file>   a browser HAR you exported  (most reliable)\n"
                           "  --curl <file>  one request copied as cURL\n"
                           "  --url <page>   a live page — the CLI drives a real browser\n"
                           "  --api <url>    an HTTP API endpoint\n"
                           "  --spec <base>  an OpenAPI/Swagger spec\n\n"
                           "Nothing is written unless it answered: an unvalidated config is a guess."),
                       epilog="examples:\n"
                              "  ascend adapter build --har ~/Downloads/target.har --out mybot.json\n"
                              "  ascend adapter build --curl req.curl --out mybot.json\n"
                              "  ascend adapter build --api https://host/chat --bearer $TOK --out mybot.json\n"
                              "  ascend adapter build --url https://site/support --manual --out mybot.json\n"
                              "\nsee docs/BUILD_ADAPTER.md for the full walkthrough and the HAR export steps.")
    _add_build_args(s)
    s.set_defaults(func=cmd_discover)

    # `map` / `discover` — the old names, kept working, hidden from the menu.
    s = sub.add_parser("map", aliases=["discover"], parents=[GLOBALS], formatter_class=_Fmt,
                       help=argparse.SUPPRESS)
    _add_build_args(s)
    s.set_defaults(func=cmd_discover)

    # export
    s = sub.add_parser("export", parents=[GLOBALS], formatter_class=_Fmt, help="export findings (json/csv/sarif/markdown)",
                       epilog="example: ascend export --app 'My Bot' --assessment asmt_x --format sarif --out out.sarif")
    s.add_argument("--app"); s.add_argument("--assessment")
    s.add_argument("--file", help="assessment json on disk (instead of fetching)")
    s.add_argument("--format", default="json", choices=["json", "csv", "sarif", "markdown"])
    s.add_argument("--out", default=None, help="write to this file instead of stdout"); s.set_defaults(func=cmd_export)

    # ci
    s = sub.add_parser("ci", parents=[GLOBALS], formatter_class=_Fmt, help="CI gate: nonzero exit on new findings / severity breach",
                       epilog="example: ascend ci --app 'My Bot' --assessment asmt_x --baseline base.json")
    s.add_argument("--app"); s.add_argument("--assessment")
    s.add_argument("--file", help="current assessment json on disk")
    s.add_argument("--baseline", default=None, help="baseline assessment json for diff")
    s.add_argument("--fail-on-severity", default="high", choices=["low", "medium", "high", "critical"])
    s.add_argument("--allow-new", action="store_true", help="do not fail on new findings")
    s.add_argument("--junit", metavar="FILE", help="also write JUnit XML for generic CI systems")
    s.add_argument("--policy", help="policy file (default ./ascend-policy.json or $ASCEND_POLICY); flags override it")
    s.add_argument("--min-probes", type=int, default=None, metavar="N",
                   help="refuse to pass a CLEAN run with fewer than N probes — that is what a "
                        "bridge which was not running produces, and it exits 1 (cannot trust the "
                        "results), never 0. Use 0 for runs that are genuinely this small. "
                        f"(default: {5})")
    s.set_defaults(func=cmd_ci)

    # chat — manual prompting
    s = sub.add_parser(
        "chat", parents=[GLOBALS], formatter_class=_Fmt,
        help="talk to an agent directly — a live, transcript (telnet for an AI agent)",
        epilog=("examples:\n"
                "  ascend chat mybot                         # live session, auto-recorded\n"
                "  ascend chat https://host/api/chat         # discover it, then talk to it\n"
                "  ascend chat mybot --prompt 'what can you do?'\n"
                "  ascend chat mybot --prompt-file probes.txt --out captures/run.jsonl\n"
                "\nin a live session:\n"
                "  /new  /results  /retry  /save <file>  /help  /exit"))
    s.add_argument("target", nargs="?",
                   help="config name, config path, or a URL (a URL is discovered first)")
    s.add_argument("--config", help="config name or path (same as the positional)")
    s.add_argument("--file", help="config json path")
    s.add_argument("--adapter", help="adapter type (default: from the config)")
    s.add_argument("--prompt", dest="prompts", action="append",
                   help="send this prompt and exit; repeat for several")
    s.add_argument("--prompt-file",
                   help="file of prompts: one per line, or JSONL {prompt,id,category,expect,note}")
    s.add_argument("--out", help="write the transcript here (default: captures/<target>-<ts>.jsonl)")
    s.add_argument("--no-record", action="store_true", help="do not write a transcript")
    s.add_argument("--header", action="append", metavar="'Name: value'",
                   help="header when the target is a URL (repeatable)")
    s.add_argument("--reset-between", action="store_true",
                   help="fresh conversation for each prompt in a file")
    s.add_argument("--timeout", type=float, default=60.0, help="per-turn timeout in seconds")
    s.set_defaults(func=cmd_chat)

    # onboard — the one-shot path
    s = sub.add_parser(
        "onboard", parents=[GLOBALS],
        help="zero to a running assessment in one command (build -> validate -> register -> bridge -> assess)",
        epilog=("examples:\n"
                "  ascend onboard --api http://127.0.0.1:8790/chat --name Local --controls sys_prompt_leak\n"
                "  ascend onboard --url https://site/support --controls sys_prompt_leak\n"
                "  ascend onboard --har capture.har --name 'Support Bot'\n"
                "  ascend onboard --config mybot --wait\n"
                "  ascend onboard --url https://site/support --dry-run   # stop after validation"),
        )
    src = s.add_mutually_exclusive_group(required=True)
    src.add_argument("--api", metavar="URL",
                     help="an HTTP API endpoint (or base URL) — one probe, no browser. The "
                          "simple-contract one-liner.")
    src.add_argument("--url", help="live page with a chat widget: capture the contract in a real browser")
    src.add_argument("--curl", metavar="FILE", help="a curl command in a file (or '-' for stdin)")
    src.add_argument("--har", help="HAR file exported from your own browser (no browser needed here)")
    src.add_argument("--config", help="an existing config in the config dir (skip discovery)")
    s.add_argument("--name", help="application name in Ascend (default: derived from the URL)")
    s.add_argument("--system-prompt", help="what the target is, for the assessment context")
    s.add_argument("--controls", help="comma-separated control ids (validated before the run)")
    s.add_argument("--adapter", help="override the adapter type (default: from the config)")
    s.add_argument("--bearer", metavar="TOKEN", help="Authorization: Bearer <token> (with --api/--curl)")
    s.add_argument("--api-key", metavar="NAME:VALUE[:in=header|query]", help="API key (with --api)")
    s.add_argument("--header", action="append", metavar="'Name: value'", help="raw header (repeatable)")
    s.add_argument("--body-field", action="append", metavar="key=value",
                   help="extra JSON body field (repeatable) — for a key/tenant that lives in the body")
    s.add_argument("--prompt-hint", help="with --curl: the literal prompt text used in that command")
    s.add_argument("--insecure", action="store_true", help="skip TLS verification (self-signed internal)")
    s.add_argument("--size", default="small", choices=["small", "medium", "large"],
                   help="assessment size")
    s.add_argument("--qpm", type=int, default=20, help="queries per minute against the target")
    s.add_argument("--prompt", default="Hello, what can you help me with?",
                   help="benign prompt used for capture and validation")
    s.add_argument("--settle", type=int, default=8, help="seconds to wait for the widget/reply during capture")
    s.add_argument("--headless", action="store_true", help="headless capture (bot protection often blocks it)")
    s.add_argument("--manual", action="store_true", help="you drive the widget; we record")
    s.add_argument("--timeout", type=float, default=60.0, help="per-request timeout for validation")
    s.add_argument("--dry-run", action="store_true",
                   help="stop after validating the config — do not register or run anything")
    s.add_argument("--wait", action="store_true", help="block until the assessment completes, then print findings")
    s.add_argument("--detail", action="store_true", help="with --wait, show key findings per control")
    s.add_argument("--interval", type=int, default=20, help="poll interval while waiting")
    s.add_argument("--timeout-assess", type=int, default=7200, help="max seconds to wait for completion")
    s.add_argument("--assessment-name", help="assessment name (default: '<app> run 1')")
    s.add_argument("-v", "--verbose", action="store_true", help="debug logging for the bridge")
    s.set_defaults(func=cmd_onboard)

    s = sub.add_parser("results", parents=[GLOBALS], formatter_class=_Fmt,
                       help="read results: a Console CSV export, or a local capture",
                       description=(
                           "Show results. One command, two sources.\n\n"
                           "With NO file it reads the platform: your assessments as a table "
                           "(severity, score, pass/fail). With a FILE it reads that file — a "
                           "Console CSV export is rolled up by the platform's own taxonomy "
                           "(category, control, data class) plus the evasion technique that "
                           "worked; a saved transcript is rendered turn by turn. The route is "
                           "sniffed from the file's contents, not its extension."),
                       epilog=("from the platform (no file):\n"
                               "  ascend results                                # every app's latest assessment\n"
                               "  ascend results --app 'My Bot' --detail        # + probe and finding counts\n"
                               "  ascend results --min-sev high --sort score\n"
                               "\nfrom a file:\n"
                               "  ascend results run.csv                        # failures by category/evasion/control\n"
                               "  ascend results run.csv --values               # the data harvest\n"
                               "  ascend results run.csv --turns --limit 5      # the failing turns themselves\n"
                               "  ascend results run.csv --matrix               # guardrail confusion matrix\n"
                               "  ascend results run.csv --md > findings.md     # for a report or PR comment\n"
                               "  ascend results run.csv --json | jq .data.by_evasion\n"
                               "  ascend results transcript.jsonl --follow      # live probe view\n"
                               "\nunits: PROBES, PASSED and FAILED are probe counts, not finding counts.\n"
                               "Unanswered probes measured nothing and are never counted as passes."))
    s.add_argument("file", nargs="?",
                   help="a Console CSV export or a saved transcript. Omit it to see your "
                        "assessments from the platform instead.")
    # --- export analysis ---
    s.add_argument("--by", metavar="SECTIONS",
                   help="comma-separated rollups: category,evasion,control,risk,dataclass,combo "
                        "(default: category,evasion,control). An unknown name is refused.")
    s.add_argument("--values", action="store_true",
                   help="rank the concrete values the target produced, with provenance")
    s.add_argument("--all-values", action="store_true",
                   help="with --values, also show values that came FROM THE PROMPT (the target "
                        "repeating back what the attacker supplied — not a disclosure)")
    s.add_argument("--turns", action="store_true", help="print the failing turns (prompt/answer/why)")
    s.add_argument("--errors", action="store_true", help="list probes the target never answered")
    s.add_argument("--matrix", action="store_true",
                   help="guardrail confusion matrix from the platform's own FP/FN flags")
    s.add_argument("--limit", type=int, default=None, metavar="N",
                   help="cap rows per section; 0 shows everything (default: per-section caps)")
    s.add_argument("--md", action="store_true", help="emit Markdown instead of a table")
    s.add_argument("--no-catalog", action="store_true",
                   help="skip the /ascend/controls fetch; roll up on raw ids (fully offline)")
    # --- local capture replay ---
    s.add_argument("--follow", "-f", action="store_true", help="tail a transcript live as probes are answered")
    s.add_argument("--verbose", "-v", action="store_true", help="show each response body")
    s.add_argument("--interval", type=float, default=2.0, help="seconds between polls when following")
    # --- platform view (no file given) ---
    s.add_argument("--app", action="append",
                   help="only this app (name or aapp_ id); repeatable")
    s.add_argument("--detail", action="store_true",
                   help="add probe and finding counts (one extra call per assessment)")
    s.add_argument("--per-app", type=int, default=1, metavar="N",
                   help="how many assessments to show per app")
    s.add_argument("--min-sev", choices=list(SEVERITY_CHOICES),
                   help="only this severity or worse. An assessment that finished but whose "
                        "severity cannot be read is always shown, never filtered out.")
    s.add_argument("--since", metavar="DAYS", help="only assessments newer than this, e.g. 30 or 30d")
    s.add_argument("--sort", choices=["sev", "fail", "when"], default="sev")
    s.add_argument("--include-running", action="store_true", help="also show unfinished assessments")
    s.add_argument("--policy", help="gate policy file (default ./ascend-policy.json or $ASCEND_POLICY)")
    s.set_defaults(func=cmd_results)

    # bridge (the fleet: one detached bridge per app / per bridge key)
    rp = sub.add_parser("bridge", aliases=["relay"], parents=[GLOBALS], formatter_class=_Fmt,
                        help="manage the CLI's built-in bridge for `bridge`-type apps "
                             "(usually auto-managed by `assess run`)"
                        ).add_subparsers(dest="verb", required=True)
    s = rp.add_parser("start", parents=[GLOBALS], formatter_class=_Fmt,
                      help="start a detached bridge per app (key comes from the local store)",
                      epilog="examples:\n"
                             "  ascend bridge start --all-running        # serve every live assessment\n"
                             "  ascend bridge start --app 'My Bot'       # one app (repeatable)\n"
                             "  ascend bridge start --all-running --qpm-total 60\n"
                             "  ascend bridge start --app 'My Bot' --config mybot --foreground\n"
                             "      one bridge, in this terminal, logs on screen (debugging)")
    s.add_argument("--app", action="append", help="app name or aapp_ id (repeatable)")
    s.add_argument("--all-running", action="store_true",
                   help="every app whose latest assessment is actively running")
    s.add_argument("--config", help="override the bound config name for all targets")
    s.add_argument("--qpm", type=int, default=None, help="per-bridge queries per minute")
    s.add_argument("--qpm-total", type=int, default=None,
                   help="split this total across the started bridges (protects a shared target host)")
    s.add_argument("--max-workers", type=int, default=None)
    s.add_argument("--wait-ms", type=int, default=None)
    s.add_argument("--idle-timeout", type=int, default=None,
                   help="seconds a paused, already-probed bridge waits before self-stopping. "
                        "0 never idle-stops (the default); the bridge stops when the run reaches a "
                        "terminal state. $ASCEND_BRIDGE_IDLE_TIMEOUT sets this default for "
                        "auto-managed runs.")
    s.add_argument("--foreground", action="store_true",
                   help="run ONE bridge in this terminal (logs here, Ctrl-C stops it) instead of "
                        "detaching — for debugging an adapter. Needs --config.")
    s.set_defaults(func=cmd_relay_start)
    s = rp.add_parser("ls", parents=[GLOBALS], formatter_class=_Fmt,
                      help="list bridges + flag live assessments with NO bridge")
    s.add_argument("--no-check", action="store_true", help="skip the tenant lookup (offline/fast)")
    s.set_defaults(func=cmd_relay_ls)
    s = rp.add_parser("stop", parents=[GLOBALS], formatter_class=_Fmt, help="stop bridges")
    s.add_argument("--app", action="append", help="app name or aapp_ id (repeatable)")
    s.add_argument("--all", action="store_true", help="stop every bridge")
    s.add_argument("--grace", type=float, default=8.0, help="seconds before SIGKILL")
    s.set_defaults(func=cmd_relay_stop)
    s = rp.add_parser("logs", parents=[GLOBALS], formatter_class=_Fmt, help="show a bridge's log")
    s.add_argument("app", help="app name or aapp_ id")
    s.add_argument("--follow", "-f", action="store_true", help="tail live")
    s.set_defaults(func=cmd_relay_logs)
    s = rp.add_parser("sync", parents=[GLOBALS], formatter_class=_Fmt,
                      help="reconcile bridges to assessment state — start for running/paused apps, "
                           "stop for terminal (the fallback after a Console-side change)")
    s.add_argument("--no-stop", action="store_true",
                   help="only start missing bridges; never stop one")
    s.set_defaults(func=cmd_bridge_sync)

    # keys (the local bridge key store)
    kp = sub.add_parser("keys", parents=[GLOBALS], formatter_class=_Fmt,
                        help="manage stored tc- bridge keys").add_subparsers(dest="verb", required=True)
    s = kp.add_parser("list", parents=[GLOBALS], formatter_class=_Fmt, help="list stored keys (masked)")
    s.add_argument("--no-check", action="store_true", help="don't check whether the apps still exist")
    s.set_defaults(func=cmd_keys_list)
    s = kp.add_parser("prune", parents=[GLOBALS], formatter_class=_Fmt,
                      help="drop keys whose app no longer exists")
    s.add_argument("--yes", action="store_true",
                   help="allow pruning ALL stored keys (refused by default: a bridge key is shown once)")
    s.set_defaults(func=cmd_keys_prune)
    s = kp.add_parser("add", parents=[GLOBALS], formatter_class=_Fmt, help="store a bridge key for an app")
    s.add_argument("--app", required=True, help="app name or aapp_ id")
    s.add_argument("--key", required=True, help="the bridge key")
    s.add_argument("--config", help="config name this app is driven by")
    s.add_argument("--adapter", help="adapter type")
    s.set_defaults(func=cmd_keys_add)
    s = kp.add_parser("rm", parents=[GLOBALS], formatter_class=_Fmt,
                      help="remove a stored key (optionally the Ascend app with it)")
    s.add_argument("app", help="app name or aapp_ id")
    s.add_argument("--delete-app", action="store_true",
                   help="also delete the Ascend app (retire the pair: a keyless app can't be served)")
    s.set_defaults(func=cmd_keys_rm)

    # tenant (the single-tenant lock)
    tp = sub.add_parser("tenant", parents=[GLOBALS], formatter_class=_Fmt,
                        help="the single-tenant lock").add_subparsers(dest="verb", required=True)
    tp.add_parser("show", parents=[GLOBALS], formatter_class=_Fmt,
                  help="which tenant this CLI is locked to").set_defaults(func=cmd_tenant_show)
    s = tp.add_parser("switch", parents=[GLOBALS], formatter_class=_Fmt,
                      help="move to another tenant (clears stored keys)")
    s.add_argument("--confirm", action="store_true", help="required: this clears stored keys")
    s.add_argument("--force", action="store_true", help="switch even if bridges are running")
    s.set_defaults(func=cmd_tenant_switch)

    # reports (results as a table)
    s = sub.add_parser("reports", parents=[GLOBALS], formatter_class=_Fmt,
                       help="assessment results as a table (severity, score, pass/fail, findings)",
                       epilog="examples:\n"
                              "  ascend reports                      # latest run per app\n"
                              "  ascend reports --detail             # + probe/finding counts\n"
                              "  ascend reports --min-sev high --sort sev\n"
                              "  ascend reports --app 'My Bot' --per-app 5 --json")
    s.add_argument("--app", action="append", help="limit to these apps (repeatable)")
    s.add_argument("--detail", action="store_true",
                   help="add pass/fail, probe and finding counts (one extra call per run)")
    s.add_argument("--per-app", type=int, default=1, help="how many recent runs per app")
    s.add_argument("--min-sev", choices=list(SEVERITY_CHOICES),
                   help="only this severity or worse. A finished run whose severity cannot be "
                        "read is always shown, never filtered out.")
    s.add_argument("--since", metavar="DAYS",
                   help="only runs newer than this many days, e.g. 30 or 30d")
    s.add_argument("--sort", choices=["sev", "fail", "when"], default="sev")
    s.add_argument("--include-running", action="store_true", help="also show unfinished assessments")
    s.add_argument("--policy", help="policy file (default ./ascend-policy.json or $ASCEND_POLICY)")
    s.set_defaults(func=cmd_reports)

    # policy (local gate thresholds + severity overrides)
    pp = sub.add_parser("policy", parents=[GLOBALS], formatter_class=_Fmt,
                        help="your gate policy: how much you care about each control, and when CI fails"
                        ).add_subparsers(dest="verb", required=True)
    s = pp.add_parser("show", parents=[GLOBALS], formatter_class=_Fmt, help="show the effective policy")
    s.add_argument("--policy", help="policy file path")
    s.set_defaults(func=cmd_policy_show)
    s = pp.add_parser("set", parents=[GLOBALS], formatter_class=_Fmt,
                      help="set gate thresholds and severity overrides",
                      description=(
                          "A CONTROL belongs to the platform — it is a check Ascend runs. A GATE "
                          "POLICY belongs to you: a file in your repo saying how much you care "
                          "about that control's findings, and when a pipeline should fail.\n\n"
                          "So `--control tool_misuse=critical` means: in MY policy, treat findings "
                          "from the platform's tool_misuse control as critical. It does not change "
                          "the control itself.\n\n"
                          "Per-CATEGORY severity can be pushed to the app (`ascend policy push`); "
                          "per-CONTROL severity has nowhere to live in the API, so it stays local "
                          "and applies to `ascend results` and `ascend ci`."),
                      epilog="examples:\n"
                             "  ascend policy set --fail-on-severity high\n"
                             "  ascend policy set --app 'My Bot' --control tool_misuse=critical\n"
                             "  ascend policy set --category data_leak=high")
    s.add_argument("--app", help="scope to one app (default: the global default block)")
    s.add_argument("--fail-on-severity", choices=["critical", "high", "medium", "low"])
    s.add_argument("--fail-on-new", action="store_true", help="fail on new findings vs a baseline")
    s.add_argument("--allow-new", action="store_true", help="do NOT fail on new findings")
    s.add_argument("--control", action="append", metavar="CONTROL=SEVERITY",
                   help="how severe THIS policy treats a control's findings (repeatable). Local "
                        "only — the API has nowhere to put it.")
    s.add_argument("--category", action="append", metavar="CATEGORY=SEVERITY",
                   help="how severe THIS policy treats a category's findings (repeatable). "
                        "Can be sent to the app with `ascend policy push`.")
    s.add_argument("--policy", help="policy file path")
    s.set_defaults(func=cmd_policy_set)
    s = pp.add_parser("push", parents=[GLOBALS], formatter_class=_Fmt,
                      help="push CATEGORY severities from the policy to the Ascend app",
                      description=(
                          "Send the local policy's per-CATEGORY severities to the app, so the "
                          "Console reflects what you decided.\n\n"
                          "Only the category half can be pushed: `category_severities` is a real "
                          "field on an Ascend app. Per-CONTROL overrides have nowhere to go in v3 "
                          "and stay local, applying to `ascend reports` and `ascend ci` only — "
                          "the command says which ones those are rather than leaving you to "
                          "assume they reached the platform.\n\n"
                          "The platform's enum is default|low|medium|high: a policy asking for "
                          "`critical` is clamped to `high`, out loud."),
                      epilog=("examples:\n"
                              "  ascend policy set --app 'My Bot' --category data_leak=high\n"
                              "  ascend policy push --app 'My Bot' --dry-run\n"
                              "  ascend policy push --app 'My Bot'"))
    s.add_argument("--app", required=True, help="app name or aapp_ id")
    s.add_argument("--dry-run", action="store_true", help="show what would be sent, send nothing")
    s.add_argument("--policy", help="policy file path")
    s.set_defaults(func=cmd_policy_push)

    s = sub.add_parser("status", parents=[GLOBALS], formatter_class=_Fmt,
                       help="where things stand: tenant, apps, live runs, bridges (one call)",
                       epilog="examples:\n"
                              "  ascend status            # the whole picture\n"
                              "  ascend status --quick    # skip the per-app assessment scan\n"
                              "  ascend status --json     # for agents/scripts")
    s.add_argument("--quick", action="store_true",
                   help="skip the per-app assessment fan-out (fast, no live-run detail)")
    s.set_defaults(func=cmd_status)

    s = sub.add_parser("doctor", parents=[GLOBALS], formatter_class=_Fmt,
                       help="preflight checks + version-vs-latest (--api-compat, --update)")
    s.add_argument("--api-compat", action="store_true",
                   help="verify every API field this CLI depends on (drift = loud failure)")
    s.add_argument("--update", action="store_true",
                   help="update this install if a newer release is published "
                        "(git pull for a clone; prints the command for pipx/binary)")
    s.set_defaults(func=cmd_doctor)
    sub.add_parser("version", parents=[GLOBALS], formatter_class=_Fmt, help="print version").set_defaults(func=lambda a: print(VERSION))
    return p


def _reapply_globals(args, raw):
    """Re-apply global flags from raw argv.

    argparse's subparser action parses into a fresh namespace and copies it back over
    the root's, which can drop a global given BEFORE the group (`ascend --json app list`).
    Re-reading raw argv makes both positions behave identically, whatever argparse does.
    """
    if "--json" in raw:
        args.json = True
    for flag, dest in (("--token", "token"), ("--base", "base"),
                       ("--bridge-base", "bridge_base")):
        if flag in raw:
            i = raw.index(flag)
            if i + 1 < len(raw):
                setattr(args, dest, raw[i + 1])
    return args


# Hardcoded so the CLI stays self-contained (no figlet dependency). Star-decorated wordmark, shown
# as the waiting banner during long operations (and on a bare `ascend`).
_STAR_UNI = [
    r"        ✦                                   ·",
    r"    _    ____   ____ _____ _   _ ____       ✦",
    r"   / \  / ___| / ___| ____| \ | |  _ \ ",
    r"  / _ \ \___ \| |   |  _| |  \| | | | |     ·",
    r" / ___ \ ___) | |___| |___| |\  | |_| |          ✦",
    r"/_/   \_\____/ \____|_____|_| \_|____/   ·",
]
_STAR_ASCII = [
    r"        *                                   .",
    r"    _    ____   ____ _____ _   _ ____       *",
    r"   / \  / ___| / ___| ____| \ | |  _ \ ",
    r"  / _ \ \___ \| |   |  _| |  \| | | | |     *",
    r" / ___ \ ___) | |___| |___| |\  | |_| |",
    r"/_/   \_\____/ \____|_____|_| \_|____/   .       *",
]


def _brand_banner():
    return "\n".join(_STAR_UNI if _ui._unicode_ok() else _STAR_ASCII)


# The plain ASCEND wordmark, with animated sparkles overlaid in the right margin (cols >= 40 so
# they never touch the letters). Fallback for terminals without truecolor: the logo icon below
# needs 24-bit color to render, so a 16-color or mono TTY gets this twinkling wordmark instead.
_WORDMARK = [
    r"    _    ____   ____ _____ _   _ ____",
    r"   / \  / ___| / ___| ____| \ | |  _ \ ",
    r"  / _ \ \___ \| |   |  _| |  \| | | | |",
    r" / ___ \ ___) | |___| |___| |\  | |_| |",
    r"/_/   \_\____/ \____|_____|_| \_|____/ ",
]
_SPARKS = [(0, 42, 0), (1, 49, 3), (2, 44, 5), (3, 51, 1), (4, 46, 6), (1, 40, 2), (3, 41, 4), (0, 52, 7)]
_SEQ_UNI = [" ", "·", "✧", "✦", "✦", "✧", "·"]
_SEQ_ASCII = [" ", ".", "+", "*", "*", "+", "."]

# The actual Ascend logo (the weapon-star + companion spark), pre-rendered offline from
# ascendai-logo.png into braille cells so the CLI needs no image library at runtime. Braille packs
# 2x4 dots per character, so a small mark stays crisp where a half-block raster looks blocky. Each
# cell is one glyph (U+2800 + dot bits); a space is an empty cell. Colored red per cell at render.
_BRAILLE_W = 14
_BRAILLE_ROWS = (
    "    ⠘⢦⡀    ⢀⣠⠆",
    "     ⠈⠻⣦⣄⣠⣴⡟⠁",
    "       ⢹⣿⣿⣿",
    "      ⣠⡿⠟⠻⢿⣆",
    "    ⢠⡾⠋    ⠙⠳⠄",
    "  ⢀⡴⠋",
    " ⠰⠋",
)
_LOGO_RED = (255, 83, 120)        # Ascend #FF5378
_LOGO_GLINT = (255, 190, 210)     # the light that sweeps the blade
_LOGO_INDENT = "   "
_LOGO_PERIOD = 14                 # frames per breathe / glint cycle


def _truecolor_ok() -> bool:
    """True when the terminal can render 24-bit color (clean reds). Otherwise the logo still renders,
    approximated into the xterm-256 palette (e.g. Apple Terminal)."""
    if (os.environ.get("COLORTERM", "").lower() in ("truecolor", "24bit")):
        return True
    return os.environ.get("TERM_PROGRAM", "") in ("iTerm.app", "WezTerm", "ghostty", "vscode")


_XT_STEPS = (0, 95, 135, 175, 215, 255)     # the xterm-256 color-cube levels


def _rgb256(r, g, b) -> int:
    """Nearest xterm-256 color-cube index for an RGB triple (16..231)."""
    def q(v):
        return min(range(6), key=lambda i: abs(_XT_STEPS[i] - v))
    return 16 + 36 * q(r) + 6 * q(g) + q(b)


# --- real-image tier: draw the actual logo PNG via a terminal graphics protocol ------------------
# Detection is conservative: only terminals that render images WITHOUT an opt-in setting are matched,
# so an image escape is never sent to a terminal that would show it as garbage. Force with
# ASCEND_LOGO=image (e.g. VS Code once terminal.integrated.enableImages is on).
_LOGO_PNG_PATH = REPO / "assets" / "ascend-logo.png"
_LOGO_PNG_TRIED = False
_LOGO_PNG_BYTES = None
_SPIN = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"


def _load_logo_png():
    global _LOGO_PNG_TRIED, _LOGO_PNG_BYTES
    if not _LOGO_PNG_TRIED:
        _LOGO_PNG_TRIED = True
        try:
            _LOGO_PNG_BYTES = _LOGO_PNG_PATH.read_bytes()
        except Exception:
            _LOGO_PNG_BYTES = None
    return _LOGO_PNG_BYTES


def _image_proto():
    """'iterm' | 'kitty' | None — the graphics protocol this terminal renders unprompted."""
    tp = os.environ.get("TERM_PROGRAM", "")
    if tp in ("iTerm.app", "WezTerm") or os.environ.get("LC_TERMINAL", "") == "iTerm2":
        return "iterm"
    if tp == "ghostty" or os.environ.get("TERM", "") == "xterm-kitty" or os.environ.get("KITTY_WINDOW_ID"):
        return "kitty"
    return None


def _iterm_image_seq(data, width_cells, height_cells):
    b64 = base64.b64encode(data).decode()
    seq = (f"\033]1337;File=inline=1;width={width_cells};height={height_cells};"
           f"preserveAspectRatio=1;size={len(data)}:{b64}\a")
    if os.environ.get("TMUX") or os.environ.get("TERM", "").startswith(("screen", "tmux")):
        seq = "\033Ptmux;" + seq.replace("\033", "\033\033") + "\033\\"   # tmux passthrough
    return seq


def _kitty_image_seq(data, cols, rows):
    b = base64.b64encode(data)
    chunks = [b[i:i + 4096] for i in range(0, len(b), 4096)] or [b""]
    parts = []
    for i, ch in enumerate(chunks):
        more = 1 if i < len(chunks) - 1 else 0
        ctrl = f"a=T,f=100,c={cols},r={rows},m={more}" if i == 0 else f"m={more}"
        parts.append("\033_G" + ctrl + ";" + ch.decode("ascii") + "\033\\")
    return "".join(parts)


class _TwinkleBanner:
    """Animated Ascend logo shown while a long operation blocks, in three tiers, best first:
      image    the actual logo PNG drawn inline (iTerm2 / WezTerm / Kitty / Ghostty), static, with
               a small spinner for motion.
      logo     the logo drawn in braille (crisp at small size) next to the ASCEND wordmark, breathing
               red with a glint sweeping the blade (any truecolor or 256-color terminal, e.g. VS Code,
               Apple Terminal).
      wordmark the twinkling ASCEND wordmark (mono / no-color last resort).
    A daemon thread animates it in place. No-op unless stdout is a TTY and --json is off, so scripts,
    pipes, and agents see nothing. Override the tier with ASCEND_LOGO=image|block|wordmark|off."""
    def __init__(self, subtitle=""):
        self._subtitle = subtitle
        self._stop = threading.Event()
        self._t = None
        self._lock = threading.Lock()
        self.enabled = bool(sys.stdout.isatty()) and not _wants_json()
        self._uni = _ui._unicode_ok()
        self._color = _ui.color_ok(sys.stdout)
        self._tc = _truecolor_ok()
        self._proto = None
        self._png = None
        self._mode = self._decide_mode()
        self._logo = self._mode == "logo"
        # Live probe feed: aggregate progress (push_progress) becomes star-bulleted lines below the
        # header, revealed a few at a time so it reads like the Console live view, not a blur.
        self._K = 8
        self._feed = collections.deque(maxlen=self._K)
        self._pending = collections.deque()
        self._total = 0
        self._completed_last = 0
        self._failed_last = 0
        self._done = False
        header = len(_BRAILLE_ROWS) if self._logo else len(_WORDMARK)
        self._n = header + 2 + self._K       # header + subtitle + blank + feed window
        self._tn = 3 + self._K               # image tier: caption + subtitle + blank + feed window

    def _decide_mode(self):
        if not self.enabled:
            return "off"
        ov = os.environ.get("ASCEND_LOGO", "auto").strip().lower()
        if ov == "off":
            return "off"
        if ov in ("image", "auto"):
            proto = _image_proto() if ov == "auto" else (_image_proto() or "iterm")
            if proto and _load_logo_png() is not None:
                self._proto, self._png = proto, _load_logo_png()
                return "image"
        if ov == "wordmark":
            return "wordmark"
        if self._uni and self._color:      # auto (no image) or ov == "block"
            return "logo"
        return "wordmark"

    def set_subtitle(self, s):
        with self._lock:
            self._subtitle = s

    # -- live probe feed --------------------------------------------------
    def push_progress(self, completed, failed, total, done=False):
        """Feed the run's aggregate counts. Each newly-completed probe becomes a star-bulleted feed
        line; the animation loop reveals them a few at a time."""
        with self._lock:
            if total:
                self._total = total
            completed = max(self._completed_last, int(completed or 0))
            failed = int(failed or 0)
            new = completed - self._completed_last
            new_fail = max(0, failed - self._failed_last)
            for i in range(new):
                idx = self._completed_last + i + 1
                self._pending.append((idx, i >= new - new_fail))   # last new_fail of the batch fail
            self._completed_last = completed
            self._failed_last = failed
            if done:
                self._done = True

    def _feed_line(self, idx, is_fail):
        star = self._red("✦" if self._uni else "*")
        tot = self._total or "?"
        if not self._color:
            return f"{star}  probe {idx:>3}/{tot:<4} {'FAIL' if is_fail else 'pass'}"
        if is_fail:
            code = "1;38;2;255;83;120" if self._tc else f"1;38;5;{_rgb256(*_LOGO_RED)}"
            res = f"\033[{code}mFAIL\033[0m"
        else:
            res = "\033[2mpass\033[0m"
        return f"{star}  \033[2mprobe {idx:>3}/{tot:<4}\033[0m {res}"

    def _drain(self, f):
        """Reveal a few pending probes into the visible window; flush all once the run is done."""
        with self._lock:
            if not self._pending:
                return
            if self._done:
                rate = len(self._pending)
            else:
                rate = max(1, len(self._pending) // 12)
                if rate == 1 and (f % 2):     # slow the trickle to a readable ~4/sec
                    rate = 0
            for _ in range(rate):
                if not self._pending:
                    break
                idx, is_fail = self._pending.popleft()
                self._feed.append(self._feed_line(idx, is_fail))

    def _feed_rows(self):
        with self._lock:
            feed = list(self._feed)
        return [""] * (self._K - len(feed)) + feed

    # -- wordmark fallback ------------------------------------------------
    def _frame_wordmark(self, f):
        w = max(len(l) for l in _WORDMARK) + 16
        grid = [list(l.ljust(w)) for l in _WORDMARK]
        seq = _SEQ_UNI if self._uni else _SEQ_ASCII
        for (r, col, seed) in _SPARKS:
            grid[r][col] = seq[(f + seed) % len(seq)]
        return [("".join(row)).rstrip() for row in grid]

    def _esc(self, rgb, layer):
        # layer 38 = foreground, 48 = background
        if self._tc:
            return f"{layer};2;{rgb[0]};{rgb[1]};{rgb[2]}"
        return f"{layer};5;{_rgb256(*rgb)}"

    # -- real-logo braille renderer ---------------------------------------
    def _cell_rgb(self, cx, cy, g, gp):
        # Ascend red per cell, breathing (g) with a lighter glint band sweeping down the blade.
        glint = max(0.0, 1.0 - abs((cx + (len(_BRAILLE_ROWS) - 1 - cy)) - gp) / 1.6) * 0.85
        r, gg, b = (v * g for v in _LOGO_RED)
        if glint:
            r += (_LOGO_GLINT[0] - r) * glint
            gg += (_LOGO_GLINT[1] - gg) * glint
            b += (_LOGO_GLINT[2] - b) * glint
        return (min(255, int(r)), min(255, int(gg)), min(255, int(b)))

    def _frame_logo(self, f):
        # Compact lockup: the braille weapon-star on the left (breathing red, glint sweeping the
        # blade) with the ASCEND wordmark vertically centered beside it.
        rows, C, R = _BRAILLE_ROWS, _BRAILLE_W, len(_BRAILLE_ROWS)
        span = (C - 1) + (R - 1)
        gp = (f % _LOGO_PERIOD) / _LOGO_PERIOD * span
        g = 0.55 + 0.45 * (0.5 - 0.5 * math.cos(2 * math.pi * (f % _LOGO_PERIOD) / _LOGO_PERIOD))
        pad = (R - len(_WORDMARK)) // 2
        out = []
        for cy, row in enumerate(rows):
            line = [_LOGO_INDENT]
            for cx in range(C):
                ch = row[cx] if cx < len(row) else " "
                if ch == " " or ch == "⠀":
                    line.append(" ")
                else:
                    line.append(f"\033[{self._esc(self._cell_rgb(cx, cy, g, gp), 38)}m{ch}\033[0m")
            wi = cy - pad
            if 0 <= wi < len(_WORDMARK):
                line.append("  " + self._red(_WORDMARK[wi]))
            out.append("".join(line))
        return out

    def _render(self, f, first=False):
        DIM, OFF, PINK = "\033[2m", "\033[0m", "\033[38;5;205m"
        with self._lock:
            sub = self._subtitle
        out = [] if first else [f"\033[{self._n}A"]
        if self._logo:
            body = self._frame_logo(f)
        else:
            body = [(f"{PINK}{ln}{OFF}" if self._color else ln) for ln in self._frame_wordmark(f)]
        for ln in body:
            out.append("\r\033[K" + ln + "\n")
        out.append("\r\033[K" + _LOGO_INDENT + (f"{DIM}{sub}{OFF}" if self._color else sub) + "\n")
        out.append("\r\033[K\n")
        for ln in self._feed_rows():
            out.append("\r\033[K" + (_LOGO_INDENT + ln if ln else "") + "\n")
        try:
            sys.stdout.write("".join(out)); sys.stdout.flush()
        except Exception:
            self.enabled = False

    # -- real-image tier --------------------------------------------------
    def _red(self, s):
        if not self._color:
            return s
        code = "38;2;255;83;120" if self._tc else f"38;5;{_rgb256(*_LOGO_RED)}"
        return f"\033[{code}m{s}\033[0m"

    def _region_lines(self, f):
        # The text region under the static image: ASCEND caption, spinner subtitle, blank, feed.
        DIM, OFF = "\033[2m", "\033[0m"
        with self._lock:
            sub = self._subtitle
        spin = _SPIN[f % len(_SPIN)]
        cap = _LOGO_INDENT + self._red("A S C E N D")
        subline = _LOGO_INDENT + self._red(spin) + "  " + (f"{DIM}{sub}{OFF}" if self._color else sub)
        rows = [cap, subline, ""]
        rows += [(_LOGO_INDENT + ln if ln else "") for ln in self._feed_rows()]
        return rows

    def _render_image(self, f, first=False):
        # The image is drawn once in _enter_image and never redrawn (no flicker); only the text
        # region below it repaints each tick.
        out = [] if first else [f"\033[{self._tn}A"]
        for ln in self._region_lines(f):
            out.append("\r\033[K" + ln + "\n")
        try:
            sys.stdout.write("".join(out)); sys.stdout.flush()
        except Exception:
            self.enabled = False

    def _enter_image(self):
        seq = (_iterm_image_seq(self._png, 10, 5) if self._proto == "iterm"
               else _kitty_image_seq(self._png, 10, 5))
        sys.stdout.write("\n" + seq + "\n")     # spacer, the real logo, land below it
        self._render_image(0, first=True)

    def _render_tick(self, f):
        self._drain(f)
        if self._mode == "image":
            self._render_image(f)
        else:
            self._render(f)

    def _loop(self):
        f = 1
        while not self._stop.wait(0.12):
            if not self.enabled:
                return
            self._render_tick(f); f += 1

    def __enter__(self):
        if self._mode == "off":
            return self
        if self._mode == "image":
            self._enter_image()
        else:
            print()
            self._render(0, first=True)
        self._t = threading.Thread(target=self._loop, daemon=True)
        self._t.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        if self._t:
            self._t.join(timeout=0.4)
        if self._mode != "off":
            try:
                with self._lock:          # flush any probes still pending into the window
                    self._done = True
                self._drain(0)
                (self._render_image if self._mode == "image" else self._render)(0)
                sys.stdout.write("\n"); sys.stdout.flush()
            except Exception:
                pass
        return False


def _launch_screen():
    """A branded home screen for a bare `ascend` on a TTY: wordmark, the flow, next steps.
    No network, so it is instant. Scripts, agents, pipes, and --json never see this."""
    color = _ui.color_ok(sys.stdout)
    PINK, DIM, B, OFF = "\033[38;5;205m", "\033[2m", "\033[1m", "\033[0m"
    def c(s, code):
        return f"{code}{s}{OFF}" if color else s
    print()
    print(c(_brand_banner(), PINK))
    print("  " + c("red-team CLI for AI targets", DIM) + f"    v{VERSION}")
    print()
    print("  " + c("THE FLOW", B) + c("   (every command also takes --json for agents)", DIM))
    print("    adapter build   turn a target into a validated adapter  " +
          c("--har / --url / --api / --curl / --spec", DIM))
    print("    app create      register it in Ascend (type bridge is auto-relayed)")
    print("    assess run      run it  " + c("(the bridge auto-starts and self-stops)", DIM))
    print("    results / ci    read findings (FAIL% + risk)  ·  gate a pipeline")
    print()
    print("  " + c("START HERE", B))
    print("    ascend status              " + c("# tenant, apps, live runs, bridges", DIM))
    print("    ascend adapter build --help" + c("  # onboard your first target", DIM))
    print("    ascend --help              " + c("# every command", DIM))
    print()
    print("  " + c("locked to one tenant at a time (ascend tenant)  ·  full guide in docs/", DIM))
    print()


def main(argv=None):
    raw = list(sys.argv[1:] if argv is None else argv)
    if "--version" in raw and not [a for a in raw if not a.startswith("-")]:
        print(VERSION)
        return
    # Bare `ascend` on a terminal -> the launch home screen. Non-TTY / piped / --json fall through
    # to argparse (unchanged), so scripts and agents behave exactly as before.
    if (not [a for a in raw if not a.startswith("-")] and sys.stdout.isatty()
            and not _wants_json() and "-h" not in raw and "--help" not in raw):
        _launch_screen()
        return
    args = build_parser().parse_args(raw)
    _reapply_globals(args, raw)
    args.func(args)


def _run():
    """Entry point with a human error boundary — a CLI must never print a traceback."""
    try:
        main()
    except SystemExit:
        raise
    except KeyboardInterrupt:
        print("\naborted", file=sys.stderr)
        raise SystemExit(130)
    except Exception as e:  # noqa: BLE001 - deliberate catch-all at the boundary
        name = type(e).__name__
        msg = str(e)
        hint = ""
        low = msg.lower()
        if ("401" in msg or "unauthorized" in low or "invalid_token" in low
                or "invalid_grant" in low or "revoked" in low or "token exchange failed" in low):
            hint = ("\n  your PAT was rejected. Generate a fresh one in the Straiker "
                    "console and re-export STRAIKER_PAT.")
        elif "403" in msg or "forbidden" in low:
            hint = "\n  the token is valid but lacks scope (need ascend:read / ascend:write)."
        elif "404" in msg:
            hint = "\n  not found — check the app id/name with `ascend app list`."
        elif any(k in low for k in ("connection", "timed out", "timeout", "resolve", "network")):
            hint = ("\n  could not reach the API. Check connectivity/proxy, or override "
                    "with --base / $STRAIKER_API_BASE.")
        if _wants_json():
            _err_json(msg or name, code=name, exit_code=EXIT_ERROR, hint=hint.strip())
        print(f"error: {msg or name}{hint}", file=sys.stderr)
        raise SystemExit(EXIT_ERROR)


if __name__ == "__main__":
    _run()
