"""
adaptor — the pure half of the custom-adaptor loop (`ascend adaptor ...`).

A custom ADAPTOR is one JavaScript file that teaches the Ascend engine how to hold a conversation
with a target whose auth or session cannot be written as a request/response template: a login, a
token mint, a conversation that has to be opened first, a reply you have to poll for. It runs on
the Straiker side, in an isolate the engine destroys after every turn, and it is stored on the
application as `request_template._adaptor_src` (minified, base64).

It is NOT an adapter in this CLI's sense. A CLI adapter (runtime/adapters/) runs on YOUR side,
behind the bridge, and the platform never sees its code. The two solve the same problem from
opposite ends of the wire, which is why they are spelled differently on purpose:

    adapter   your side, Python, behind the bridge        ascend target add / adapter build
    adaptor   the engine's side, JavaScript, on the app   ascend adaptor gate / test / store

docs/CUSTOM_ADAPTOR.md says which one to reach for.

Nothing in here touches the network or the terminal. The HTTP calls live in control/api.py and the
command bodies in shells/cli/ascend.py, so every rule below is testable on its own: which template
keys survive a store, what the reply shape has to be, and whether a scored reply is the answer or
the whole body stringified.
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# The one key the engine reads inline source from. The gate reports it as `templateKey`; this is
# the fallback for a gate payload that does not.
TEMPLATE_KEY = "_adaptor_src"
# The link-check adaptor a customer saves an app with. The engine refuses to assess an app still
# carrying it, so `store` replacing it is the expected path, and `verify` failing on it is correct.
PLACEHOLDER = "v0:passthrough"
# The https://custom-adaptor URL adaptor apps once carried. The engine no longer resolves it, so an
# adaptor stored on such an app would dial a dead address.
RETIRED_MARKER = "custom-adapt"
# A `v0:<name>` value is an ALIAS of an adaptor the engine ships; anything else is inline source.
ALIAS_PREFIX = "v0:"
# One benign prompt, the same one test-connection uses. A test must look like a user saying hello.
DEFAULT_PROMPT = "Hi, what can you help me with?"
DEFAULT_BUDGET_S = 120.0
# The engine's ceiling for one test/verify run. Checked locally so the error names the limit
# instead of coming back as a bare 422.
MAX_BUDGET_S = 240.0

_ENGINE_UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)

# Where the shipped JavaScript lives: the repo's templates/ in a checkout, the bundle root when
# frozen by PyInstaller (scripts/build_binary.sh adds templates/ to the bundle).
REPO = Path(__file__).resolve().parents[1]
_TEMPLATE_FILES = {"scaffold": "adaptor_scaffold.js", "example": "adaptor_example_chattie.js",
                   "login": "adaptor_login_scaffold.js"}


# ----------------------------------------------------------------------------- ids and budgets
def is_engine_uuid(ref: Any) -> bool:
    """The engine's application id: the uuid in the Console URL (…/applications/ascend/<this>).

    The platform's `aapp_…` token is an encrypted form of it that the engine cannot decode, so the
    adaptor routes (`get`, `test`, `verify`) 404 on it. Telling the two apart by shape is what lets
    the CLI explain that 404 instead of relaying it.
    """
    return bool(ref) and bool(_ENGINE_UUID.match(str(ref).strip()))


def check_budget(value: Any) -> Tuple[Optional[float], Optional[str]]:
    """(seconds, None) for a usable run budget, or (None, why) for one the engine would refuse."""
    if value is None:
        return DEFAULT_BUDGET_S, None
    try:
        b = float(value)
    except (TypeError, ValueError):
        return None, f"--budget must be a number of seconds, got {value!r}"
    if not (0 < b <= MAX_BUDGET_S):
        return None, f"--budget must be between 1 and {MAX_BUDGET_S:g} seconds, got {b:g}"
    return b, None


# ----------------------------------------------------------------------------- the template
def parse_template(raw: Any) -> Dict[str, Any]:
    """The app's request_template as a dict. The platform stores it as a JSON string.

    Raises ValueError when it is not JSON or not an object: an adaptor cannot be merged into a
    template that is not a dict, and silently replacing the whole thing would drop the prompt key.
    """
    if raw is None or raw == "":
        return {}
    if isinstance(raw, dict):
        return dict(raw)
    if not isinstance(raw, str):
        raise ValueError(f"request_template is a {type(raw).__name__}, not JSON text")
    if not raw.strip():
        return {}
    parsed = json.loads(raw)          # ValueError (JSONDecodeError) on bad JSON
    if not isinstance(parsed, dict):
        raise ValueError("request_template is JSON but not an object")
    return parsed


def template_for_display(tpl: Dict[str, Any]) -> Dict[str, Any]:
    """The template with the adaptor collapsed to its size: 2KB of base64 drowns everything else."""
    out = {}
    for k, v in (tpl or {}).items():
        if k == TEMPLATE_KEY and isinstance(v, str) and not v.startswith(ALIAS_PREFIX):
            out[k] = f"<{len(v)}b of base64>"
        else:
            out[k] = v
    return out


def is_inline_source(source: str) -> bool:
    return not (source or "").lstrip().startswith(ALIAS_PREFIX)


def address_problem(url: str, tpl: Dict[str, Any]) -> Optional[str]:
    """Why an adaptor stored on this app would have nowhere to go, or None.

    The adaptor's address is the application's URL — the target's real address, set in the
    Console — and `test`/`verify` take it from there, never from the request. Only an app with no
    URL falls back to `_adaptor_endpoint` in the template.
    """
    url = (url or "").strip()
    if RETIRED_MARKER in url:
        return ("this application's URL is the retired https://custom-adaptor marker, which the "
                "engine no longer resolves: the adaptor would dial it.\n  Set the URL to the "
                "target's address in the Console, then store again.")
    if not url and not (tpl or {}).get("_adaptor_endpoint"):
        return ("this application has no URL and no _adaptor_endpoint, so the adaptor would have "
                "nowhere to go.\n  Set the target's address as the application's URL in the "
                "Console, then store again.")
    return None


def dead_endpoint_keys(tpl: Dict[str, Any], url: str, inline: bool) -> Tuple[List[str], str]:
    """Endpoint keys in the template the engine would never read, and why.

    With a URL every one is dead (the URL is the address). Without one, a namespaced
    `_adaptor_<slug>_endpoint` is read only for a `v0:` alias, whose slug comes from the alias;
    inline source has no slug and reads the bare `_adaptor_endpoint` only.

    `store` keeps every template key it is given — it only ever adds `_adaptor_src` — so these are
    reported, out loud, rather than dropped: dead config that looks live is how a wrong address
    gets debugged somewhere far from the key.
    """
    keys = [k for k in (tpl or {})
            if k.lower().endswith("_endpoint") and k.lower().startswith(("_adaptor_", "_adapter_"))]
    if not keys:
        return [], ""
    if (url or "").strip():
        return keys, "the application's URL is the adaptor's address, so it is never read"
    if inline:
        dead = [k for k in keys if k.lower() != "_adaptor_endpoint"]
        return dead, ("namespaced endpoint keys are read only for a v0 alias, and this adaptor is "
                      "inline source")
    return [], ""


def merge_source(tpl: Dict[str, Any], key: str, value: str) -> Tuple[Dict[str, Any], List[str]]:
    """The template with the adaptor set, plus the notes worth saying out loud.

    Every existing key survives: the platform's PATCH replaces the whole `request_template`
    field, so "patch only `_adaptor_src`" means sending the merged template back, not a one-key
    body. The prompt key (`{{PROMPT}}`) in particular must stay, or the Console refuses to save
    the app's form afterwards.
    """
    key = key or TEMPLATE_KEY
    out = dict(tpl or {})
    notes = []
    if out.get(key) == PLACEHOLDER:
        notes.append(f"replacing the placeholder {PLACEHOLDER}: this app was waiting for its "
                     f"real adaptor")
    elif isinstance(out.get(key), str) and out.get(key) != value:
        notes.append(f"replacing the adaptor already stored under {key}")
    out[key] = value
    if not any("{{" in str(v) for k, v in out.items() if not k.startswith("_adaptor")):
        notes.append("no {{PROMPT}} key in the template; the Console will refuse to save edits "
                     "to this app until there is one")
    return out, notes


# ----------------------------------------------------------------------------- the record's basis
def record_digest(value: Any) -> Optional[str]:
    """sha-256 of a template value as the record holds it, first 12 hex: the gate's own recipe,
    over the base64 instead of the source.

    The gate's `digest` is of the stripped source and the engine's GET …/adapter prints a third;
    neither can be rebuilt from the application record. A ledger that compares a workspace copy
    of an adaptor against the record can only do it on the record's basis, so every verb that
    holds one states it, hashed here and nowhere else: `template_digest` over the gate's
    `templateValue` (the bytes a store writes) and `stored_digest` over `_adaptor_src` as it was
    read back afterwards — identical when the write landed, the placeholder's hash when it did
    not. None for anything but a non-empty string, so a value that was never read back prints as
    null, never as the hash of ''. Not trimmed: base64 carries no whitespace, and a value is
    hashed exactly as the record holds it.
    """
    if not isinstance(value, str) or not value:
        return None
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]


# ----------------------------------------------------------------------------- the reply shape
def reply_shape(response_template: Any) -> Optional[Dict[str, str]]:
    """Where the app's response_template expects the answer, and the return statement to write.

    The engine does not read the adaptor's reply directly: it applies the application's
    response_template to it, exactly as it would to a target's own response. A reply of the wrong
    shape does not error — parsed_response becomes a stringified object and a detector scores
    that. So this is the first thing to read, not the last.
    """
    try:
        shape = (json.loads(response_template) if isinstance(response_template, str)
                 and response_template.strip() else (response_template or {}))
    except ValueError:
        return None
    if isinstance(shape, str):
        if "RESPONSE" in shape:
            return {"path": "", "statement": "return { status_code: 200, body: text };"}
        return None

    def find(v, path=""):
        if isinstance(v, dict):
            for k, x in v.items():
                found = find(x, f"{path}.{k}" if path else k)
                if found is not None:
                    return found
        elif isinstance(v, list):
            # `{"choices": [{"message": {"content": "{{RESPONSE}}"}}]}` is the mirror
            # `target add` writes for an answer at choices.0.message.content; the statement has
            # to put the array back, or the engine's template matches nothing in the reply.
            for i, x in enumerate(v):
                found = find(x, f"{path}.{i}" if path else str(i))
                if found is not None:
                    return found
        elif isinstance(v, str) and "RESPONSE" in v:
            return path
        return None

    where = find(shape)
    if where is None:
        return None
    js = "text"
    for part in reversed(where.split(".")):
        js = f"[ {js} ]" if part.isdigit() else f"{{ {part}: {js} }}"
    return {"path": where, "statement": f"return {{ status_code: 200, body: {js} }};"}


# ----------------------------------------------------------------------------- the local lint
# What the publish gate refuses (docs/CUSTOM_ADAPTOR.md, "Rules the gate enforces"): the host is
# synchronous and sandboxed, so these identifiers are either a false affordance (`await` on a
# non-promise resolves immediately) or a capability that does not exist in the isolate. Checked
# on the source with comments stripped, because the JSDoc typedef legitimately says
# `import("./host")`. The engine's gate is the authority; this is the free check that runs before
# a network round trip, and the one the generated adaptors are tested against.
GATE_BANNED = ("async", "await", "Promise", "fetch", "XMLHttpRequest", "require", "import",
               "eval", "Function", "setTimeout", "setInterval", "setImmediate", "console",
               "process", "globalThis", "window", "document")
# Members the gate denies on any object: the prototype chain is how a sandboxed script reaches
# what it was not given. Measured: a generated adaptor was refused for `Object.prototype.toString`.
GATE_DENIED_MEMBERS = (".prototype", ".__proto__", ".constructor")
_SEND_TURN = re.compile(r"\bfunction\s+sendTurn\s*\(")
_EXPORTED = re.compile(r"^\s*(export|module\.exports)\b", re.M)


def strip_comments(source: str) -> str:
    """The source minus /* */ and // comments; string contents are kept (a banned word in a
    string is still refused by the gate's identifier check only when it is an identifier, but a
    generated file has no reason to say it anywhere)."""
    out = re.sub(r"/\*.*?\*/", "", source or "", flags=re.S)
    return re.sub(r"//[^\n]*", "", out)


def lint_source(source: str) -> List[str]:
    """Problems the publish gate would refuse this source for, as one line each; [] when clean.

    Mirrors the gate's rules on the operator's side: the banned identifiers, exactly one
    `function sendTurn(`, and no `export`/`module.exports` (the file is one plain script).
    """
    problems: List[str] = []
    code = strip_comments(source)
    for word in GATE_BANNED:
        m = re.search(rf"\b{re.escape(word)}\b", code)
        if m:
            line = code.count("\n", 0, m.start()) + 1
            problems.append(f"{word}: not available inside the isolate (line {line})")
    for member in GATE_DENIED_MEMBERS:
        m = re.search(re.escape(member) + r"\b", code)
        if m:
            line = code.count("\n", 0, m.start()) + 1
            problems.append(f"{member}: a denied member inside the isolate (line {line})")
    n = len(_SEND_TURN.findall(code))
    if n != 1:
        problems.append(f"exactly one `function sendTurn(turn, host)` is required; found {n}")
    if _EXPORTED.search(code):
        problems.append("no `export` or `module.exports`: the adaptor is one plain script")
    return problems


# ----------------------------------------------------------------------------- what a detector sees
def looks_unextracted(scored: Any) -> bool:
    """Did the pipeline stringify the body instead of reading through the template?

    The signature of the bug this exists for: `scored` comes out as a Python dict/list repr (or
    JSON text), which a detector then scores as if the target had said it.
    """
    s = str(scored or "").strip()
    return s.startswith(("{'", '{"', "[{", "['")) and s.endswith(("}", "]"))


def scored_problem(turn: Dict[str, Any]) -> Optional[str]:
    """`empty`, `unextracted`, or None when the scored text could be a real answer.

    None also when the engine did not send a `scored` field at all (an older engine), because
    then there is nothing to judge — the caller falls back to `parsed`.
    """
    if "scored" not in (turn or {}) or turn.get("scored") is None:
        return None
    s = str(turn.get("scored"))
    if not s.strip():
        return "empty"
    if looks_unextracted(s):
        return "unextracted"
    return None


def summarize_run(payload: Dict[str, Any]) -> Dict[str, Any]:
    """One verdict over a test/verify payload: did every step the engine ran come back healthy?

    `ok` is False for a refused gate, a failed preflight, a non-200 turn, a run with no turns at
    all, and — the one that does not look like a failure — a turn whose scored text is empty or
    the whole body stringified, because a detector would score that verbatim.
    """
    payload = payload or {}
    gate = payload.get("gate") or {}
    out: Dict[str, Any] = {"ok": True, "problems": [], "preflight": None, "turns": []}
    if gate and gate.get("ok") is False:
        out["ok"] = False
        out["problems"].append("refused by the gate; nothing ran")
        return out
    if "preflight" in payload:
        pre = payload.get("preflight")
        if pre is None:
            out["preflight"] = {"defined": False}
        else:
            pre_ok = pre.get("status_code") == 200
            out["preflight"] = {"defined": True, "ok": pre_ok, "status_code": pre.get("status_code"),
                                "ms": pre.get("ms")}
            if not pre_ok:
                out["ok"] = False
                out["problems"].append(
                    f"preflight (checkReachability) returned {pre.get('status_code')} — it would "
                    f"block the run before any probe")
    turns = payload.get("turns") or []
    for t in turns:
        status = t.get("status_code")
        problem = scored_problem(t)
        row = {"n": t.get("n"), "status_code": status, "ms": t.get("ms"),
               "ok": status == 200 and problem is None, "scored_problem": problem}
        out["turns"].append(row)
        if status != 200:
            out["ok"] = False
            out["problems"].append(f"turn {t.get('n')} returned {status}")
        if problem == "empty":
            out["ok"] = False
            out["problems"].append(f"turn {t.get('n')}: scored text is empty — a detector would "
                                   f"score NOTHING; the reply did not survive the app's "
                                   f"response_template")
        elif problem == "unextracted":
            out["ok"] = False
            out["problems"].append(f"turn {t.get('n')}: scored text is the whole body stringified "
                                   f"— the reply shape and the app's response_template disagree")
    # verify carries the engine's own verdict; it wins even when every turn above looked fine.
    if payload.get("ok") is False:
        out["ok"] = False
        out["problems"].append(payload.get("summary") or "the engine reported a failure")
    elif not turns and "ok" not in payload:
        out["ok"] = False
        out["problems"].append("no turns in the reply")
    return out


def violation_lines(gate: Dict[str, Any]) -> List[str]:
    out = []
    for v in (gate or {}).get("violations") or []:
        where = f" (line {v['line']})" if v.get("line") else ""
        out.append(f"REFUSED  {v.get('kind')}: {v.get('detail')}{where}")
    return out


def preflight_note(gate: Dict[str, Any]) -> Optional[str]:
    """Whether the gate found a checkReachability entry. None against an engine that does not
    report `entries` (it only ever calls sendTurn)."""
    entries = (gate or {}).get("entries")
    if entries is None:
        return None
    return ("checkReachability" if "checkReachability" in entries
            else "none - preflight spends one real sendTurn")


# ----------------------------------------------------------------------------- shipped JavaScript
def templates_dir() -> Path:
    meipass = getattr(sys, "_MEIPASS", None)
    return (Path(meipass) if meipass else REPO) / "templates"


def template_js(kind: str = "scaffold") -> str:
    """The scaffold (the onboarding adaptor) or the worked thin example, as shipped."""
    name = _TEMPLATE_FILES.get(kind)
    if not name:
        raise ValueError(f"no adaptor template called {kind!r}")
    path = templates_dir() / name
    try:
        return path.read_text(encoding="utf-8")
    except OSError as e:
        raise FileNotFoundError(f"the shipped adaptor template is missing ({path}): {e}")
