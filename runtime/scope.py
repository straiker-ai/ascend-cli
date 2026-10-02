"""Propose which of Ascend's controls fit what a target IS — and say why.

A single probe is not a coverage claim, and the surface worth testing depends on what the target
can do: a retrieval bot's risk is grounding and data leakage; a bot with tools adds tool misuse;
one that can run code adds code execution; one that holds user data adds exfiltration. The
operator picks the scope today. This maps discovered capabilities to a proposed control scope with
a one-line reason each, so the assessment covers the surface that exists instead of a default.

Deterministic and read-only: it recommends, it does not start anything. The control ids are the
live catalog's (see the `controls` knowledge topic); a name the catalog does not carry is dropped
by the caller, never invented here. `propose(capabilities)` takes a dict of booleans/flags and
returns ``{scope: [{control, why}], baseline: [...], notes: [...]}``.

`resolve(names, catalog)` then maps those names onto a LIVE catalog (`ascend controls list
--json`): an exact control id is kept, a category name expands to its active controls, a stem
or alias match is reported with the match it made, and anything the tenant does not carry is
listed as unknown rather than passed on. The proposal is a prior; the catalog is the truth.
"""
from __future__ import annotations

from typing import Any, Dict, List

# Baseline: every conversational target, whatever it is. sys_prompt_leak and a jailbreak/prompt
# injection probe are the floor — they need no special capability.
BASELINE = [
    ("sys_prompt_leak", "every agent has a system prompt; leaking it is the first thing to test"),
    ("jailbreak", "instruction-manipulation resistance is a floor for any conversational target"),
]

# capability flag -> [(control_id, why)]. Flags are matched loosely (any truthy of the aliases).
_CAP_RULES: List[Dict[str, Any]] = [
    {"aliases": ("rag", "research", "retrieval", "knowledge", "search", "grounding"),
     "controls": [("app_grounding", "a retrieval/RAG bot can be pushed off its grounding — test that it stays on-source"),
                  ("data_leak", "retrieval surfaces let a bot disclose data it should not — test for leakage")]},
    {"aliases": ("tools", "agentic", "tool", "function_calling", "actions"),
     "controls": [("agentic_tmu", "an agent with tools can be steered into misusing them — tool-misuse assessment")]},
    {"aliases": ("code", "code_interpreter", "shell", "exec", "sandbox", "repl"),
     "controls": [("agentic_rce", "an agent that can run code is where code-execution abuse is meaningful")]},
    {"aliases": ("memory", "user_data", "pii", "crm", "profile", "database", "db", "records"),
     "controls": [("agentic_data_exfil", "an agent with access to user data or memory can be driven to exfiltrate it"),
                  ("data_leak", "a target holding personal or internal data must be tested for leakage")]},
    {"aliases": ("browser", "web", "fetch", "url", "link"),
     "controls": [("indirect_prompt_injection", "a bot that fetches web content can be hijacked by content it reads")]},
    {"aliases": ("file", "upload", "attachment", "document"),
     "controls": [("indirect_prompt_injection", "a bot that reads uploaded files can be hijacked by their contents")]},
    {"aliases": ("sub_agent", "sub_agents", "multi_agent", "orchestrator", "handoff"),
     "controls": [("agentic_tmu", "a bot that delegates to sub-agents widens the tool-misuse surface")]},
]


def _canon(text: str) -> str:
    # fold separators so 'user data', 'user-data' and 'user_data' all match the alias 'user_data'
    return "".join(c if c.isalnum() else "_" for c in str(text).lower())


def _flagged(capabilities: Dict[str, Any], aliases) -> bool:
    for key, val in (capabilities or {}).items():
        if any(a in _canon(key) for a in aliases) and val not in (None, False, 0, "", "false", "no", "none"):
            return True
    return False


def _flagged_any(capabilities: Any, aliases) -> bool:
    if isinstance(capabilities, dict):
        return _flagged(capabilities, aliases)
    if isinstance(capabilities, (list, tuple, set)):
        blob = "_".join(_canon(x) for x in capabilities)
        return any(a in blob for a in aliases)
    return any(a in _canon(capabilities) for a in aliases)


def propose(capabilities: Any) -> Dict[str, Any]:
    """Proposed control scope for a target with these capabilities. Deterministic, additive, de-duped."""
    scope: List[Dict[str, str]] = []
    seen = set()

    def add(control: str, why: str) -> None:
        if control not in seen:
            seen.add(control)
            scope.append({"control": control, "why": why})

    matched: List[str] = []
    for rule in _CAP_RULES:
        if _flagged_any(capabilities, rule["aliases"]):
            matched.append(rule["aliases"][0])
            for control, why in rule["controls"]:
                add(control, why)

    baseline = [{"control": c, "why": w} for c, w in BASELINE]
    notes: List[str] = []
    if not matched:
        notes.append("no agentic capabilities discovered — the baseline is the honest scope; run recon or "
                     "ask the operator what the target can do before widening")
    else:
        notes.append("capabilities matched: " + ", ".join(matched))
    notes.append("proposed names are catalog categories or controls — confirm them against the live catalog "
                 "before registering; a name the tenant does not carry is dropped, not invented")
    notes.append("a small run on each control proves interaction; widen only after the baseline is clean and "
                 "the answer rate is real — a single probe is never a coverage claim")
    return {"scope": scope, "baseline": baseline, "matched": matched, "notes": notes}


# What a proposed name may be called in a live catalog. Catalogs differ between tenants and
# product versions; these are the stems seen so far, lowest-confidence last.
_ALIASES: Dict[str, List[str]] = {
    "jailbreak": ["jailbreak", "prompt_injection", "llm_evasion", "evasion"],
    "app_grounding": ["app_grounding", "grounding", "hallucination", "off_topic", "business_risk"],
    "data_leak": ["data_leak", "data_leakage", "pii", "sensitive_data"],
    "agentic_tmu": ["agentic_tmu", "tool_misuse", "agentic_risks", "agent_vulnerabilities"],
    "agentic_rce": ["agentic_rce", "code_execution", "rce"],
    "agentic_data_exfil": ["agentic_data_exfil", "data_exfil", "exfiltration"],
    "indirect_prompt_injection": ["indirect_prompt_injection", "indirect_injection", "prompt_injection", "llm_evasion"],
    "sys_prompt_leak": ["sys_prompt_leak", "system_prompt_leak", "prompt_leak"],
}
_CATEGORY_CAP = 8     # a category expands to at most this many controls; the rest are named


def _catalog_lists(catalog: Any):
    """(controls, categories) from the shapes the CLI and the platform emit."""
    if isinstance(catalog, dict) and isinstance(catalog.get("result"), dict):
        catalog = catalog["result"]
    if isinstance(catalog, dict):
        controls = catalog.get("controls") or []
        categories = catalog.get("categories") or []
    elif isinstance(catalog, list):
        controls, categories = catalog, []
    else:
        controls, categories = [], []
    controls = [c for c in controls if isinstance(c, dict) and c.get("id")]
    categories = [g for g in categories if isinstance(g, dict) and g.get("id")]
    return controls, categories


def resolve(names: Any, catalog: Any) -> Dict[str, Any]:
    """Map proposed control/category names onto a live catalog. Deterministic, read-only.

    Returns ``{controls: [live ids], resolved: [{proposed, kind, ids, label, via}], unknown: [...],
    catalog_seen: bool}``. ``kind`` is ``control`` (exact), ``category`` (expanded to its active
    controls), ``alias`` (a stem match, says what it matched) or ``unknown``. Fail-open: with no
    usable catalog, ``controls`` is the input unchanged and ``catalog_seen`` is False.
    """
    wanted = [str(n) for n in (names or []) if str(n).strip()]
    controls, categories = _catalog_lists(catalog)
    if not controls and not categories:
        return {"controls": wanted, "resolved": [], "unknown": [], "catalog_seen": False,
                "note": "no catalog to resolve against — the names are passed through unchanged; "
                        "confirm them with ascend_controls_validate before registering"}
    active = [c for c in controls if not c.get("deprecated")]
    by_id = {str(c["id"]): c for c in active}
    cat_by_id = {str(g["id"]): g for g in categories}

    def _members(cat_id: str) -> List[str]:
        ids = [str(c["id"]) for c in active if str(c.get("category_id") or "") == cat_id]
        g = cat_by_id.get(cat_id) or {}
        for cid in g.get("control_ids") or []:
            if str(cid) in by_id and str(cid) not in ids:
                ids.append(str(cid))
        return ids

    def _stem_hits(stem: str):
        stem_c = _canon(stem)
        hit_controls = [str(c["id"]) for c in active
                        if stem_c and (stem_c in _canon(c["id"]) or stem_c in _canon(c.get("name") or ""))]
        hit_cats = [str(g["id"]) for g in categories
                    if stem_c and (stem_c in _canon(g["id"]) or stem_c in _canon(g.get("name") or ""))]
        return hit_controls, hit_cats

    out_ids: List[str] = []
    resolved: List[Dict[str, Any]] = []
    unknown: List[str] = []

    def _take(ids: List[str]) -> List[str]:
        fresh = [i for i in ids if i not in out_ids]
        out_ids.extend(fresh)
        return fresh

    for name in wanted:
        key = _canon(name)
        if name in by_id:
            resolved.append({"proposed": name, "kind": "control", "ids": _take([name]),
                             "label": by_id[name].get("name") or name, "via": "exact id"})
            continue
        if name in cat_by_id:
            members = _members(name)
            resolved.append({"proposed": name, "kind": "category", "ids": _take(members[:_CATEGORY_CAP]),
                             "label": cat_by_id[name].get("name") or name, "via": "category id",
                             "members": len(members)})
            continue
        found = False
        for stem in _ALIASES.get(key, [key]):
            if stem in by_id:
                resolved.append({"proposed": name, "kind": "alias", "ids": _take([stem]),
                                 "label": by_id[stem].get("name") or stem, "via": f"alias {stem!r} is a control id"})
                found = True
                break
            if stem in cat_by_id:
                members = _members(stem)
                resolved.append({"proposed": name, "kind": "category", "ids": _take(members[:_CATEGORY_CAP]),
                                 "label": cat_by_id[stem].get("name") or stem, "via": f"alias {stem!r} is a category",
                                 "members": len(members)})
                found = True
                break
            hc, hg = _stem_hits(stem)
            if hc:
                resolved.append({"proposed": name, "kind": "alias", "ids": _take(hc[:_CATEGORY_CAP]),
                                 "label": ", ".join(hc[:3]), "via": f"stem {stem!r} matches control(s)"})
                found = True
                break
            if hg:
                members = []
                for cid in hg:
                    members.extend(m for m in _members(cid) if m not in members)
                resolved.append({"proposed": name, "kind": "category", "ids": _take(members[:_CATEGORY_CAP]),
                                 "label": ", ".join(cat_by_id[c].get("name") or c for c in hg[:2]),
                                 "via": f"stem {stem!r} matches categor{'y' if len(hg) == 1 else 'ies'}",
                                 "members": len(members)})
                found = True
                break
        if not found:
            unknown.append(name)
            resolved.append({"proposed": name, "kind": "unknown", "ids": [], "label": "",
                             "via": "no control or category in this tenant's catalog matches"})
    return {"controls": out_ids, "resolved": resolved, "unknown": unknown, "catalog_seen": True}
