#!/usr/bin/env python3
"""
gen_command_map.py — generate the command REFERENCE from the CLI's own argparse tree.

The reference used to be hand-maintained (and lived outside the repo), so it drifted the moment a
command changed. This introspects the real parser instead: every command, every flag, its value
placeholder, its default, its choices, whether it is required, and the help text — all read from
the parser that actually runs. Regenerate, commit, done. A test asserts the committed files match
fresh output, so a new flag cannot ship undocumented.

Section order and grouping come from `ascend.LIFECYCLE_HELP`, the same block that `ascend --help`
prints, so the docs and the CLI's own menu cannot disagree about what exists or where it belongs.

    python3 scripts/gen_command_map.py            # write docs/COMMAND_MAP.md + docs/command-map.html
    python3 scripts/gen_command_map.py --check    # exit 3 if they are stale (CI/test)
"""
from __future__ import annotations

import argparse
import html
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "control"))
sys.path.insert(0, str(REPO / "runtime"))
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "shells" / "cli"))

HTML_OUT = REPO / "docs" / "command-map.html"
MD_OUT = REPO / "docs" / "COMMAND_MAP.md"

# Flags every command inherits. Documented once instead of repeated on all ~43 commands.
GLOBAL_FLAGS = {"--json", "--token", "--base", "--bridge-base", "-h", "--help"}


# ---------------------------------------------------------------------------------------------
# read the parser
# ---------------------------------------------------------------------------------------------

def _flag_rows(parser):
    """Every option and positional on a parser, as documentation rows."""
    opts, positionals = [], []
    for a in parser._actions:
        if isinstance(a, argparse._SubParsersAction):
            continue
        if a.help == argparse.SUPPRESS:
            continue
        names = list(a.option_strings)
        if not names:                                    # a positional
            positionals.append({
                "name": a.metavar or a.dest,
                "help": (a.help or "").strip(),
                "required": a.nargs not in ("?", "*"),
                "choices": list(a.choices) if a.choices else [],
            })
            continue
        if set(names) & GLOBAL_FLAGS:
            continue
        # What the flag takes: a value placeholder, or nothing for a switch.
        if a.nargs == 0 or isinstance(a, (argparse._StoreTrueAction, argparse._StoreFalseAction)):
            value = ""
        elif a.choices:
            value = "|".join(str(c) for c in a.choices)
        else:
            value = a.metavar or a.dest.upper()
        # `is` comparisons, not `in (None, False)`: in Python `0 == False`, so an int default of
        # 0 (e.g. --limit 0 meaning "no cap") would silently render as "no default".
        default = a.default
        if default is None or default is False or default == [] or default == "":
            default = ""
        elif isinstance(a, argparse._AppendAction):
            default = ""
        opts.append({
            "names": names,
            "value": value,
            "default": "" if default == "" else str(default),
            "required": bool(a.required),
            "repeatable": isinstance(a, argparse._AppendAction),
            "help": (a.help or "").strip(),
        })
    return positionals, opts


def _clean(text):
    return re.sub(r"\s*\n\s*", " ", (text or "").strip())


def _examples(parser):
    """Pull the worked examples out of a command's epilog."""
    ep = (parser.epilog or "").strip()
    if not ep:
        return [], ""
    lines = ep.splitlines()
    cmds, notes = [], []
    for ln in lines:
        st = ln.strip()
        if not st or st.lower().startswith("examples"):
            continue
        if st.startswith("ascend ") or (cmds and (ln.startswith("      ") or ln.startswith("\t"))):
            cmds.append(ln.rstrip())
        else:
            notes.append(st)
    return cmds, " ".join(notes)


def build_tree():
    """{group: {"help","desc","verbs":{verb:{...}},"aliases":[...], "flags":...}} from the parser."""
    import ascend
    parser = ascend.build_parser()
    groups = {}
    subaction = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))

    by_id = {}
    for name, sub in subaction.choices.items():
        by_id.setdefault(id(sub), []).append(name)

    for name, sub in subaction.choices.items():
        canonical = by_id[id(sub)][0]
        if name != canonical:                            # this name is an alias
            continue
        aliases = [n for n in by_id[id(sub)] if n != canonical]
        entry = {"name": canonical, "aliases": aliases,
                 "help": _clean(_group_help(subaction, canonical)),
                 "desc": _clean(sub.description), "verbs": {}}
        inner = [a for a in sub._actions if isinstance(a, argparse._SubParsersAction)]
        if inner:
            vb = inner[0]
            vseen = {}
            for vname, vsub in vb.choices.items():
                vseen.setdefault(id(vsub), []).append(vname)
            for vname, vsub in vb.choices.items():
                vcanon = vseen[id(vsub)][0]
                if vname != vcanon:
                    continue
                pos, opts = _flag_rows(vsub)
                ex, note = _examples(vsub)
                entry["verbs"][vcanon] = {
                    "aliases": [n for n in vseen[id(vsub)] if n != vcanon],
                    "help": _clean(_group_help(vb, vcanon)),
                    "desc": _clean(vsub.description), "positionals": pos, "options": opts,
                    "examples": ex, "notes": note,
                    "hidden": _group_help(vb, vcanon) is None,
                }
        else:
            pos, opts = _flag_rows(sub)
            ex, note = _examples(sub)
            entry.update({"positionals": pos, "options": opts, "examples": ex, "notes": note})
        entry["hidden"] = _group_help(subaction, canonical) is None
        groups[canonical] = entry
    return groups, ascend.LIFECYCLE_HELP


def _group_help(subaction, name):
    """The help string argparse stored for a choice, or None when it was suppressed."""
    for ca in subaction._choices_actions:
        if ca.dest == name:
            return None if ca.help == argparse.SUPPRESS else (ca.help or "")
    return None


def sections_from_menu(menu):
    """Parse LIFECYCLE_HELP into [(section, [group, ...])] so docs follow the CLI's own order."""
    out, current = [], None
    for ln in menu.splitlines():
        if re.match(r"^  [A-Z][A-Z &]+$", ln):
            current = ln.strip()
            out.append((current, []))
        elif current and re.match(r"^    \S", ln):
            group = ln.strip().split()[0]
            if group not in out[-1][1]:
                out[-1][1].append(group)
    return out


# ---------------------------------------------------------------------------------------------
# markdown
# ---------------------------------------------------------------------------------------------

def _flag_table(rows, md=True):
    if not rows:
        return []
    out = ["", "| Flag | Value | Default | What it does |", "|---|---|---|---|"]
    for r in rows:
        flag = ", ".join(f"`{n}`" for n in r["names"])
        if r["required"]:
            flag += " **(required)**"
        if r["repeatable"]:
            flag += " *(repeatable)*"
        val = f"`{r['value']}`" if r["value"] else "—"
        dflt = f"`{r['default']}`" if r["default"] else "—"
        out.append(f"| {flag} | {val} | {dflt} | {_md_escape(r['help']) or '—'} |")
    return out


def _md_escape(s):
    return (s or "").replace("|", "\\|")


def _command_md(path, node):
    out = [f"### `ascend {path}`", ""]
    if node.get("aliases"):
        out.append(f"*Aliases: {', '.join('`' + a + '`' for a in node['aliases'])}*")
        out.append("")
    if node.get("hidden"):
        out.append("*Hidden from the menu (kept for compatibility); still supported.*")
        out.append("")
    body = node.get("desc") or node.get("help")
    if body:
        out += [body, ""]
    for p in node.get("positionals") or []:
        req = "required" if p["required"] else "optional"
        ch = f" One of: {', '.join('`' + c + '`' for c in p['choices'])}." if p["choices"] else ""
        out.append(f"- **`{p['name']}`** ({req}) — {_md_escape(p['help'])}{ch}")
    if node.get("positionals"):
        out.append("")
    out += _flag_table(node.get("options") or [])
    if node.get("examples"):
        out += ["", "```bash"] + [e.strip() if e.strip().startswith("ascend") else e
                                  for e in node["examples"]] + ["```"]
    if node.get("notes"):
        out += ["", f"> {node['notes']}"]
    out.append("")
    return out


def render_md(groups, menu):
    n_cmds = sum(max(1, len(g["verbs"])) for g in groups.values())
    out = [
        "# Ascend CLI — command reference",
        "",
        "*Generated from the CLI's argparse tree by `scripts/gen_command_map.py`. "
        "A test fails if this file is stale, so every flag here is a flag that exists.*",
        "",
        f"{len(groups)} command groups · {n_cmds} commands. Sections follow "
        "`ascend --help`.",
        "",
        "## Flags every command accepts",
        "",
        "| Flag | Value | What it does |",
        "|---|---|---|",
        "| `--json` | — | machine-readable output. Success is `{\"ok\":true,...}`, failure is "
        "`{\"ok\":false,\"error\":{...}}` — both on stdout, prose on stderr. |",
        "| `--token` | `TOKEN` | Straiker PAT (`s6r_pat_…`) or a JWT. Defaults to `$STRAIKER_PAT`. |",
        "| `--base` | `URL` | v3 API base. Defaults to `$STRAIKER_API_BASE`. |",
        "| `--bridge-base` | `URL` | bridge lease/result base. Defaults to `$STRAIKER_BRIDGE_URL`. |",
        "",
        "## Exit codes",
        "",
        "| Code | Meaning |",
        "|---|---|",
        "| `0` | success / clean |",
        "| `1` | tool or target error — including *could not read results*, never a pass |",
        "| `2` | findings gate failed (`ascend ci`) |",
        "| `3` | bad invocation (unknown control id, missing per-type field, malformed or unknown flag or command) |",
        "",
    ]
    placed = set()
    for section, names in sections_from_menu(menu):
        present = [n for n in names if n in groups]
        if not present:
            continue
        out += [f"## {section.title()}", ""]
        for name in present:
            placed.add(name)
            out += _group_md(name, groups[name])
    rest = [n for n in sorted(groups) if n not in placed]
    if rest:
        out += ["## Also available", "",
                "*Not in the menu — compatibility aliases and reference output.*", ""]
        for name in rest:
            out += _group_md(name, groups[name])
    return "\n".join(out).rstrip() + "\n"


def _group_md(name, g):
    out = [f"### `ascend {name}`" if not g["verbs"] else f"## `ascend {name}`", ""]
    if g["verbs"]:
        if g["aliases"]:
            out.append(f"*Aliases: {', '.join('`' + a + '`' for a in g['aliases'])}*")
            out.append("")
        if g["help"]:
            out += [g["help"], ""]
        for verb in sorted(g["verbs"]):
            out += _command_md(f"{name} {verb}", g["verbs"][verb])
        return out
    return _command_md(name, g)


# ---------------------------------------------------------------------------------------------
# html
# ---------------------------------------------------------------------------------------------

CSS = """
:root { --bg:#0b0c10; --panel:#0e1015; --fg:#e8e9ed; --dim:#9aa0aa; --line:#22242c;
        --accent:#FF5378; --mono:ui-monospace,SFMono-Regular,Menlo,monospace; }
:root[data-theme="light"] { --bg:#fbfbfc; --panel:#fff; --fg:#16181d; --dim:#5d626c;
        --line:#e3e5ea; }
@media (prefers-color-scheme: light) {
  :root:not([data-theme="dark"]) { --bg:#fbfbfc; --panel:#fff; --fg:#16181d; --dim:#5d626c;
        --line:#e3e5ea; }
}
* { box-sizing:border-box }
body { margin:0; background:var(--bg); color:var(--fg);
       font:15px/1.55 ui-sans-serif,-apple-system,"Helvetica Neue",Arial; }
.wrap { display:grid; grid-template-columns:250px minmax(0,1fr); gap:0; align-items:start }
nav { position:sticky; top:0; max-height:100vh; overflow-y:auto; padding:26px 16px 40px;
      border-right:1px solid var(--line); font-size:13px }
nav h2 { font-size:11px; letter-spacing:.09em; text-transform:uppercase; color:var(--dim);
         margin:18px 0 6px }
nav a { display:block; color:var(--fg); text-decoration:none; padding:2px 0; font-family:var(--mono) }
nav a:hover { color:var(--accent) }
main { padding:34px 30px 90px; min-width:0; max-width:1000px }
h1 { font-size:26px; margin:0 0 6px; letter-spacing:-.01em }
.sub { color:var(--dim); font-size:13px; margin-bottom:26px }
h2 { font-size:19px; margin:38px 0 10px; padding-bottom:6px; border-bottom:1px solid var(--line) }
h2 code, h3 code { color:var(--accent); font-family:var(--mono) }
h3 { font-size:15px; margin:26px 0 8px; font-family:var(--mono) }
p, li { color:var(--fg) }
.blurb { color:var(--dim); font-size:13.5px; margin:4px 0 10px }
.alias { color:var(--dim); font-size:12px; font-family:var(--mono) }
.hidden-note { color:var(--dim); font-size:12px; font-style:italic }
table { width:100%; border-collapse:collapse; font-size:13px; margin:10px 0 4px;
        display:block; overflow-x:auto; white-space:nowrap }
th { text-align:left; color:var(--dim); font-weight:600; font-size:11px; letter-spacing:.06em;
     text-transform:uppercase; padding:5px 12px 5px 0; border-bottom:1px solid var(--line) }
td { padding:5px 12px 5px 0; border-top:1px solid var(--line); vertical-align:top;
     white-space:normal }
td.f { font-family:var(--mono); white-space:nowrap; color:var(--fg) }
td.v, td.d { font-family:var(--mono); color:var(--dim); white-space:nowrap }
pre { background:var(--panel); border:1px solid var(--line); border-radius:2px; padding:11px 13px;
      overflow-x:auto; font-family:var(--mono); font-size:12.5px; margin:10px 0 }
.req { color:var(--accent); font-size:10px; letter-spacing:.05em }
.rep { color:var(--dim); font-size:10px }
blockquote { margin:10px 0; padding:8px 12px; border-left:2px solid var(--accent);
             background:var(--panel); color:var(--dim); font-size:13px }
footer { margin-top:46px; padding-top:14px; border-top:1px solid var(--line); color:var(--dim);
         font-size:12px }
@media (max-width:820px) {
  .wrap { grid-template-columns:1fr } nav { position:static; max-height:none; border-right:0;
  border-bottom:1px solid var(--line) } main { padding:22px 18px 60px }
}
"""


def _h(s):
    return html.escape(str(s or ""))


def _slug(s):
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")


def _cmd_html(path, node):
    out = [f'<h3 id="{_slug(path)}"><code>ascend {_h(path)}</code></h3>']
    if node.get("aliases"):
        out.append('<div class="alias">aliases: '
                   + ", ".join(_h(a) for a in node["aliases"]) + "</div>")
    if node.get("hidden"):
        out.append('<div class="hidden-note">Hidden from the menu (kept for compatibility); '
                   "still supported.</div>")
    body = node.get("desc") or node.get("help")
    if body:
        out.append(f'<p class="blurb">{_h(body)}</p>')
    pos = node.get("positionals") or []
    if pos:
        out.append("<table><tr><th>Argument</th><th></th><th></th><th>What it is</th></tr>")
        for p in pos:
            ch = (" One of: " + ", ".join(p["choices"]) + ".") if p["choices"] else ""
            req = '<span class="req">REQUIRED</span>' if p["required"] else ""
            out.append(f'<tr><td class="f">{_h(p["name"])}</td><td class="v">{req}</td>'
                       f'<td class="d">—</td><td>{_h(p["help"] + ch)}</td></tr>')
        out.append("</table>")
    opts = node.get("options") or []
    if opts:
        out.append("<table><tr><th>Flag</th><th>Value</th><th>Default</th>"
                   "<th>What it does</th></tr>")
        for r in opts:
            flag = ", ".join(r["names"])
            tags = ""
            if r["required"]:
                tags += ' <span class="req">REQUIRED</span>'
            if r["repeatable"]:
                tags += ' <span class="rep">repeatable</span>'
            out.append(f'<tr><td class="f">{_h(flag)}{tags}</td>'
                       f'<td class="v">{_h(r["value"]) or "—"}</td>'
                       f'<td class="d">{_h(r["default"]) or "—"}</td>'
                       f'<td>{_h(r["help"])}</td></tr>')
        out.append("</table>")
    if node.get("examples"):
        out.append("<pre>" + _h("\n".join(node["examples"])) + "</pre>")
    if node.get("notes"):
        out.append(f"<blockquote>{_h(node['notes'])}</blockquote>")
    return out


def render_html(groups, menu):
    n_cmds = sum(max(1, len(g["verbs"])) for g in groups.values())
    sections = sections_from_menu(menu)
    placed = {n for _, names in sections for n in names if n in groups}
    rest = [n for n in sorted(groups) if n not in placed]

    nav = ['<nav><h2>Reference</h2>',
           '<a href="#global">Global flags</a><a href="#exits">Exit codes</a>']
    body = []
    for section, names in sections:
        present = [n for n in names if n in groups]
        if not present:
            continue
        nav.append(f"<h2>{_h(section.title())}</h2>")
        body.append(f'<h2 id="{_slug(section)}">{_h(section.title())}</h2>')
        for name in present:
            nav.append(f'<a href="#{_slug(name)}">ascend {_h(name)}</a>')
            body += _group_html(name, groups[name])
    if rest:
        nav.append("<h2>Also available</h2>")
        body.append('<h2 id="also">Also available</h2>'
                    '<p class="blurb">Not in the menu — compatibility aliases and reference '
                    "output.</p>")
        for name in rest:
            nav.append(f'<a href="#{_slug(name)}">ascend {_h(name)}</a>')
            body += _group_html(name, groups[name])
    nav.append("</nav>")

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Ascend CLI — command reference</title>
<style>{CSS}</style></head>
<body><div class="wrap">
{''.join(nav)}
<main>
<h1>Ascend CLI — command reference</h1>
<div class="sub">{len(groups)} command groups · {n_cmds} commands · every flag, generated from the
CLI's own argparse tree. Sections follow <code>ascend --help</code>.</div>

<h2 id="global">Flags every command accepts</h2>
<table><tr><th>Flag</th><th>Value</th><th>What it does</th></tr>
<tr><td class="f">--json</td><td class="v">—</td><td>Machine-readable output. Success is
<code>{{"ok":true,…}}</code>, failure is <code>{{"ok":false,"error":{{…}}}}</code> — both on
stdout, prose on stderr.</td></tr>
<tr><td class="f">--token</td><td class="v">TOKEN</td><td>Straiker PAT
(<code>s6r_pat_…</code>) or a JWT. Defaults to <code>$STRAIKER_PAT</code>.</td></tr>
<tr><td class="f">--base</td><td class="v">URL</td><td>v3 API base. Defaults to
<code>$STRAIKER_API_BASE</code>.</td></tr>
<tr><td class="f">--bridge-base</td><td class="v">URL</td><td>Bridge lease/result base. Defaults
to <code>$STRAIKER_BRIDGE_URL</code>.</td></tr>
</table>

<h2 id="exits">Exit codes</h2>
<table><tr><th>Code</th><th>Meaning</th></tr>
<tr><td class="f">0</td><td>success / clean</td></tr>
<tr><td class="f">1</td><td>tool or target error — including <em>could not read results</em>,
which is never treated as a pass</td></tr>
<tr><td class="f">2</td><td>findings gate failed (<code>ascend ci</code>)</td></tr>
<tr><td class="f">3</td><td>bad invocation (unknown control id, missing per-type field,
malformed flag)</td></tr>
</table>

{''.join(body)}
<footer>Generated from the CLI's argparse tree by <code>scripts/gen_command_map.py</code>.
Regenerate after any command change — a test fails if this file is stale.</footer>
</main></div></body></html>
"""


def _group_html(name, g):
    if not g["verbs"]:
        return _cmd_html(name, g)
    out = [f'<h3 id="{_slug(name)}"><code>ascend {_h(name)}</code></h3>']
    if g["aliases"]:
        out.append('<div class="alias">aliases: ' + ", ".join(_h(a) for a in g["aliases"])
                   + "</div>")
    if g["help"]:
        out.append(f'<p class="blurb">{_h(g["help"])}</p>')
    for verb in sorted(g["verbs"]):
        out += _cmd_html(f"{name} {verb}", g["verbs"][verb])
    return out


# ---------------------------------------------------------------------------------------------

def main():
    check = "--check" in sys.argv
    groups, menu = build_tree()
    md, page = render_md(groups, menu), render_html(groups, menu)
    if check:
        stale = [p.name for p, want in ((MD_OUT, md), (HTML_OUT, page))
                 if not p.exists() or p.read_text() != want]
        if stale:
            print(f"stale (run scripts/gen_command_map.py): {', '.join(stale)}", file=sys.stderr)
            return 3
        print("command reference is current")
        return 0
    MD_OUT.parent.mkdir(parents=True, exist_ok=True)
    MD_OUT.write_text(md)
    HTML_OUT.write_text(page)
    n = sum(max(1, len(g["verbs"])) for g in groups.values())
    flags = sum(len(v.get("options") or []) for g in groups.values()
                for v in (g["verbs"].values() if g["verbs"] else [g]))
    print(f"wrote {MD_OUT.relative_to(REPO)} and {HTML_OUT.relative_to(REPO)} "
          f"({len(groups)} groups, {n} commands, {flags} documented flags)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
