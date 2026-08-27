# Product surface: one core, three shells

**One core, exposed three ways, with zero logic duplication.**
Deterministic behaviour → CLI. Agent-invokable → MCP mirrors the CLI 1:1. Reasoning-heavy
workflow → a Skill orchestrates CLI/MCP (never reimplements them).

```
              ┌──────────────────────── core (this repo) ────────────────────────┐
              │  transport (v2 lease/term/browser) · runtime (compose adapters)   │
              │  control (v3 api, fixed lifecycle) · discovery (layer classifiers)│
              └───────────────▲───────────────▲───────────────▲──────────────────┘
                              │               │               │
                   CLI (deterministic)   MCP (typed tools)   Skills (reasoning)
                   scriptable, --help    for any agent host  SKILL.md workflows
```

## CLI: `ascend <group> <verb>`, full --help everywhere
- **app**: create --type bridge|api|gcp|bedrock (default bridge; returns the bridge key) · list · get · bind · delete
- **assess**: run · status · pause · resume · results · list   (lifecycle: created→pause→resume)
- **controls**: list (filter deprecated/agentic/category; warn on zero-probe)
- **runtime**: start   (v2 pull-mode; --capture, --qpm, --max-workers)
- **discover**: har|url|capture → per-layer classification → draft config (+confidence+evidence)
- **adapter**: validate(hard gate) · list · show · layers(introspect capability matrix)
- **ci**: nonzero on new findings / severity breach; baseline diff
- **doctor**: preflight (key scopes, reachability, egress/proxy, tmux/deps, control sanity)

## MCP: thin passthrough (optional / deferred)
CLI and skills are the primary surfaces. MCP is a thin wrapper that execs the same CLI verbs
with `--json` (or imports the same core). It is used only for hosts without a shell (Cowork,
claude.ai web, locked-down enterprise) or for remote/hosted org-wide deployment. For
shell-having agents (Claude Code, Codex, Cursor) the agent calls `ascend <verb> --json`
directly. MCP would only add tool-definition token overhead (4–32x vs a CLI call). Every CLI
command emits `--json`. MCP is an auto-generated 1:1 shim added later if a shell-less host
needs it, never a v1 priority and never a second implementation.

## Skills: reasoning workflows (Claude Code plugin)
- **build-adapter**: drive `discover` → resolve low-confidence layers with judgment → `adapter
  validate` → iterate. Determinism in the CLI; reasoning only on the ambiguous layers.
- **onboard-target**: map → build-adapter → app create → adapter validate → first run.
- **run-assessment**: choose controls/strategies → run → monitor → summarize.
- **triage-findings**: FP triage, auth-gating severity recalc, STAR framing.
- **report**: brand-consistent readout (reuses existing ascend-report).

## Distribution (all from one repo)
CLI → pip/standalone binary (primary) · Skills → Claude Code plugin marketplace · MCP → optional thin shim (exec CLI --json) for shell-less hosts.
