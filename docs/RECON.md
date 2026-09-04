# Reconnaissance

Reconnaissance is a run of its own. In the Console it lives on the **Reconnaissance** tab and is
started separately from an assessment: Iris asks the target what it *can do* — which tools it has,
what data it can reach, how its guardrails behave, what it renders, whether sub-agents exist — and
records which capabilities it confirmed. A confirmed capability is the surface an assessment should
then attack. The five categories are Architecture, General, I/O Handling, PII Discovery and Tool
Reconnaissance; `ascend recon controls` lists them with their controls.

The CLI gives that one noun and one decision:

```bash
ascend recon run --app 'My Bot'                                   # recon only
ascend assess run --app 'My Bot' --name r1 --with-recon           # recon to completion, then the attack run
ascend assess run --app 'My Bot' --name r1                        # attack run only (the default)
ascend assess run --app 'My Bot' --name r1 --recon-only           # the same as `recon run`
```

`--recon-controls` scopes which recon controls run (default: the whole recon catalog). Recon runs
one app at a time, to completion, before any attack probe is scheduled — a fleet with `--with-recon`
recons each app first.

Reading it back:

```bash
ascend recon list --app 'My Bot'            # every recon run on the app
ascend recon show --app 'My Bot'            # the latest run in detail (or --recon <id>)
ascend recon results --app 'My Bot'         # confirmed capabilities across runs, by category
```

Every recon verb honours `--json`.

## What "found" means

A recon control is a goal — "does this agent have a database tool?" — pursued over a few turns. The
result is **found** when the target's behaviour confirmed the capability, and a miss otherwise. A
miss is not a pass: it means the capability is absent, or the target resisted discovery. Multi-turn
agentic tools are often invisible to automated recon; a HAR of real traffic still finds what recon
did not (`docs/DISCOVERY.md`).

## Platform status

The public v3 API does not expose reconnaissance yet; today only the Console runs it. Every recon
verb goes through one seam, so on such a tenant the CLI says exactly that and exits 1:

```
error: recon: reconnaissance is not exposed by the Ascend API on this tenant yet. The Console's
Reconnaissance tab runs it today. This command lights up when the platform ships
`/ascend/applications/{id}/recon`; nothing else about it changes.
```

Under `--json` the error code is `recon_unavailable`. The paths the CLI expects, mirroring the
Console's own recon client:

| CLI | expected v3 path |
|---|---|
| `recon controls` | `GET /ascend/recon/controls` |
| `recon run` | `POST /ascend/applications/{id}/recon` `{name, controls}` → `{id, status}` |
| `recon list` | `GET /ascend/applications/{id}/recon` → `{recon_requests: [...]}` |
| `recon show` | `GET /ascend/applications/{id}/recon/{recon_id}` → status, tasks, `control_summaries`, `category_summaries` |
| `recon results` | `GET /ascend/applications/{id}/recon/results` → `controls`, `matched_controls`, `category_summaries` |

Field names follow the Console's recon schemas (`status`, `total_tasks`, `completed_tasks`,
`matched_tasks`, `control_summaries[].goal_matched`, `summarized_recon_structured`).
