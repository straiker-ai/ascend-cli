# Driving the Ascend CLI from an agent (or a script)

The CLI is the API. An agent (Claude Code in a terminal, a CI job, a bot) can read state, act, and
recover without parsing English.

## The contract

```bash
ascend status --json           # tenant + apps + live runs + bridges, in ONE call
ascend reports --json          # assessment-level results (platform rollups)
ascend results run.csv --json  # turn-level results from a Console export
ascend bridge ls --json        # who is serving what
```

**Success** is `{"ok": true, "data": …}` on stdout. **Failure** is also JSON on stdout:

```json
{"ok": false, "error": {"code": "usage", "message": "config not found: mybot",
                        "hint": "did you mean: my-bot", "exit_code": 3}}
```

Human-readable prose always goes to **stderr**, machine output to **stdout**, so redirecting one
never corrupts the other. Progress spinners are stderr-only and disable themselves entirely under
`--json`.

## Exit codes (stable)

| Code | Meaning | What an agent should do |
|---|---|---|
| `0` | success / clean | continue |
| `1` | tool or target error, including **"could not read results"** | do not treat as a pass; investigate |
| `2` | findings gate failed | report the findings |
| `3` | bad invocation | fix the arguments, don't retry blindly |

`1` and `2` differ: "the target is unreachable" and "the target answered badly" require
different responses.

## Retrying safely

Some operations create things. These are the idempotent forms:

```bash
ascend app create --name 'My Bot' --controls sys_prompt_leak --if-not-exists
ascend bridge start --app 'My Bot'        # refuses to double-start; reports the existing pid
ascend keys add --app 'My Bot' --key tc-…   # upsert, last write wins
ascend app bind mybot --app 'My Bot'     # merges, safe to repeat
```

Without `--if-not-exists`, a retried create leaves **two apps with the same name**. That makes
every later name-based command ambiguous and orphans the first app's `tc-` key (the API shows it
exactly once). `assess pause`/`resume` are already safe to repeat.

## The standard loop

```bash
ascend status --json                                    # 1. read state
ascend adapter build --api "$URL" --bearer "$TOK" --out bot.json  # 2. get a VALIDATED config
ascend app create --name Bot --config bot --controls sys_prompt_leak --if-not-exists
ascend assess run --app Bot --name 'run 1'              # 3. run — auto-starts the bridge for a
                                                        #    bridge-type app, self-stops at the end
ascend assess watch --all --json                        # 4. follow (NDJSON, one object per tick)
ascend reports --app Bot --detail --json                # 5. read results
ascend ci --app Bot --assessment "$AID" --fail-on-severity high   # 6. decide
```

`assess run` auto-manages the bridge, so there is no manual serve step. If run state changed in the
Console (a Console-side pause/resume), reconcile with `ascend bridge sync` (start for running/paused
apps, stop for terminal); `ascend assess resume` re-ensures a bridge on its own.

Every step is checkable: `map` refuses to write an unvalidated config, `bridge ls` tells you if a
run has **no** bridge, and `reports --detail` flags a suspiciously clean result.

## What the CLI decides, and what it leaves to you

This determines what you can trust from `ascend results` in an automated pipeline, and what you
must still judge.

**The CLI is deterministic and does not exercise judgement.** It counts, groups, extracts, and
reports the platform's own flags. It never suppresses, reclassifies, or re-scores a finding.

| Mechanical: the CLI answers it | Judgement: you answer it |
|---|---|
| Did this value appear in a response? | Is it sensitive for *this* customer? |
| Was it also in the prompt (an echo)? | Is this finding a false positive? |
| Did the target answer this probe at all? | What severity does the impact justify? |
| Which evasion technique succeeded most? | Was the capability demonstrated or just present? |
| Did the platform flag the turn as a guardrail FP? | Should the report count it? |

Concretely: the CLI will tell you a phone number appeared in 16 responses and in **zero** prompts
(`values[].from_target: 16`, `values[].echoed: 0`). It will not tell you that the number is the
company's published support line and therefore not a finding. That call needs context the CLI does
not have, and a heuristic guessing at it would silently change a number on its way into a report.

The rules for making that call live in [`../agent/TRIAGE.md`](../agent/TRIAGE.md), prompt material
kept outside the CLI's code. Point an agent at that file plus `ascend results --json`.

## Reading turn-level results

`ascend results <file>` takes a Console CSV export or a local capture and detects which it is.

```bash
ascend results run.csv --json | jq '.data.totals'
ascend results run.csv --json | jq '.data.by_evasion[:5]'      # what actually worked
ascend results run.csv --json | jq '.data.values[] | select(.from_target > 0)'
ascend results run.csv --no-catalog --json                     # fully offline, raw ids
```

Fields worth knowing:

| Field | Meaning |
|---|---|
| `totals.probes` | rows in the export — prompts sent |
| `totals.answered` | probes the target actually replied to (HTTP 200 **and** a pass/fail verdict) |
| `totals.unanswered` | probes that errored or came back `unknown`, **not passes** |
| `totals.failure_rate_pct` | failures over **answered**, not over probes |
| `by_risk` / `by_category` | the platform's own taxonomy and Security/Safety/Trust tags |
| `by_evasion` | success rate per evasion technique |
| `confusion` | TP/FP/FN/TN from the platform's own FP/FN columns, plus precision/recall/ASR |
| `values[]` | disclosed values with mechanical provenance |
| `warnings[]` | anything that changes how the numbers should be read |
| `source.taxonomy` | `platform` if the control catalog was reachable, `raw-ids` if not |

Two units traps, both of which produce wrong statements if missed:

1. **Probes are not findings.** `totals.failed` counts adversarial *prompts* that achieved
   something. `reports --detail`'s `findings` counts failed *controls*. They are different units and
   will not match.
2. **Unanswered probes are not passes.** On real exports this is routinely 30–43% of a run. The
   failure rate is computed over `answered` for this reason; if `unanswered` is high, the run
   under-measured.

## Pitfalls

1. **A run with no bridge still completes and looks clean.** Unanswered probes are not findings, so
   the score can be `0 / low` from measuring nothing. `assess run` auto-starts the bridge, so this
   normally can't happen, but it still can when auto-management is off, the run started from the
   Console, or a remote/pre-started bridge died. Confirm a bridge is serving
   (`ascend status --json` → `live[].bridge_serving`, or `bridge ls`), and `ascend bridge sync` to
   reconcile. This is the most important check in the tool.
2. **Pause is not immediate.** Probes are generated up front; pausing stops new scheduling while
   in-flight probes drain, so the target keeps receiving prompts for a while. See
   [ASSESSMENT_LIFECYCLE.md](ASSESSMENT_LIFECYCLE.md).
3. **`onboard --json` returns instead of holding the bridge open.** Use `bridge start` for a durable
   bridge; `onboard` without `--json` keeps one in the foreground for interactive use.
4. **One tenant per machine.** The CLI pins itself to the first tenant it sees and refuses another
   PAT (`ascend tenant show`). This stops customer material from crossing.
5. **`tc-` keys are shown once.** They're stored automatically by `app create`/`onboard`; if a
   create response lacks one, the command fails rather than storing nothing.
6. **Long calls are slow.** There is no tenant-wide assessments endpoint, so anything
   "across all apps" is one call per app (parallelised). `--quick` on `status` skips that scan.
7. **There is no per-turn results endpoint.** The deepest programmatic read is the assessment detail
   (category/control rollups). Turn-level data (prompt, response, the technique that worked, the
   platform's reason) comes only from a Console CSV export, which is why `ascend results` takes a
   file. DataBridge currently publishes only a `defend.turn` source; there is no `ascend.turn` yet.
8. **`controls validate` exits 3 on an unknown id.** A control that does not exist
   generates zero probes, so a typo would otherwise produce a run that comes back clean having
   tested nothing. Deprecated ids warn and exit 0 (`--strict` fails on those too).
9. **Only `bridge` apps need a bridge.** `api`, `gcp` and `bedrock` targets are called by Ascend
   directly. Check `needs_bridge` on the create response, or `api_type` on the app. The NO-BRIDGE
   alarm is scoped to bridge-based apps for this reason.
10. **Compliance mapping is not exposed.** The platform maps controls to standards and requirements
    on the backend and shows it in the Console, but no v3 endpoint returns it and the CSV export
    does not carry it. The CLI therefore rolls up on the platform's own axes (risk tag, category,
    control, data class) and does **not** invent an OWASP/NIST/ATLAS mapping. `doctor --api-compat`
    watches for the field appearing.

## Speed notes

The PAT→JWT exchange is cached on disk (0600, tenant-scoped) until shortly before it expires, and
all HTTP uses one pooled connection, so a second command in the same window costs ~0.4s instead of
~1.5s. `ASCEND_NO_CACHE=1` disables the cache if you need a cold read.

## Environment

| Variable | Purpose |
|---|---|
| `STRAIKER_PAT` | your platform PAT (`s6r_pat_…`), required |
| `STRAIKER_BRIDGE_API_KEY` | a `tc-` bridge key, when not using the local key store |
| `ASCEND_CONFIG_DIR` | where adapter configs live |
| `ASCEND_POLICY` | path to the severity/gate policy file |
| `ASCEND_NO_CACHE` | disable the response/JWT cache |
| `ASCEND_NO_SPINNER` / `NO_COLOR` | plain, quiet output |
| `ASCEND_STATE_DIR` | keys, bridge records, cache (per tenant) |

## The CLI versus MCP

For an agent with shell access the CLI needs no install or config step, and it composes: pipe
`--json` into `jq`/`python`, tail a bridge log, chain steps in one command. An MCP layer applies to
clients that can't run a shell, or when you want to restrict an agent to a fixed set of verbs. An
MCP passthrough exists in `shells/mcp/` for that case.
