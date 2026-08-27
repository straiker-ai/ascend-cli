# Reading a run in depth

```bash
ascend results                                  # from the platform: your assessments, as a table
ascend results run.csv                          # from a file: failures by category/evasion/control
ascend results run.csv --values                 # the data harvest — what the target gave up
ascend results run.csv --turns --limit 5        # the failing turns themselves
ascend results run.csv --matrix                 # the guardrail confusion matrix
ascend results run.csv --md > findings.md
ascend results run.csv --json | jq .data.by_evasion
```

One command reads two sources. **No file** reads the platform: assessment-level rows, the same view
`ascend reports` gave (still a hidden alias). **A file** reads a Console CSV export: one row per
probe, with the prompt, the target's actual answer, the evasion technique used, and the platform's
reason for flagging it.

## Why this command reads a file

There is no per-turn results endpoint in v3. The deepest programmatic read is the assessment detail
(`category_summary`, `failed`, `total`, `score`, `severity`). That is what `ascend reports` uses.
DataBridge publishes a `defend.turn` source but no `ascend.turn`, so red-team turns are not
streamable either. The Console export is the only route to turn-level data, which is why this
command takes a path.

`doctor --api-compat` watches for that to change.

## Units

| Term | Unit | Meaning |
|---|---|---|
| `probes` | prompts | rows in the export; one adversarial prompt each |
| `answered` | prompts | the target actually replied (HTTP 200 **and** a pass/fail verdict) |
| `unanswered` | prompts | errored or came back `unknown` — **not passes** |
| `failed` | prompts | the attack achieved something (`score > 0`) |
| `strict` | prompts | fully scored failure (`score >= 1.0`) |
| `passed` | prompts | answered, and the attack did not succeed |
| `findings` | **controls** | what `results --detail` counts — a different unit entirely |

Two traps, both of which produce wrong statements:

**1. Probes are not findings.** 187 failed probes across 56 failed controls is one run. The two
numbers are not expected to agree. A table that mixed them silently would be wrong.

**2. Unanswered probes are not passes.** A probe the target errored on measured nothing. On real
exports this is routinely 30–43% of a run. The failure rate is therefore computed over
**answered**, and a warning names the count:

```
!! 378 of 1229 probes (30.8%) were never answered by the target. Those measured nothing —
   they are not passes. The failure rate above is over the 851 answered probes.
```

This is the row-level equivalent of the false pass a dead bridge produces. It is rarer now that
`assess run` auto-manages the bridge, but still occurs when auto-management is off or a remote
bridge dies.

## The rollups

All grouping axes come from the platform (`/ascend/controls`):

| Axis | Source | Values |
|---|---|---|
| Risk grouping | `categories[].tag` | Security · Safety · Trust |
| Category | `categories[].id` | 10, with the platform's display names |
| Control | `controls[].id` | 71 |
| Data class | `controls[].prefix` | PII · Financial · IP |
| Evasion technique | `evasions_applied` | the technique list per probe |

```
ascend results run.csv --by category,evasion,control          # the default
ascend results run.csv --by risk,dataclass,combo              # the rest
```

An unknown section name is refused with a did-you-mean suggestion.

Offline, or with `--no-catalog`, the rollups fall back to raw ids and the header says `raw ids`
instead of `platform taxonomy`.

### By evasion technique

The view the Console shows as its Threat Matrix rows:

```
  BY EVASION TECHNIQUE  (which attacks worked)
                             PROBES  PASSED  FAILED   RATE  UNANSW  FAILURES (relative)
  single_turn                 1,599   1,582      17   1.1%       0  ██████████████
  space_breaker                 164     160       4   2.4%       0  ███
  evidence_based_persuasion     224     221       3   1.3%       0  ██
```

Volume and effectiveness are different measures: `single_turn` has the most failures because it has
the most probes, while `space_breaker` has more than double the success *rate*. The bar is scaled to
the worst row in the table rather than to 0–100%. Real failure rates are often 1–2%, which rounds to
a full block at any usable width and makes every row look identical. The `RATE` column shows the
absolute number.

## Compliance

The platform maps controls to standards and individual requirements on the backend, and the Console
renders it. **No v3 endpoint returns that mapping and the CSV export does not carry it.**

This command does not provide one. There is no local OWASP/NIST/ATLAS table, because a locally
written mapping would drift from the platform's and put two different answers in front of the same
customer. The command returns the platform's own taxonomy (risk tag, category, control, data class),
which is what the compliance view is built on. When the mapping becomes reachable it drops in as one
more axis.

## The data harvest

```
  DATA HARVEST  (5 distinct value(s) across 3 type(s), produced by the target)

  Email Address  —  1 distinct, 18 occurrence(s)
    VALUE                                    TIMES SEEN  FROM TARGET  FROM PROMPT
    renewals@example.com                             18           18            0

  Phone Number  —  2 distinct, 17 occurrence(s)
    VALUE                                    TIMES SEEN  FROM TARGET  FROM PROMPT
    866-555-0142                                     16           16            0
    415-555-0134                                      5            0            5
```

Values are grouped by type, each ranked. `FROM TARGET + FROM PROMPT = TIMES SEEN`, so the
arithmetic is checkable. The second row above shows why the split matters: seen five times, but
every one was the attacker's own prompt repeated back. Not a disclosure.

Extractors are keyed to **platform control ids** (`phone_number`, `email_address`,
`social_security_number`, `api_key`, `internal_url_and_endpoints`, …) so the view cannot drift from
the taxonomy. Formatting variants collapse: `(415) 820-7431` and `415-820-7431` are one value.

- **TIMES SEEN** — how many responses contained the value.
- **FROM TARGET** — the prompt did not contain it, so the target produced it. A disclosure.
- **FROM PROMPT** — the attacker's prompt already contained it and the target repeated it back.
  Not a disclosure. `--all-values` shows these too; by default they are hidden.

That distinction is mechanical, and it is where this stops. Whether a target-produced value is
*sensitive* (a customer's private number) or *public* (the support line on the contact page) is a
judgement call that needs context the CLI does not have. It is not decided here, and no heuristic
adjusts a count on the basis of it. See [../agent/TRIAGE.md](../agent/TRIAGE.md).

Only obvious format noise is filtered: literal placeholders (`123-45-6789`, `test@example.com`) and
digit runs that cannot be phone numbers.

## The guardrail confusion matrix

```
ascend results run.csv --matrix
```

Built from the platform's **own** `input_guardrails_false_positive` / `_false_negative` columns.
Every answered turn lands in exactly one cell, by this precedence:

| Cell | Condition |
|---|---|
| FN — attack succeeded | the attack achieved something (`score > 0`) |
| FP — benign blocked | else the platform flagged it a false positive |
| TP — attack blocked | else the response was a refusal/block |
| TN — benign allowed | everything else |

Errored probes are excluded and reported separately. Precision, recall and attack-success-rate
follow from the cells.

`successes_after_refusal` is reported alongside, because a response that **opens** with a refusal
and then discloses anyway is still a failure. Classifying by prefix once halved a real engagement's
failure count, so the refusal regex is used only for this sub-statistic and never touches a verdict.

## Defend exports

The command sniffs the schema, so a Defend runtime-log export works too:

```
  Defend events — 2,328
  flagged 1,641   blocked 0 (0.0%)   detected 1,641 (70.49%)
  input scans 0   output scans 2,328   sessions 2,328
```

`blocked 0` with everything in detect mode means the guardrails are in monitor-only mode.
Detections are broken out by block vs detect.

## Parsing the record fields

`user_interaction_record` and `verdict` look like JSON but are not:

```
{assessment_prompt=Tell me about…, response=Sure, here is…, status_code=200, …}
```

Keys are bare, values unquoted and unescaped, and values routinely contain commas, `=`, braces and
newlines. `json.loads` fails on every row. The values are text the *target* produced, so a
response can legitimately contain the literal `, response=`. That defeats a naive next-key scan
and silently truncates the answer, changing value extraction and every count downstream.

`reporting/turns.py` finds all candidate key boundaries and keeps only those whose key order
increases monotonically, so a stray marker inside a later value stays text. Validated against 8,073
rows of real exports across both schemas with zero parse failures.

## For scripts and agents

```bash
ascend results run.csv --json | jq '.data.totals'
ascend results run.csv --json | jq '.data.values[] | select(.from_target > 0)'
ascend results run.csv --json | jq '.data.warnings[]'
```

`{"ok": true, "data": {...}}` on success, `{"ok": false, "error": {...}}` on failure, both on
stdout. `source.taxonomy` tells you whether labels came from the platform or are raw ids. See
[AGENTS.md](AGENTS.md).
