# Ascend CLI — command reference

*Generated from the CLI's argparse tree by `scripts/gen_command_map.py`. A test fails if this file is stale, so every flag here is a flag that exists.*

20 command groups · 54 commands. Sections follow `ascend --help`.

## Flags every command accepts

| Flag | Value | What it does |
|---|---|---|
| `--json` | — | machine-readable output. Success is `{"ok":true,...}`, failure is `{"ok":false,"error":{...}}` — both on stdout, prose on stderr. |
| `--token` | `TOKEN` | Straiker PAT (`s6r_pat_…`) or a JWT. Defaults to `$STRAIKER_PAT`. |
| `--base` | `URL` | v3 API base. Defaults to `$STRAIKER_API_BASE`. |
| `--bridge-base` | `URL` | bridge lease/result base. Defaults to `$STRAIKER_BRIDGE_URL`. |

## Exit codes

| Code | Meaning |
|---|---|
| `0` | success / clean |
| `1` | tool or target error — including *could not read results*, never a pass |
| `2` | findings gate failed (`ascend ci`) |
| `3` | bad invocation (unknown control id, missing per-type field, malformed flag) |

## Also available

*Not in the menu — compatibility aliases and reference output.*

## `ascend adapter`

### `ascend adapter build`

Build an adapter config for a target and PROVE it against the live target before writing anything. Give it whichever source you have — --api, --curl, --har, --url or --spec, listed below. Nothing is written unless it answered: an unvalidated config is a guess.

- **`evidence`** (optional) — evidence JSON path


| Flag | Value | Default | What it does |
|---|---|---|---|
| `--url` | `URL` | — | live page with a chat widget: drive a real browser and capture the true contract |
| `--api` | `URL` | — | an HTTP API endpoint (or just the base URL — the path is discovered). No browser. |
| `--curl` | `FILE` | — | a curl command in a file, or '-' for stdin. Zero guessing. |
| `--spec` | `BASE_URL` | — | find an OpenAPI/Swagger spec under this base URL and build from it |
| `--har` | `HAR` | — | HAR file to classify |
| `--header` *(repeatable)* | `'Name: value'` | — | raw header (repeatable), honored by all sources, e.g. 'X-Api-Key: …'. A value written env:NAME is read from the environment and never stored in the config |
| `--bearer` | `TOKEN` | — | Authorization: Bearer <token>; env:NAME keeps the token out of the config |
| `--api-key` | `NAME:VALUE[:in=header|query]` | — | API key, e.g. 'x-api-key:abc', 'key:abc:in=query', or 'x-api-key:env:MY_KEY' to reference the environment instead of storing the value |
| `--basic` | `USER:PASS` | — | HTTP Basic auth; 'user:env:MY_PW' references the password |
| `--cookie` | `'k=v; k2=v2'` | — | Cookie header for a session-gated target; 'session=env:MY_SESSION' references the value |
| `--token-file` | `PATH` | — | read a bearer token from this file |
| `--body-field` *(repeatable)* | `key=value` | — | extra JSON body field, repeatable — for agents whose key/tenant lives in the BODY, e.g. --body-field apiKey=abc --body-field workspace=support. Use key:=raw for a non-string literal (true/1/{...}). |
| `--login-url` | `URL` | — | POST here first to exchange creds/code for a token |
| `--login-body` | `JSON|FORM` | — | body for --login-url. JSON ('{"code":"1234"}') or form-encoded ('grant_type=client_credentials&client_id=…') — OAuth2 is form-encoded. |
| `--token-path` | `DOTPATH` | `token` | dot-path to the token in the login response (default: token) |
| `--login-method` | `POST|GET` | `POST` | verb for --login-url (default: POST). GET for a bootstrap page that sets a session cookie or embeds a CSRF token. |
| `--token-regex` | `RE` | — | extract the token with a regex (first capture group) instead of --token-path — for a token embedded in HTML, e.g. 'csrf-token" content="([^"]+)' |
| `--token-header` | `NAME` | — | send the extracted token in this header verbatim (e.g. X-CSRF-Token) instead of as 'Authorization: Bearer <token>' |
| `--insecure` | — | — | skip TLS verification (self-signed internal targets) |
| `--ca-bundle` | `PATH` | — | custom CA bundle for TLS verification |
| `--client-cert` | `PATH` | — | client certificate (PEM) for mTLS |
| `--client-key` | `PATH` | — | client private key (PEM) for mTLS |
| `--proxy` | `URL` | — | HTTP(S) proxy for the probe/validate calls |
| `--cdp` | `ENDPOINT` | — | with --url: attach to a browser you are ALREADY signed into (start it with `chrome --remote-debugging-port=9222`) instead of launching one. The only route into an Entra / SAML / SSO-gated target. Default endpoint http://127.0.0.1:9222; the written adapter attaches the same way, and your browser is never closed. |
| `--prompt-hint` | `PROMPT_HINT` | — | with --curl: the literal prompt text used in that command |
| `--allow-internal` | — | — | allow link-local/cloud-metadata hosts (169.254/fd00::) — off by default |
| `--timeout` | `TIMEOUT` | `20.0` | per-request timeout in seconds |
| `--prompt` | `PROMPT` | `Hello, what can you help me with?` | benign prompt to send during capture |
| `--headless` | — | — | run the capture browser headless (faster, but bot protection often blocks it) |
| `--no-headless` | — | `True` | force a visible browser (default; most reliable against bot protection) |
| `--manual` | — | — | open the page and let YOU drive the widget while we record (for widgets our automation cannot reach) |
| `--settle` | `SETTLE` | `6` | seconds to wait for page/widget/reply |
| `--response-path` | `DOTPATH` | — | where the answer is in the response, e.g. data.reply — set it explicitly when the CLI cannot find it, or to override its guess (scriptable) |
| `--save-evidence` | `SAVE_EVIDENCE` | — | also write the raw captured evidence here |
| `--code` | — | — | advanced: also write the adapter as an editable Python module (the CLI picks the adapter kind automatically; you don't need this normally) |
| `--out` | `OUT` | — | write the drafted config here |

```bash
ascend adapter build --har ~/Downloads/target.har --out mybot.json
ascend adapter build --curl req.curl --out mybot.json
ascend adapter build --api https://host/chat --bearer $TOK --out mybot.json
ascend adapter build --url https://site/support --manual --out mybot.json
```

> see docs/BUILD_ADAPTER.md for the full walkthrough and the HAR export steps.

### `ascend adapter configs`

list adapter configs on disk (incl. shipped examples)


### `ascend adapter layers`

*Hidden from the menu (kept for compatibility); still supported.*


### `ascend adapter list`

list registered adapter types


### `ascend adapter show`

print a saved adapter config (secrets masked)

- **`config`** (required) — config name in the config dir


| Flag | Value | Default | What it does |
|---|---|---|---|
| `--reveal` | — | — | print secret values in clear (they are masked by default, because a built config can carry the session token that authenticated the browser) |

### `ascend adapter validate`

HARD GATE: run one prompt through a config against the live target


| Flag | Value | Default | What it does |
|---|---|---|---|
| `--config` | `CONFIG` | — | config name in configs/ |
| `--file` | `FILE` | — | path to a config json (instead of --config) |
| `--adapter` | `ADAPTER` | — | adapter type override (else config['adapter']) |
| `--prompt` | `PROMPT` | `Hello, what can you help me with?` | — |
| `--expect` | `EXPECT` | — | substring the response must contain |
| `--timeout` | `TIMEOUT` | `60.0` | — |

> example: ascend adapter validate --config mybot --prompt 'hello' --expect 'Bot'

## `ascend app`

### `ascend app bind`

record which Ascend app a config was registered as

- **`config`** (required) — config name (see `ascend adapter configs`)


| Flag | Value | Default | What it does |
|---|---|---|---|
| `--app` **(required)** | `APP` | — | app name or aapp_ id |

> example: ascend app bind mybot --app 'My Bot'

### `ascend app create`

Create an Ascend application. The platform supports four target types; one of them is served by the CLI's built-in bridge: bridge   Ascend hands prompts to the CLI's bridge; `assess run` auto-manages it (key shown ONCE) api      Ascend calls your HTTP target directly    (no bridge) gcp      Vertex AI / Agent Engine target           (no bridge) bedrock  AWS Bedrock target                        (no bridge) Required fields differ per type and are checked locally before the request, so a missing one is named rather than returned as a 422.


| Flag | Value | Default | What it does |
|---|---|---|---|
| `--type` | `bridge|api|gcp|bedrock` | `bridge` | target type (default: bridge — the type served by the CLI's built-in bridge) |
| `--url` | `URL` | — | target endpoint (api/gcp/bedrock) |
| `--target-api-key` | `KEY` | — | API key Ascend should present to the target (--type api) |
| `--service-account` | `JSON|@FILE` | — | GCP service-account JSON, or @path to it (--type gcp) |
| `--bedrock-auth` | `assume-role|access-key` | — | Bedrock authentication method (--type bedrock) |
| `--region` | `REGION` | — | AWS region (--type bedrock) |
| `--role-arn` | `ROLE_ARN` | — | role to assume (--type bedrock, assume-role) |
| `--external-id` | `EXTERNAL_ID` | — | external id for the assume-role trust policy |
| `--role-session-name` | `ROLE_SESSION_NAME` | — | session name for the assumed role |
| `--access-key-id` | `ACCESS_KEY_ID` | — | AWS access key id (--type bedrock, access-key) |
| `--secret-access-key` | `SECRET_ACCESS_KEY` | — | AWS secret access key |
| `--session-token` | `SESSION_TOKEN` | — | AWS session token |
| `--name` **(required)** | `NAME` | — | application name shown in Ascend |
| `--system-prompt` | `SYSTEM_PROMPT` | — | what the target is — the scorer compares responses against this to detect a system-prompt leak (default: the app name) |
| `--purpose` | `PURPOSE` | — | business purpose, for assessment context |
| `--controls` | `CONTROLS` | — | comma-separated control ids (validated before the create) |
| `--size` | `small|medium|large` | `small` | assessment size — how many probes a run generates |
| `--qpm` | `N` | `30` | max queries per minute against the target |
| `--config` | `CONFIG` | — | adapter config to bind (and, for --type api, to take the url/templates/headers from) |
| `--category-severity` *(repeatable)* | `CAT=SEV` | — | per-category severity, repeatable: data_leak=high. Platform enum is default\|low\|medium\|high ('critical' is clamped to 'high') |
| `--input-guardrail` | `TYPE=VALUE` | — | how the target signals a guardrail block, so a block is not scored as an answer: http_status_code=403 or response_pattern='I can\|t help' (pipe-separate several values) |
| `--strategy` | `A,B` | — | comma-separated attack strategies (e.g. single_turn,multi_turn); implies --strategy-type custom |
| `--strategy-type` | `recommended|custom` | — | attack strategy selection (default: recommended) |
| `--if-not-exists` | — | — | reuse an app with this name instead of creating a duplicate (safe retry) |
| `--force` | — | — | create the app even if its controls generate zero probes (an app pinned to an unknown control scores clean without ever being tested) |

```bash
ascend app create --name 'My Bot' --controls sys_prompt_leak
      a bridge app (the default) — `ascend assess run` starts the relay for you
ascend app create --type api --name 'Public Bot' --config mybot \
      --target-api-key $KEY
      Ascend calls the target itself; url/templates/headers come from the config
ascend app create --type gcp --name 'Vertex Agent' \
      --url https://…/agents/x:streamQuery --service-account @sa.json
ascend app create --type bedrock --name 'Bedrock Agent' \
      --url arn:aws:bedrock:… --bedrock-auth assume-role \
      --role-arn arn:aws:iam::…:role/x --region us-east-1
ascend app create --name 'My Bot' --category-severity data_leak=high \
      --input-guardrail http_status_code=403
```

### `ascend app delete`

delete an application (also stops its bridge + drops its stored key)

- **`app`** (required) — app name or aapp_ id


| Flag | Value | Default | What it does |
|---|---|---|---|
| `--keep-key` | — | — | keep the stored bridge key (default: remove it — a key without its app is dead) |

### `ascend app get`

get an application (by id or name)

- **`app`** (required) — app name or aapp_ id


### `ascend app list`

list applications (add --with-runs for the assessment table)


| Flag | Value | Default | What it does |
|---|---|---|---|
| `--with-runs` | — | — | show the assessment table: state, run count, latest run, progress/score/severity |
| `--running` | — | — | only apps that have a live (running/created/paused) assessment |
| `--all-runs` | — | — | list every assessment per app, not just the latest |

```bash
ascend app list                    # just the apps (fast)
ascend app list --with-runs        # + assessment status table
ascend app list --running          # only apps with a LIVE assessment
ascend app list --all-runs         # every assessment per app
```

### `ascend app resolve`

*Hidden from the menu (kept for compatibility); still supported.*

- **`name`** (required) — application name to resolve to an id


### `ascend app update`

change a live app's settings in place (no delete/recreate)

- **`app`** (required) — app name or aapp_ id


| Flag | Value | Default | What it does |
|---|---|---|---|
| `--name` | `NAME` | — | rename the app |
| `--system-prompt` | `SYSTEM_PROMPT` | — | update the system prompt used for leak scoring |
| `--purpose` | `PURPOSE` | — | update the business purpose |
| `--qpm` | `QPM` | — | queries per minute |
| `--controls` | `CONTROLS` | — | replace the control set (comma-separated, validated) |
| `--category-severity` *(repeatable)* | `CAT=SEV` | — | set a category severity (repeatable); pushed to the app |
| `--input-guardrail` | `TYPE=VALUE` | — | how a block is signalled |
| `--frequency` | `none|weekly|monthly|quarterly` | — | recurring assessment cadence |
| `--strategy` | `A,B` | — | comma-separated attack strategies |
| `--strategy-type` | `recommended|custom` | — | — |

> example: ascend app update 'My Bot' --qpm 60 --controls sys_prompt_leak,pii_leak

## `ascend assess`

run and monitor assessments

### `ascend assess diff`

compare two assessments: new / resolved / regressed findings


| Flag | Value | Default | What it does |
|---|---|---|---|
| `--app` | `APP` | — | app name or aapp_ id (for --base/--against ids) |
| `--baseline` | `BASELINE` | — | baseline assessment id |
| `--current` | `CURRENT` | — | the newer assessment id to compare |
| `--baseline-file` | `BASELINE_FILE` | — | baseline assessment json on disk (instead of --baseline) |
| `--current-file` | `CURRENT_FILE` | — | current assessment json on disk (instead of --current) |

> example: ascend assess diff --app 'My Bot' --base asmt_old --against asmt_new

### `ascend assess list`

list assessments for an app (running assessments marked *)


| Flag | Value | Default | What it does |
|---|---|---|---|
| `--app` **(required)** | `APP` | — | app name or aapp_ id |
| `--running` | — | — | only assessments still running |

### `ascend assess pause`

pause a running assessment (in-flight probes drain, see docs)


| Flag | Value | Default | What it does |
|---|---|---|---|
| `--app` **(required)** | `APP` | — | app name or aapp_ id |
| `--assessment` **(required)** | `ASSESSMENT` | — | assessment id (asmt_...) |

### `ascend assess results`

assessment findings summary


| Flag | Value | Default | What it does |
|---|---|---|---|
| `--app` **(required)** | `APP` | — | app name or aapp_ id |
| `--assessment` **(required)** | `ASSESSMENT` | — | assessment id (asmt_...) |
| `--detail` | — | — | show key findings per control |

### `ascend assess resume`

resume a paused assessment


| Flag | Value | Default | What it does |
|---|---|---|---|
| `--app` **(required)** | `APP` | — | app name or aapp_ id |
| `--assessment` **(required)** | `ASSESSMENT` | — | assessment id (asmt_...) |

### `ascend assess run`

create->pause->resume->poll an assessment


| Flag | Value | Default | What it does |
|---|---|---|---|
| `--app` *(repeatable)* | `APP` | — | app name or aapp_ id (repeatable for a fleet) |
| `--all-bound` | — | — | every app with a stored bridge key (see `ascend keys list`) |
| `--name` **(required)** | `NAME` | — | a label for this assessment run |
| `--controls` | `CONTROLS` | — | scope the run to these control ids — applied to the app, because the platform has no per-run override |
| `--no-wait` | — | — | return as soon as the run starts |
| `--interval` | `INTERVAL` | `20` | seconds between status polls |
| `--timeout` | `TIMEOUT` | `7200` | max seconds to wait for completion |
| `--force` | — | — | run even if the selected controls would generate zero probes |

```bash
ascend assess run --app 'My Bot' --name 'run 1'
ascend assess run --app A --app B --app C --name 'wave 1'   # fleet
ascend assess run --all-bound --name 'wave 1'
```

### `ascend assess status`

*Hidden from the menu (kept for compatibility); still supported.*


| Flag | Value | Default | What it does |
|---|---|---|---|
| `--app` **(required)** | `APP` | — | app name or aapp_ id |
| `--assessment` **(required)** | `ASSESSMENT` | — | assessment id (asmt_...) |

### `ascend assess watch`

live view of a running assessment until it finishes


| Flag | Value | Default | What it does |
|---|---|---|---|
| `--app` *(repeatable)* | `APP` | — | app name or aapp_ id (repeatable) |
| `--all` | — | — | watch every live assessment in the tenant, with bridge status per run |
| `--include-done` | — | — | with --all: also show finished runs |
| `--assessment` | `ASSESSMENT` | — | assessment id (default: the one currently running) |
| `--interval` | `INTERVAL` | `10` | seconds between polls |
| `--detail` | — | — | show key findings when it completes |
| `--once` | — | — | print one snapshot and exit instead of following (replaces `assess status`) |

```bash
ascend assess watch --app 'My Bot'            # auto-picks the running one
ascend assess watch --all                     # every live run, one table
ascend assess watch --app 'My Bot' --assessment asmt_x --detail
```

## `ascend bridge`

*Aliases: `relay`*

### `ascend bridge logs`

show a bridge's log

- **`app`** (required) — app name or aapp_ id


| Flag | Value | Default | What it does |
|---|---|---|---|
| `--follow`, `-f` | — | — | tail live |

### `ascend bridge ls`

list bridges + flag live assessments with NO bridge


| Flag | Value | Default | What it does |
|---|---|---|---|
| `--no-check` | — | — | skip the tenant lookup (offline/fast) |

### `ascend bridge start`

start a detached bridge per app (key comes from the local store)


| Flag | Value | Default | What it does |
|---|---|---|---|
| `--app` *(repeatable)* | `APP` | — | app name or aapp_ id (repeatable) |
| `--all-running` | — | — | every app whose latest assessment is actively running |
| `--config` | `CONFIG` | — | override the bound config name for all targets |
| `--qpm` | `QPM` | — | per-bridge queries per minute |
| `--qpm-total` | `QPM_TOTAL` | — | split this total across the started bridges (protects a shared target host) |
| `--max-workers` | `MAX_WORKERS` | — | — |
| `--wait-ms` | `WAIT_MS` | — | — |
| `--idle-timeout` | `IDLE_TIMEOUT` | — | seconds a paused, already-probed bridge waits before self-stopping. 0 never idle-stops (the default); the bridge stops when the run reaches a terminal state. $ASCEND_BRIDGE_IDLE_TIMEOUT sets this default for auto-managed runs. |
| `--foreground` | — | — | run ONE bridge in this terminal (logs here, Ctrl-C stops it) instead of detaching — for debugging an adapter. Needs --config. |

```bash
ascend bridge start --all-running        # serve every live assessment
ascend bridge start --app 'My Bot'       # one app (repeatable)
ascend bridge start --all-running --qpm-total 60
ascend bridge start --app 'My Bot' --config mybot --foreground
      one bridge, in this terminal, logs on screen (debugging)
```

### `ascend bridge stop`

stop bridges


| Flag | Value | Default | What it does |
|---|---|---|---|
| `--app` *(repeatable)* | `APP` | — | app name or aapp_ id (repeatable) |
| `--all` | — | — | stop every bridge |
| `--grace` | `GRACE` | `8.0` | seconds before SIGKILL |

### `ascend bridge sync`

reconcile bridges to assessment state — start for running/paused apps, stop for terminal (the fallback after a Console-side change)


| Flag | Value | Default | What it does |
|---|---|---|---|
| `--no-stop` | — | — | only start missing bridges; never stop one |

### `ascend chat`

talk to an agent directly — a live, transcript (telnet for an AI agent)

- **`target`** (optional) — config name, config path, or a URL (a URL is discovered first)


| Flag | Value | Default | What it does |
|---|---|---|---|
| `--config` | `CONFIG` | — | config name or path (same as the positional) |
| `--file` | `FILE` | — | config json path |
| `--adapter` | `ADAPTER` | — | adapter type (default: from the config) |
| `--prompt` *(repeatable)* | `PROMPTS` | — | send this prompt and exit; repeat for several |
| `--prompt-file` | `PROMPT_FILE` | — | file of prompts: one per line, or JSONL {prompt,id,category,expect,note} |
| `--out` | `OUT` | — | write the transcript here (default: captures/<target>-<ts>.jsonl) |
| `--no-record` | — | — | do not write a transcript |
| `--header` *(repeatable)* | `'Name: value'` | — | header when the target is a URL (repeatable) |
| `--reset-between` | — | — | fresh conversation for each prompt in a file |
| `--timeout` | `TIMEOUT` | `60.0` | per-turn timeout in seconds |

```bash
ascend chat mybot                         # live session, auto-recorded
ascend chat https://host/api/chat         # discover it, then talk to it
ascend chat mybot --prompt 'what can you do?'
ascend chat mybot --prompt-file probes.txt --out captures/run.jsonl
```

> in a live session: /new  /results  /retry  /save <file>  /help  /exit

### `ascend ci`

CI gate: nonzero exit on new findings / severity breach


| Flag | Value | Default | What it does |
|---|---|---|---|
| `--app` | `APP` | — | — |
| `--assessment` | `ASSESSMENT` | — | — |
| `--file` | `FILE` | — | current assessment json on disk |
| `--baseline` | `BASELINE` | — | baseline assessment json for diff |
| `--fail-on-severity` | `low|medium|high|critical` | `high` | — |
| `--allow-new` | — | — | do not fail on new findings |
| `--junit` | `FILE` | — | also write JUnit XML for generic CI systems |
| `--policy` | `POLICY` | — | policy file (default ./ascend-policy.json or $ASCEND_POLICY); flags override it |
| `--min-probes` | `N` | — | refuse to pass a CLEAN run with fewer than N probes — that is what a bridge which was not running produces, and it exits 1 (cannot trust the results), never 0. Use 0 for runs that are genuinely this small. (default: 5) |

> example: ascend ci --app 'My Bot' --assessment asmt_x --baseline base.json

## `ascend controls`

control catalog

### `ascend controls list`

The platform's control catalog. Deprecated controls are hidden by default because they generate zero probes — selecting one produces a run that scores nothing. `--categories` switches to the grouping view: the platform's own categories with their risk tag (Security / Safety / Trust), display name, and how many active controls each still has.


| Flag | Value | Default | What it does |
|---|---|---|---|
| `--categories` | — | — | list the categories (with risk tag and active-control counts) instead |
| `--category` | `ID` | — | filter to one category id |
| `--tag` | `TAG` | — | filter by the platform's risk tag (Security/Safety/Trust) |
| `--include-deprecated` | — | — | include deprecated controls (they generate zero probes) |
| `--agentic-only` | — | — | only agentic controls |

```bash
ascend controls list
ascend controls list --categories        # the platform's grouping + tags
ascend controls list --tag Security
ascend controls list --category data_leak
ascend controls list --agentic-only      # tool-use probes
ascend controls list --include-deprecated
```

### `ascend controls validate`

Check control ids against the live catalog. Exit codes are the point: an unknown id exits 3, because a control that does not exist generates zero probes and the run would come back clean having tested nothing. A deprecated id warns and exits 0; use --strict to fail on those too.

- **`controls`** (required) — comma-separated control ids to validate


| Flag | Value | Default | What it does |
|---|---|---|---|
| `--strict` | — | — | also fail on deprecated ids (they generate zero probes) |

```bash
ascend controls validate sys_prompt_leak,jailbreak
ascend controls validate $(cat controls.txt) --strict
ascend controls validate a,b --json
```

### `ascend doctor`

preflight checks + version-vs-latest (--api-compat, --update)


| Flag | Value | Default | What it does |
|---|---|---|---|
| `--api-compat` | — | — | verify every API field this CLI depends on (drift = loud failure) |
| `--update` | — | — | update this install if a newer release is published (git pull for a clone; prints the command for pipx/binary) |

### `ascend export`

export findings (json/csv/sarif/markdown)


| Flag | Value | Default | What it does |
|---|---|---|---|
| `--app` | `APP` | — | — |
| `--assessment` | `ASSESSMENT` | — | — |
| `--file` | `FILE` | — | assessment json on disk (instead of fetching) |
| `--format` | `json|csv|sarif|markdown` | `json` | — |
| `--out` | `OUT` | — | write to this file instead of stdout |

> example: ascend export --app 'My Bot' --assessment asmt_x --format sarif --out out.sarif

## `ascend keys`

### `ascend keys add`

store a bridge key for an app


| Flag | Value | Default | What it does |
|---|---|---|---|
| `--app` **(required)** | `APP` | — | app name or aapp_ id |
| `--key` **(required)** | `KEY` | — | the bridge key |
| `--config` | `CONFIG` | — | config name this app is driven by |
| `--adapter` | `ADAPTER` | — | adapter type |

### `ascend keys list`

list stored keys (masked)


| Flag | Value | Default | What it does |
|---|---|---|---|
| `--no-check` | — | — | don't check whether the apps still exist |

### `ascend keys prune`

drop keys whose app no longer exists


| Flag | Value | Default | What it does |
|---|---|---|---|
| `--yes` | — | — | allow pruning ALL stored keys (refused by default: a bridge key is shown once) |

### `ascend keys rm`

remove a stored key (optionally the Ascend app with it)

- **`app`** (required) — app name or aapp_ id


| Flag | Value | Default | What it does |
|---|---|---|---|
| `--delete-app` | — | — | also delete the Ascend app (retire the pair: a keyless app can't be served) |

### `ascend map`

*Aliases: `discover`*

*Hidden from the menu (kept for compatibility); still supported.*

- **`evidence`** (optional) — evidence JSON path


| Flag | Value | Default | What it does |
|---|---|---|---|
| `--url` | `URL` | — | live page with a chat widget: drive a real browser and capture the true contract |
| `--api` | `URL` | — | an HTTP API endpoint (or just the base URL — the path is discovered). No browser. |
| `--curl` | `FILE` | — | a curl command in a file, or '-' for stdin. Zero guessing. |
| `--spec` | `BASE_URL` | — | find an OpenAPI/Swagger spec under this base URL and build from it |
| `--har` | `HAR` | — | HAR file to classify |
| `--header` *(repeatable)* | `'Name: value'` | — | raw header (repeatable), honored by all sources, e.g. 'X-Api-Key: …'. A value written env:NAME is read from the environment and never stored in the config |
| `--bearer` | `TOKEN` | — | Authorization: Bearer <token>; env:NAME keeps the token out of the config |
| `--api-key` | `NAME:VALUE[:in=header|query]` | — | API key, e.g. 'x-api-key:abc', 'key:abc:in=query', or 'x-api-key:env:MY_KEY' to reference the environment instead of storing the value |
| `--basic` | `USER:PASS` | — | HTTP Basic auth; 'user:env:MY_PW' references the password |
| `--cookie` | `'k=v; k2=v2'` | — | Cookie header for a session-gated target; 'session=env:MY_SESSION' references the value |
| `--token-file` | `PATH` | — | read a bearer token from this file |
| `--body-field` *(repeatable)* | `key=value` | — | extra JSON body field, repeatable — for agents whose key/tenant lives in the BODY, e.g. --body-field apiKey=abc --body-field workspace=support. Use key:=raw for a non-string literal (true/1/{...}). |
| `--login-url` | `URL` | — | POST here first to exchange creds/code for a token |
| `--login-body` | `JSON|FORM` | — | body for --login-url. JSON ('{"code":"1234"}') or form-encoded ('grant_type=client_credentials&client_id=…') — OAuth2 is form-encoded. |
| `--token-path` | `DOTPATH` | `token` | dot-path to the token in the login response (default: token) |
| `--login-method` | `POST|GET` | `POST` | verb for --login-url (default: POST). GET for a bootstrap page that sets a session cookie or embeds a CSRF token. |
| `--token-regex` | `RE` | — | extract the token with a regex (first capture group) instead of --token-path — for a token embedded in HTML, e.g. 'csrf-token" content="([^"]+)' |
| `--token-header` | `NAME` | — | send the extracted token in this header verbatim (e.g. X-CSRF-Token) instead of as 'Authorization: Bearer <token>' |
| `--insecure` | — | — | skip TLS verification (self-signed internal targets) |
| `--ca-bundle` | `PATH` | — | custom CA bundle for TLS verification |
| `--client-cert` | `PATH` | — | client certificate (PEM) for mTLS |
| `--client-key` | `PATH` | — | client private key (PEM) for mTLS |
| `--proxy` | `URL` | — | HTTP(S) proxy for the probe/validate calls |
| `--cdp` | `ENDPOINT` | — | with --url: attach to a browser you are ALREADY signed into (start it with `chrome --remote-debugging-port=9222`) instead of launching one. The only route into an Entra / SAML / SSO-gated target. Default endpoint http://127.0.0.1:9222; the written adapter attaches the same way, and your browser is never closed. |
| `--prompt-hint` | `PROMPT_HINT` | — | with --curl: the literal prompt text used in that command |
| `--allow-internal` | — | — | allow link-local/cloud-metadata hosts (169.254/fd00::) — off by default |
| `--timeout` | `TIMEOUT` | `20.0` | per-request timeout in seconds |
| `--prompt` | `PROMPT` | `Hello, what can you help me with?` | benign prompt to send during capture |
| `--headless` | — | — | run the capture browser headless (faster, but bot protection often blocks it) |
| `--no-headless` | — | `True` | force a visible browser (default; most reliable against bot protection) |
| `--manual` | — | — | open the page and let YOU drive the widget while we record (for widgets our automation cannot reach) |
| `--settle` | `SETTLE` | `6` | seconds to wait for page/widget/reply |
| `--response-path` | `DOTPATH` | — | where the answer is in the response, e.g. data.reply — set it explicitly when the CLI cannot find it, or to override its guess (scriptable) |
| `--save-evidence` | `SAVE_EVIDENCE` | — | also write the raw captured evidence here |
| `--code` | — | — | advanced: also write the adapter as an editable Python module (the CLI picks the adapter kind automatically; you don't need this normally) |
| `--out` | `OUT` | — | write the drafted config here |

### `ascend onboard`

zero to a running assessment in one command (build -> validate -> register -> bridge -> assess)


| Flag | Value | Default | What it does |
|---|---|---|---|
| `--api` | `URL` | — | an HTTP API endpoint (or base URL) — one probe, no browser. The simple-contract one-liner. |
| `--ws` | `URL` | — | a WebSocket endpoint (ws:// or wss://) — connects, works out the frame contract, no browser |
| `--url` | `URL` | — | live page with a chat widget: capture the contract in a real browser |
| `--curl` | `FILE` | — | a curl command in a file (or '-' for stdin) |
| `--har` | `HAR` | — | HAR file exported from your own browser (no browser needed here) |
| `--config` | `NAME|PATH` | — | a config already on disk — a name in the config dir, or a path to a .json file anywhere (skip discovery) |
| `--module` | `FILE.py` | — | a custom adapter you wrote: a Python file with `def send_prompt(prompt: str) -> str`. Use this when the contract cannot be derived — signed requests, a multi-step handshake, an async poll. It is proven against the live target like any other. |
| `--scaffold` | `FILE.py` | — | write a working custom-adapter stub to this path and stop. Edit it, then re-run with --module to onboard it. |
| `--name` | `NAME` | — | application name in Ascend (default: derived from the URL) |
| `--app` | `NAME|aapp_id` | — | bind to an application that ALREADY exists in the Console instead of creating one — its bridge key is fetched for you. Use this when the app was set up in the UI and all that is missing is something serving it. |
| `--save-as` | `NAME` | — | name the adapter config (default: derived from the URL, e.g. 'myhost-com'). Use this and you always know what to pass to --config. |
| `--system-prompt` | `SYSTEM_PROMPT` | — | what the target is, for the assessment context |
| `--controls` | `CONTROLS` | — | comma-separated control ids (validated before the run) |
| `--adapter` | `ADAPTER` | — | override the adapter type (default: from the config) |
| `--header` *(repeatable)* | `'Name: value'` | — | raw header (repeatable), honored by all sources, e.g. 'X-Api-Key: …'. A value written env:NAME is read from the environment and never stored in the config |
| `--bearer` | `TOKEN` | — | Authorization: Bearer <token>; env:NAME keeps the token out of the config |
| `--api-key` | `NAME:VALUE[:in=header|query]` | — | API key, e.g. 'x-api-key:abc', 'key:abc:in=query', or 'x-api-key:env:MY_KEY' to reference the environment instead of storing the value |
| `--basic` | `USER:PASS` | — | HTTP Basic auth; 'user:env:MY_PW' references the password |
| `--cookie` | `'k=v; k2=v2'` | — | Cookie header for a session-gated target; 'session=env:MY_SESSION' references the value |
| `--token-file` | `PATH` | — | read a bearer token from this file |
| `--body-field` *(repeatable)* | `key=value` | — | extra JSON body field, repeatable — for agents whose key/tenant lives in the BODY, e.g. --body-field apiKey=abc --body-field workspace=support. Use key:=raw for a non-string literal (true/1/{...}). |
| `--login-url` | `URL` | — | POST here first to exchange creds/code for a token |
| `--login-body` | `JSON|FORM` | — | body for --login-url. JSON ('{"code":"1234"}') or form-encoded ('grant_type=client_credentials&client_id=…') — OAuth2 is form-encoded. |
| `--token-path` | `DOTPATH` | `token` | dot-path to the token in the login response (default: token) |
| `--login-method` | `POST|GET` | `POST` | verb for --login-url (default: POST). GET for a bootstrap page that sets a session cookie or embeds a CSRF token. |
| `--token-regex` | `RE` | — | extract the token with a regex (first capture group) instead of --token-path — for a token embedded in HTML, e.g. 'csrf-token" content="([^"]+)' |
| `--token-header` | `NAME` | — | send the extracted token in this header verbatim (e.g. X-CSRF-Token) instead of as 'Authorization: Bearer <token>' |
| `--insecure` | — | — | skip TLS verification (self-signed internal targets) |
| `--ca-bundle` | `PATH` | — | custom CA bundle for TLS verification |
| `--client-cert` | `PATH` | — | client certificate (PEM) for mTLS |
| `--client-key` | `PATH` | — | client private key (PEM) for mTLS |
| `--proxy` | `URL` | — | HTTP(S) proxy for the probe/validate calls |
| `--cdp` | `ENDPOINT` | — | with --url: attach to a browser you are ALREADY signed into (start it with `chrome --remote-debugging-port=9222`) instead of launching one. The only route into an Entra / SAML / SSO-gated target. Default endpoint http://127.0.0.1:9222; the written adapter attaches the same way, and your browser is never closed. |
| `--allow-internal` | — | — | allow link-local/cloud-metadata hosts (169.254/fd00::) — off by default |
| `--prompt-hint` | `PROMPT_HINT` | — | with --curl: the literal prompt text used in that command |
| `--size` | `small|medium|large` | `small` | assessment size |
| `--qpm` | `QPM` | `20` | queries per minute against the target |
| `--prompt` | `PROMPT` | `Hello, what can you help me with?` | benign prompt used for capture and validation |
| `--settle` | `SETTLE` | `8` | seconds to wait for the widget/reply during capture |
| `--headless` | — | — | headless capture (bot protection often blocks it) |
| `--manual` | — | — | you drive the widget; we record |
| `--timeout` | `TIMEOUT` | `60.0` | per-request timeout for validation |
| `--dry-run` | — | — | stop after validating the config — do not register or run anything |
| `--force` | — | — | register even if the target answers two different questions identically (normally refused: that config can only produce a false pass) |
| `--wait` | — | — | block until the assessment completes, then print findings |
| `--detail` | — | — | with --wait, show key findings per control |
| `--interval` | `INTERVAL` | `20` | poll interval while waiting |
| `--timeout-assess` | `TIMEOUT_ASSESS` | `7200` | max seconds to wait for completion |
| `--assessment-name` | `ASSESSMENT_NAME` | — | assessment name (default: '<app> run 1') |
| `-v`, `--verbose` | — | — | debug logging for the bridge |

```bash
ascend onboard --api http://127.0.0.1:8790/chat --name Local --controls sys_prompt_leak
ascend onboard --url https://site/support --controls sys_prompt_leak
ascend onboard --har capture.har --name 'Support Bot'
ascend onboard --config mybot --wait
ascend onboard --url https://site/support --dry-run   # stop after validation
```

## `ascend policy`

your gate policy: how much you care about each control, and when CI fails

### `ascend policy push`

Send the local policy's per-CATEGORY severities to the app, so the Console reflects what you decided. Only the category half can be pushed: `category_severities` is a real field on an Ascend app. Per-CONTROL overrides have nowhere to go in v3 and stay local, applying to `ascend reports` and `ascend ci` only — the command says which ones those are rather than leaving you to assume they reached the platform. The platform's enum is default|low|medium|high: a policy asking for `critical` is clamped to `high`, out loud.


| Flag | Value | Default | What it does |
|---|---|---|---|
| `--app` **(required)** | `APP` | — | app name or aapp_ id |
| `--dry-run` | — | — | show what would be sent, send nothing |
| `--policy` | `POLICY` | — | policy file path |

```bash
ascend policy set --app 'My Bot' --category data_leak=high
ascend policy push --app 'My Bot' --dry-run
ascend policy push --app 'My Bot'
```

### `ascend policy set`

A CONTROL belongs to the platform — it is a check Ascend runs. A GATE POLICY belongs to you: a file in your repo saying how much you care about that control's findings, and when a pipeline should fail. So `--control tool_misuse=critical` means: in MY policy, treat findings from the platform's tool_misuse control as critical. It does not change the control itself. Per-CATEGORY severity can be pushed to the app (`ascend policy push`); per-CONTROL severity has nowhere to live in the API, so it stays local and applies to `ascend results` and `ascend ci`.


| Flag | Value | Default | What it does |
|---|---|---|---|
| `--app` | `APP` | — | scope to one app (default: the global default block) |
| `--fail-on-severity` | `critical|high|medium|low` | — | — |
| `--fail-on-new` | — | — | fail on new findings vs a baseline |
| `--allow-new` | — | — | do NOT fail on new findings |
| `--control` *(repeatable)* | `CONTROL=SEVERITY` | — | how severe THIS policy treats a control's findings (repeatable). Local only — the API has nowhere to put it. |
| `--category` *(repeatable)* | `CATEGORY=SEVERITY` | — | how severe THIS policy treats a category's findings (repeatable). Can be sent to the app with `ascend policy push`. |
| `--policy` | `POLICY` | — | policy file path |

```bash
ascend policy set --fail-on-severity high
ascend policy set --app 'My Bot' --control tool_misuse=critical
ascend policy set --category data_leak=high
```

### `ascend policy show`

show the effective policy


| Flag | Value | Default | What it does |
|---|---|---|---|
| `--policy` | `POLICY` | — | policy file path |

### `ascend reports`

assessment results as a table (severity, score, pass/fail, findings)


| Flag | Value | Default | What it does |
|---|---|---|---|
| `--app` *(repeatable)* | `APP` | — | limit to these apps (repeatable) |
| `--detail` | — | — | add pass/fail, probe and finding counts (one extra call per run) |
| `--per-app` | `PER_APP` | `1` | how many recent runs per app |
| `--min-sev` | `critical|high|medium|low|info|none` | — | only this severity or worse. A finished run whose severity cannot be read is always shown, never filtered out. |
| `--since` | `DAYS` | — | only runs newer than this many days, e.g. 30 or 30d |
| `--sort` | `sev|fail|when` | `sev` | — |
| `--include-running` | — | — | also show unfinished assessments |
| `--policy` | `POLICY` | — | policy file (default ./ascend-policy.json or $ASCEND_POLICY) |

```bash
ascend reports                      # latest run per app
ascend reports --detail             # + probe/finding counts
ascend reports --min-sev high --sort sev
ascend reports --app 'My Bot' --per-app 5 --json
```

### `ascend results`

Show results. One command, two sources. With NO file it reads the platform: your assessments as a table (severity, score, pass/fail). With a FILE it reads that file — a Console CSV export is rolled up by the platform's own taxonomy (category, control, data class) plus the evasion technique that worked; a saved transcript is rendered turn by turn. The route is sniffed from the file's contents, not its extension.

- **`file`** (optional) — a Console CSV export or a saved transcript. Omit it to see your assessments from the platform instead.


| Flag | Value | Default | What it does |
|---|---|---|---|
| `--by` | `SECTIONS` | — | comma-separated rollups: category,evasion,control,risk,dataclass,combo (default: category,evasion,control). An unknown name is refused. |
| `--values` | — | — | rank the concrete values the target produced, with provenance |
| `--all-values` | — | — | with --values, also show values that came FROM THE PROMPT (the target repeating back what the attacker supplied — not a disclosure) |
| `--turns` | — | — | print the failing turns (prompt/answer/why) |
| `--errors` | — | — | list probes the target never answered |
| `--matrix` | — | — | guardrail confusion matrix from the platform's own FP/FN flags |
| `--limit` | `N` | — | cap rows per section; 0 shows everything (default: per-section caps) |
| `--md` | — | — | emit Markdown instead of a table |
| `--no-catalog` | — | — | skip the /ascend/controls fetch; roll up on raw ids (fully offline) |
| `--follow`, `-f` | — | — | tail a transcript live as probes are answered |
| `--verbose`, `-v` | — | — | show each response body |
| `--interval` | `INTERVAL` | `2.0` | seconds between polls when following |
| `--app` *(repeatable)* | `APP` | — | only this app (name or aapp_ id); repeatable |
| `--detail` | — | — | add probe and finding counts (one extra call per assessment) |
| `--per-app` | `N` | `1` | how many assessments to show per app |
| `--min-sev` | `critical|high|medium|low|info|none` | — | only this severity or worse. An assessment that finished but whose severity cannot be read is always shown, never filtered out. |
| `--since` | `DAYS` | — | only assessments newer than this, e.g. 30 or 30d |
| `--sort` | `sev|fail|when` | `sev` | — |
| `--include-running` | — | — | also show unfinished assessments |
| `--policy` | `POLICY` | — | gate policy file (default ./ascend-policy.json or $ASCEND_POLICY) |

```bash
ascend results                                # every app's latest assessment
ascend results --app 'My Bot' --detail        # + probe and finding counts
ascend results --min-sev high --sort score
ascend results run.csv                        # failures by category/evasion/control
ascend results run.csv --values               # the data harvest
ascend results run.csv --turns --limit 5      # the failing turns themselves
ascend results run.csv --matrix               # guardrail confusion matrix
ascend results run.csv --md > findings.md     # for a report or PR comment
ascend results run.csv --json | jq .data.by_evasion
ascend results transcript.jsonl --follow      # live probe view
```

> from the platform (no file): from a file: units: PROBES, PASSED and FAILED are probe counts, not finding counts. Unanswered probes measured nothing and are never counted as passes.

## `ascend runtime`

### `ascend runtime start`

lease probes and relay them to a target via an adapter (see `bridge start --foreground`)


| Flag | Value | Default | What it does |
|---|---|---|---|
| `--adapter` | `ADAPTER` | — | adapter type (default: from the config) |
| `--config` **(required)** | `CONFIG` | — | config name in the config dir |
| `--api-key` | `API_KEY` | — | bridge key (tc-); else $STRAIKER_BRIDGE_API_KEY |
| `--app` | `APP` | — | resolve the bridge key from the local key store for this app |
| `--consumer` | `CONSUMER` | — | bridge consumer id (parallel bridges MUST differ; auto per app) |
| `--log-file` | `LOG_FILE` | — | write bridge logs here instead of stderr |
| `--status-file` | `STATUS_FILE` | — | force heartbeat+stats publishing for a relay that cannot be resolved to an app id (supervised children pass this; when the app IS known the heartbeat is published under it automatically) |
| `--qpm` | `QPM` | — | queries per minute against the target |
| `--max-workers` | `MAX_WORKERS` | — | concurrency (auto: 1 for stateful targets) |
| `--capture` | `CAPTURE` | — | jsonl file to record probe/result envelopes |
| `--wait-ms` | `WAIT_MS` | `25000` | long-poll hold in ms (server clamps to 0-55000) |
| `--assessment-id` | `ASSESSMENT_ID` | — | the assessment this bridge serves; it self-stops when that run ends |
| `--idle-timeout` | `IDLE_TIMEOUT` | — | seconds a paused, already-probed bridge waits before self-stopping. 0 never idle-stops (the default); the bridge stops when the run reaches a terminal state. $ASCEND_BRIDGE_IDLE_TIMEOUT sets this default for auto-managed runs. |
| `--no-self-reconcile` | — | — | do NOT self-stop on assessment completion (stay up until stopped manually) |

> example: STRAIKER_BRIDGE_API_KEY=tc-... ascend runtime start --adapter direct_api --config mybot

### `ascend status`

where things stand: tenant, apps, live runs, bridges (one call)


| Flag | Value | Default | What it does |
|---|---|---|---|
| `--quick` | — | — | skip the per-app assessment fan-out (fast, no live-run detail) |

```bash
ascend status            # the whole picture
ascend status --quick    # skip the per-app assessment scan
ascend status --json     # for agents/scripts
```

## `ascend target`

add, list, inspect and re-check the targets you assess

### `ascend target add`

onboard a target from a URL, a cURL/HAR file, or a saved config

- **`source`** (optional) — a URL, a cURL/HAR file, or a saved config name — detected for you


| Flag | Value | Default | What it does |
|---|---|---|---|
| `--api` | `URL` | — | an HTTP API endpoint (or base URL) — one probe, no browser. The simple-contract one-liner. |
| `--ws` | `URL` | — | a WebSocket endpoint (ws:// or wss://) — connects, works out the frame contract, no browser |
| `--url` | `URL` | — | live page with a chat widget: capture the contract in a real browser |
| `--curl` | `FILE` | — | a curl command in a file (or '-' for stdin) |
| `--har` | `HAR` | — | HAR file exported from your own browser (no browser needed here) |
| `--config` | `NAME|PATH` | — | a config already on disk — a name in the config dir, or a path to a .json file anywhere (skip discovery) |
| `--module` | `FILE.py` | — | a custom adapter you wrote: a Python file with `def send_prompt(prompt: str) -> str`. Use this when the contract cannot be derived — signed requests, a multi-step handshake, an async poll. It is proven against the live target like any other. |
| `--scaffold` | `FILE.py` | — | write a working custom-adapter stub to this path and stop. Edit it, then re-run with --module to onboard it. |
| `--name` | `NAME` | — | application name in Ascend (default: derived from the URL) |
| `--app` | `NAME|aapp_id` | — | bind to an application that ALREADY exists in the Console instead of creating one — its bridge key is fetched for you. Use this when the app was set up in the UI and all that is missing is something serving it. |
| `--save-as` | `NAME` | — | name the adapter config (default: derived from the URL, e.g. 'myhost-com'). Use this and you always know what to pass to --config. |
| `--system-prompt` | `SYSTEM_PROMPT` | — | what the target is, for the assessment context |
| `--controls` | `CONTROLS` | — | comma-separated control ids (validated before the run) |
| `--adapter` | `ADAPTER` | — | override the adapter type (default: from the config) |
| `--header` *(repeatable)* | `'Name: value'` | — | raw header (repeatable), honored by all sources, e.g. 'X-Api-Key: …'. A value written env:NAME is read from the environment and never stored in the config |
| `--bearer` | `TOKEN` | — | Authorization: Bearer <token>; env:NAME keeps the token out of the config |
| `--api-key` | `NAME:VALUE[:in=header|query]` | — | API key, e.g. 'x-api-key:abc', 'key:abc:in=query', or 'x-api-key:env:MY_KEY' to reference the environment instead of storing the value |
| `--basic` | `USER:PASS` | — | HTTP Basic auth; 'user:env:MY_PW' references the password |
| `--cookie` | `'k=v; k2=v2'` | — | Cookie header for a session-gated target; 'session=env:MY_SESSION' references the value |
| `--token-file` | `PATH` | — | read a bearer token from this file |
| `--body-field` *(repeatable)* | `key=value` | — | extra JSON body field, repeatable — for agents whose key/tenant lives in the BODY, e.g. --body-field apiKey=abc --body-field workspace=support. Use key:=raw for a non-string literal (true/1/{...}). |
| `--login-url` | `URL` | — | POST here first to exchange creds/code for a token |
| `--login-body` | `JSON|FORM` | — | body for --login-url. JSON ('{"code":"1234"}') or form-encoded ('grant_type=client_credentials&client_id=…') — OAuth2 is form-encoded. |
| `--token-path` | `DOTPATH` | `token` | dot-path to the token in the login response (default: token) |
| `--login-method` | `POST|GET` | `POST` | verb for --login-url (default: POST). GET for a bootstrap page that sets a session cookie or embeds a CSRF token. |
| `--token-regex` | `RE` | — | extract the token with a regex (first capture group) instead of --token-path — for a token embedded in HTML, e.g. 'csrf-token" content="([^"]+)' |
| `--token-header` | `NAME` | — | send the extracted token in this header verbatim (e.g. X-CSRF-Token) instead of as 'Authorization: Bearer <token>' |
| `--insecure` | — | — | skip TLS verification (self-signed internal targets) |
| `--ca-bundle` | `PATH` | — | custom CA bundle for TLS verification |
| `--client-cert` | `PATH` | — | client certificate (PEM) for mTLS |
| `--client-key` | `PATH` | — | client private key (PEM) for mTLS |
| `--proxy` | `URL` | — | HTTP(S) proxy for the probe/validate calls |
| `--cdp` | `ENDPOINT` | — | with --url: attach to a browser you are ALREADY signed into (start it with `chrome --remote-debugging-port=9222`) instead of launching one. The only route into an Entra / SAML / SSO-gated target. Default endpoint http://127.0.0.1:9222; the written adapter attaches the same way, and your browser is never closed. |
| `--allow-internal` | — | — | allow link-local/cloud-metadata hosts (169.254/fd00::) — off by default |
| `--prompt-hint` | `PROMPT_HINT` | — | with --curl: the literal prompt text used in that command |
| `--size` | `small|medium|large` | `small` | assessment size |
| `--qpm` | `QPM` | `20` | queries per minute against the target |
| `--prompt` | `PROMPT` | `Hello, what can you help me with?` | benign prompt used for capture and validation |
| `--settle` | `SETTLE` | `8` | seconds to wait for the widget/reply during capture |
| `--headless` | — | — | headless capture (bot protection often blocks it) |
| `--manual` | — | — | you drive the widget; we record |
| `--timeout` | `TIMEOUT` | `60.0` | per-request timeout for validation |
| `--dry-run` | — | — | stop after validating the config — do not register or run anything |
| `--force` | — | — | register even if the target answers two different questions identically (normally refused: that config can only produce a false pass) |
| `--wait` | — | — | block until the assessment completes, then print findings |
| `--detail` | — | — | with --wait, show key findings per control |
| `--interval` | `INTERVAL` | `20` | poll interval while waiting |
| `--timeout-assess` | `TIMEOUT_ASSESS` | `7200` | max seconds to wait for completion |
| `--assessment-name` | `ASSESSMENT_NAME` | — | assessment name (default: '<app> run 1') |
| `-v`, `--verbose` | — | — | debug logging for the bridge |
| `--run` | — | — | continue into an assessment once the target is registered |

```bash
ascend target add https://your-bot.example.com/chat
ascend target add ./request.curl --name 'Support Bot'
ascend target add ~/Downloads/session.har
ascend target add mybot --run          # existing config, then assess
```

### `ascend target check`

re-prove a target against its live endpoint (the hard gate)

- **`target`** (required) — target name, config name, or aapp_ id


| Flag | Value | Default | What it does |
|---|---|---|---|
| `--prompt` | `PROMPT` | `Hello, what can you help me with?` | prompt to send |
| `--expect` | `EXPECT` | — | require this substring in the reply |
| `--timeout` | `TIMEOUT` | `60.0` | per-request timeout in seconds |
| `--adapter` | `ADAPTER` | — | override the adapter type (default: from the config) |

### `ascend target list`

every target: its adapter, whether it is registered, whether it is serving


### `ascend target rm`

delete the application and drop its stored key

- **`target`** (required) — target name or aapp_ id


| Flag | Value | Default | What it does |
|---|---|---|---|
| `--keep-key` | — | — | leave the stored bridge key in place |

### `ascend target show`

everything bound to one target, in one place

- **`target`** (required) — target name or aapp_ id


### `ascend target types`

the kinds of target this can speak to (adapter types)


## `ascend tenant`

the single-tenant lock

### `ascend tenant show`

which tenant this CLI is locked to


### `ascend tenant switch`

move to another tenant (clears stored keys)


| Flag | Value | Default | What it does |
|---|---|---|---|
| `--confirm` | — | — | required: this clears stored keys |
| `--force` | — | — | switch even if bridges are running |

### `ascend version`

print version
