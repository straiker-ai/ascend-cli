# Usage

Each section is a complete how-to with `ascend` commands. Set your PAT once:

```bash
export STRAIKER_PAT='s6r_pat_…'
ascend doctor          # confirm the PAT exchanges, the API + bridge are reachable
```

`ascend doctor` exits non-zero if anything is wrong. Wire it into scripts before a run.

---

## 1. Onboard a target

A **target** is the thing you assess. It used to be four objects you held in your head and kept in
sync by hand — an adapter config, an application record, a stored bridge key, a purpose string —
and any one of them drifting broke a run in a way that looked like something else. `ascend target`
is one noun for all four:

```bash
ascend target add https://your-bot.example.com/chat \
  --name 'My Bot' --controls sys_prompt_leak,pii_leak
```

`target add` detects what you handed it, so there is no source flag to choose first:

| what you have | what you run |
|---|---|
| a URL | `ascend target add https://your-bot.example.com/chat` |
| a request copied out of devtools (**Copy as cURL**) | `ascend target add ./request.curl` |
| a browser session exported from devtools | `ascend target add ~/Downloads/session.har` |
| a config already on disk | `ascend target add mybot` |

One call builds the adapter, proves it against the live endpoint, registers the application as a
`bridge` app and stores the `tc-` key — then **stops**. Registering a target and spending an
assessment are separate decisions:

```bash
ascend target add ./request.curl --run       # continue straight into an assessment
ascend target add ./request.curl --dry-run   # stop after validation; register nothing
```

Then, day to day:

```bash
ascend target list             # adapter, config, whether registered, whether serving
ascend target show 'My Bot'    # app id, adapter, endpoint, masked key, last verified reply
ascend target check 'My Bot'   # re-prove it against the LIVE endpoint, and time it
ascend target rm 'My Bot'      # delete the application and drop its stored key (asks on a terminal; --yes skips)
```

`target check` is the first thing to run when a run comes back suspiciously clean. It exits
non-zero when the adapter can no longer talk to the target — an expired session token is the usual
cause — and warns when the measured reply time cannot survive the platform's per-probe window.

Nothing was removed to make room for this. `app`, `adapter`, `keys` and `onboard` are the machinery
underneath `target` and behave exactly as before; the sections below drive them directly, for when
the individual steps matter.

---

## 2. Onboard a reachable API target (direct `api` app)

Use this when the target is a plain REST endpoint with stable auth that Ascend can call itself,
with no runtime process and no bridge. `adapter build` already produces the url, templates and
headers an `api` app needs, so the built config feeds the create:

```bash
ascend adapter build --api https://bot.example.com/v1/chat --bearer "$TOK" --out mybot.json
ascend app create --type api --name 'My Bot' --config mybot \
  --target-api-key "$TOK" --controls sys_prompt_leak,pii_leak
```

Then run the assessment directly (Section 4) — there is no bridge to start. Note the no-space
`{{PROMPT}}` / `{{RESPONSE}}` gotcha: the templates are enforced literal.

---

## 3. Onboard a bridge target (adapter + relay)

Use this for anything Ascend can't call directly: browser widgets, session handshakes, SSE
reassembly, OAuth, WebSocket framing, or egress from inside your network. A **bridge** app has
its adapter on your side; the CLI relays each probe to the target. You do NOT start the relay by
hand for a normal run. `ascend assess run` starts it before probes are scheduled and it
self-stops when the run reaches a terminal state.

`ascend target add` (Section 1) collapses steps 1 and 2 into one call, and `--run` takes step 3
as well. Do them by hand when you are writing the config yourself — for an adapter whose contract
no capture can infer.

**Step 1: register the bridge app** (`bridge` is the default type; prints the `tc-` key ONCE):

```bash
ascend app create --name 'My Bot' --config mybot \
  --controls sys_prompt_leak,pii_leak --size small --qpm 30
# app_id:  aapp_…
# tc_key:  tc-…   (stored in the local key store for this app — shown ONCE)
```

**Step 2: write an adapter config** at `configs/mybot.json` (schema per adapter in
`docs/ADAPTER_AUTHORING.md`):

```json
{
  "adapter": "direct_api",
  "endpoint": "https://bot.example.com/v1/chat",
  "method": "POST",
  "headers": {"Authorization": "Bearer …"},
  "body": {"prompt": "{{PROMPT}}"},
  "response_path": "choices.0.message.content",
  "timeout_ms": 30000
}
```

Sanity-check it before running:

```bash
ascend adapter list                 # the 15 adapter types
ascend adapter configs              # every config on disk, and where new ones are written
ascend adapter show mybot           # echo the config back (secrets masked)
```

A config is resolved per **file**, across every config directory in turn: `$ASCEND_CONFIG_DIR`,
then `./configs`, then `~/.ascend/configs`, then the examples bundled with the CLI. Precedence is
unchanged, and new configs are still written to a single directory — the one `adapter configs`
names. Lookup used to stop at the first directory that *existed*; since every checkout ships a
`configs/` of examples, running from a checkout hid `~/.ascend/configs` entirely, so a config
written in one directory was "config not found" in another. The app's key resolved fine either way
(keys live in `~/.ascend`), which is what made it read as a flaky bridge rather than a lookup bug.

**Step 3: run the assessment** (Section 4). It auto-starts the bridge for this app up front, so
the first probes are never dropped, and the bridge self-stops when the run ends:

```bash
ascend assess run --app 'My Bot' --name 'run 1' --controls sys_prompt_leak,pii_leak
```

The bridge is per-app: one relay is shared across that app's assessments, with no
cross-assessment contamination. It never self-stops while it cannot verify state, so an
unanswered run cannot score a false pass.

---

## 4. Run and monitor an assessment

The lifecycle is *create → pause → resume → poll*. `ascend assess run` does it in
one command:

```bash
# validate the control selection first (optional but recommended)
ascend controls validate sys_prompt_leak,pii_leak

# run and stream progress to stderr until it finishes
ascend assess run --app 'My Bot' --name 'run 1' \
  --controls sys_prompt_leak,pii_leak
```

Non-blocking / scripted variants:

```bash
ascend assess run --app 'My Bot' --name 'run 1' --no-wait --json   # kick off, return now
ascend assess list --app 'My Bot' --json                           # find the assessment id
ascend assess status  --app 'My Bot' --assessment <aid>            # poll status/progress
ascend assess results --app 'My Bot'                               # latest finished run (or --assessment <aid>)
ascend assess pause   --app 'My Bot' --assessment <aid>            # pause / resume as needed
ascend assess resume  --app 'My Bot' --assessment <aid>
```

`--app` accepts an `aapp_` id or a (unique substring of a) name — except for commands that change
or delete an app (`app update`/`delete`, `target rm`, `keys add`/`rm`, `bridge stop`, `assess
pause`/`resume`, `policy push`), which take the exact name or the id. Add `--json` to any command
for machine-readable output.

Bridge lifecycle across pause/resume:

- While an assessment is **paused** the bridge stays alive; it self-stops only when the run reaches a terminal state (idle cleanup is opt-in via `--idle-timeout`).
- `ascend assess resume` re-ensures a bridge. This is the reliable path after a resume done in the
  Console, since the SaaS cannot start a process on your machine.
- If state changed in the Console and local bridges drifted, reconcile them:

  ```bash
  ascend bridge sync             # every app you hold a key for; live runs you cannot serve are listed, not failed
  ascend bridge sync --app 'My Bot'   # just this one
  ```

---

## 5. Multi-turn / session targets

Some targets carry conversation state (a session id, a thread, an open widget). In pull-mode
Ascend sends only the *prompt*; the bridge owns continuity. This is handled automatically:
the twelve **stateful** adapters (`session_api`, `session_poll`, `sentinel_stream`, `browser`,
`amazon_connect`, `scrt2_direct`, `agentforce`, `slack_direct`, `copilot_studio`,
`websocket_direct`, `bedrock`, `custom`) run at concurrency **1** by default so exactly one
conversation is ever in flight, and a persistent adapter instance threads the turns.
`ascend assess run` auto-starts the bridge at the right concurrency for the config, with no flag
needed:

```bash
ascend assess run --app 'My Bot' --name 'run 1' --controls sys_prompt_leak,pii_leak
```

If the target echoes a stable correlation value, run conversations concurrently by setting
`conversation_key` and `max_workers` in the config; the auto-started bridge picks them up.

The full model, covering sequential-vs-concurrent policy, `conversation_key`, and identity rotation, is in
`docs/MULTI_TURN.md`.

---

## 6. Browser and terminal targets

**Browser** (`browser` adapter): for chat widgets with no API. Needs Playwright:

```bash
python3 -m pip install playwright && playwright install chromium
ascend assess run --app 'My Bot' --name 'run 1' --controls sys_prompt_leak,pii_leak
```

`assess run` auto-starts the bridge, which keeps one headless Chromium session open, runs
`pre_actions` (navigate, dismiss popups, open the widget) once, then fills + sends + waits for
each probe. Stateful → runs sequentially.

**Terminal**: targets driven through a terminal multiplexer need `tmux`. `ascend doctor`
reports whether `tmux` is present (it's optional and only warns when missing):

```bash
ascend doctor            # look for: [ok] tmux present (terminal targets only)
```

---

## 7. Reporting and CI

- **Export findings**: `ascend export --format sarif|json|csv|markdown` turns a completed
  assessment into a file you can attach or submit.
- **Gate a pipeline**: `ascend ci --baseline baseline.json` exits `2` on new findings or a
  severity breach, and `1` only if the tool itself failed, so CI can tell them apart.
- **Keep the evidence**: `ascend chat <target|config> --out <file.jsonl>` records a session's prompts
  and responses (header-redacted, `0600`); chat is auto-recorded to `captures/` by default.



## Talking to a target by hand

Before (or instead of) a full assessment, talk to it directly:

```bash
ascend chat 'My Bot'            # a target name from `target list`, a config name, or a URL
you › what can you help me with?
mybot › I can help with orders, returns and billing.
  (412ms · http 200)
you › /results
you › /exit
transcript: captures/mybot-20260816-204133.jsonl
replay it:  ascend results captures/mybot-20260816-204133.jsonl
```

Everything is recorded by default in the same evidence format the relay writes, so a
manual session and a platform-driven run are analysed the same way. To watch a live
assessment relay its probes in real time:

```bash
ascend bridge start --config mybot --capture captures/run.jsonl &
ascend results captures/run.jsonl --follow
```
