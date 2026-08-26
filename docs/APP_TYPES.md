# Application types

An Ascend application declares **how the platform reaches your target**. There are four types, and
the choice decides one thing above all: *does the adapter run on your side?*

```
ascend app create --type bridge|api|gcp|bedrock --name 'My Bot' ...
```

| Type | How Ascend reaches the target | Bridge? | Use it when |
|---|---|---|---|
| `bridge` | Hands prompts to the CLI relay running on **your** side, which calls the target | **Yes** | The target is internal, behind auth/VPN, needs a browser, or speaks a protocol only your adapter knows |
| `api` | Ascend calls your HTTP endpoint directly | No | The target is reachable from the internet with a static key and a simple request/response shape |
| `gcp` | Native Vertex AI / Agent Engine integration | No | Vertex Agent Engine, ADK on Vertex |
| `bedrock` | Native AWS Bedrock integration | No | Bedrock agents and runtimes |

`bridge` is the default because it is the one that always works: whatever the target does, the CLI's
adapter layer can be taught to speak it, and the relay runs on your side of the network boundary.
Pick `bridge` when **either** Ascend can't reach the target **or** the adapter has to run locally
(code, browser, signed requests, stateful sessions) — if it needs a locally-run adapter, it's a
bridge app. `ascend assess run` starts and stops the bridge for you (see below); you don't run one
by hand for a normal assessment.

## Required fields per type

These are validated **locally, before the request**, so a gap reads as a named field rather than a
422 from the API.

| Type | Required |
|---|---|
| `bridge` | `request_template`, `response_template`, `headers` — all defaulted, so `--name` alone works |
| `api` | `url`, `api_key`, `request_template`, `response_template`, `headers` |
| `gcp` | `url`, `service_account_info` |
| `bedrock` | `url`, `bedrock_authentication_method` (`assume-role` or `access-key`) |

```
$ ascend app create --type gcp --name 'Vertex Agent' --url https://…:streamQuery
error: a 'gcp' application needs: url, service_account_info
  missing: service_account_info
```

## The four, in practice

### `bridge` — the default

```bash
ascend adapter build --api https://internal.corp/chat --bearer "$TOK" --out mybot.json
ascend app create --name 'My Bot' --config mybot --controls sys_prompt_leak,jailbreak
ascend assess run --app 'My Bot' --name 'run 1'
```

No manual `ascend bridge start`. `ascend assess run` on a bridge app **auto-starts** the bridge
before probes are scheduled, and the bridge **self-stops** when the assessment reaches a terminal
state. While an assessment is paused the bridge stays alive and keeps serving; idle cleanup is opt-in
via `--idle-timeout` (off by default), so a platform stall never stops it. It
never self-stops when it cannot verify state — an unverifiable stop would risk a false pass, so the
relay stays up.

`ascend assess resume` re-ensures a bridge — the reliable path after a Console-side resume, since
the SaaS can't start a process on your machine. If state changed in the Console and a bridge is out
of sync, `ascend bridge sync` reconciles: it starts bridges for running/paused apps and stops them
for terminal ones.

A bridge is per-**app**: one relay is shared across that app's assessments, with no cross-assessment
contamination. The v2 lease/result protocol carries only an opaque `request_id`/`msg_id` that the
bridge echoes back; the platform attributes each probe to its assessment.

The create response carries the bridge key (`tc-…`) **exactly once**. The CLI stores it for you; if
the API ever returns a create without one, the command fails loudly rather than leaving an app no
bridge can serve.

`ascend bridge start` still exists for advanced use — a remote or long-lived host, a continuous
relay, pre-starting before a run — but it is not a step in the normal flow.

### `api` — no bridge needed

The url, templates and headers come straight from a mapped config, since `ascend adapter build` already
produces exactly those fields:

```bash
ascend adapter build --api https://api.example.com/chat --bearer "$TOK" --out mybot.json
ascend app create --type api --name 'Public Bot' --config mybot --target-api-key "$TOK"
ascend assess run --app 'Public Bot' --name 'run 1'      # no bridge to start
```

Ascend calls the target from its own infrastructure, so the target must be reachable from the
internet and the key must be one the platform can hold. This type never appears in `bridge ls` and
never triggers the NO-BRIDGE alarm.

### `gcp`

```bash
ascend app create --type gcp --name 'Vertex Agent' \
  --url 'https://us-central1-aiplatform.googleapis.com/v1/projects/P/locations/us-central1/reasoningEngines/ID:streamQuery' \
  --service-account @sa.json
```

`--service-account` takes `@path` so a service-account JSON is never pasted onto a command line
(where it would land in shell history).

### `bedrock`

```bash
# assume-role (preferred)
ascend app create --type bedrock --name 'Bedrock Agent' \
  --url 'arn:aws:bedrock:us-east-1:123456789012:agent/AGENTID' \
  --bedrock-auth assume-role \
  --role-arn 'arn:aws:iam::123456789012:role/StraikerAscend' \
  --external-id "$EXT" --region us-east-1

# static keys
ascend app create --type bedrock --name 'Bedrock Agent' --url 'arn:…' \
  --bedrock-auth access-key --access-key-id "$AKID" --secret-access-key "$SECRET"
```

Credential fields you do not pass are omitted from the request rather than sent empty.

## Which apps need a bridge

```bash
ascend app list --with-runs     # STATE column
ascend bridge ls                # bridge-based apps only; flags live runs with no bridge
```

The NO-BRIDGE alarm is deliberately scoped to `bridge` apps. Flagging an `api`/`gcp`/`bedrock` app for
having no bridge would be a false alarm, and a false alarm trains people to ignore the one alarm
that matters — a live assessment with nobody answering scores a **false pass**, because unanswered
probes are not findings.

## Severity and guardrails at create time

```bash
ascend app create --name 'My Bot' \
  --category-severity data_leak=high \
  --input-guardrail http_status_code=403
```

**`--category-severity`** maps to the app's real `category_severities` field. The platform's enum is
`default|low|medium|high` — there is no `critical`, so a policy asking for it is clamped to `high`
and the command says so. Per-**control** severity is not settable anywhere in v3; express that in
`ascend-policy.json` instead, where it applies to `ascend reports` and `ascend ci`.

**`--input-guardrail`** tells the platform how the target signals a block — an HTTP status
(`http_status_code=403`) or text (`response_pattern='I can't help with that'`, pipe-separated for
several). Without it, a guardrail block looks identical to the target genuinely answering, which is
what produces guardrail false positives in scoring.

To change either later:

```bash
ascend policy set --app 'My Bot' --category data_leak=high
ascend policy push --app 'My Bot'          # sends the CATEGORY half upstream
```

`push` reports which per-control overrides stayed local, so nobody assumes they reached the Console.

## Changing an app's type

You cannot. `api_type` is fixed at creation — the create body is a discriminated union on it.
Delete and recreate:

```bash
ascend app delete 'My Bot'        # also drops its stored bridge key
ascend app create --type api --name 'My Bot' --config mybot --target-api-key "$TOK"
```

Deleting removes the stored key too: a `tc-` key without its app is a dead secret on disk.
