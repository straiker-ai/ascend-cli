---
name: build-adapter
description: >-
  Turn captured target traffic (a HAR export, a browser in-page capture, or a
  proxied send) into a validated Ascend adapter config. Drives the deterministic
  `ascend adapter build` classifiers, resolves only the low-confidence layers with
  judgment, and gates on `ascend adapter validate` against the live target. Use
  when onboarding a new red-team target whose transport/auth/session shape is not
  already a known preset, or when an existing config stops matching the target.
---

# build-adapter

> **Try the bare URL first.** A create-then-message target — one that needs `POST /session`
> before `POST /session/{id}/message` — is now derived automatically by
> `ascend target add <url>`, which emits a `session_api` config whose `message_endpoint` carries
> `{{SESSION_ID}}`. Capturing a HAR for that shape is a fallback, not the opening move. Reach for
> the capture path when the bare URL genuinely fails, or when the flow needs a step the prober
> cannot guess (a login page, a GraphQL operation, a browser-only widget).


An adapter is **not** a class you pick from a list. It is a **composition of six
orthogonal layers**, each with a finite set of values. This skill is the reasoning
wrapper around a deterministic pipeline: the CLI classifies each layer from
evidence, you resolve only the ambiguous residue, and the CLI **validates** the
composition against the live target before anything ships. Determinism lives in
the CLI; you supply judgment only where a classifier reports low confidence.

Read `docs/CAPABILITY_MATRIX.md` (the full contract) before starting. `ascend
adapter layers` prints it. This skill assumes it.

> **Hard rule: never ship an unvalidated config.** A config that has not passed
> `ascend adapter validate` (replay of the captured turn *and* a fresh probe,
> compared to the observed answer) is not done. A plausible-looking config that
> silently mis-parses the target produces a whole assessment of garbage results.

`ascend` below means `python3 shells/cli/ascend.py`.

## The six layers (what you are composing)

One value per layer, plus that value's params:

1. **Transport & assembly** — `rest_json` · `sse` · `ndjson` · `websocket` ·
   `poll` · `browser_dom` · `terminal`. *How a response is carried and reassembled.*
2. **Auth** — `none` · `static` · `mtls` · `derived_multihop` · `oauth2` · `csrf`.
   *How one request is authorized.*
3. **Auth lifecycle** — `static` · `refresh_on_ttl` · `reauth_on_401` ·
   `cookie_rotation`. *How the credential stays valid over a long run.* This one is
   declared with an `auth` block and is the usual cause of a run that dies half way —
   see **Layer 3 in practice** below.
4. **Session / conversation** — `stateless` · `create_session` ·
   `create_conversation` · `warmup` · `multi_turn`. *How turns bind together.*
5. **Identity** — `fixed` · `rotate_per_conversation` · `rotate_per_n` ·
   `fresh_per_probe`. *Who is calling (mostly an ROE choice, not auto-detected).*
6. **Rate / concurrency** — `qpm`, `max_workers`, `per_identity_qpm`. Cross-cutting;
   `max_workers` auto-defaults to 1 for stateful, 10 for stateless.

## Layer 3 in practice: keeping a credential alive for a whole run

This is the single most common reason an onboarded target stops working part-way through
an assessment, and it does not look like an auth problem — it looks like a well-behaved
bot that refuses everything.

A token captured at build time (a mobile app's bearer, an OAuth access token, a login
cookie) is valid when you build the adapter and expired an hour into the run. Every probe
after expiry gets a 401, the adapter reports a failure, the scorer sees "no answer", and
the run finishes **looking clean while measuring nothing**. Worse: when probes keep
failing the platform **auto-pauses the assessment**, so the visible symptom is a stalled
run and an idle bridge — which reads as "the bridge died".

Declare it instead of pasting a token. For a credential that does not expire, give it on
the command line as an environment reference — `--bearer env:MY_TOKEN`,
`--api-key 'X-API-Key:env:MY_KEY'`, `--basic 'user:env:MY_PW'` — and the config carries the
reference, never the value; the relay resolves it on every run. For a credential that is
minted by a login, two separate blocks, because they answer two different questions —
**`auth`** is *who mints the credential* (Layer 2), and **`auth_lifecycle`** is *when to
re-acquire it* (Layer 3):

```json
"auth": {
  "type": "oauth2",
  "grant": "client_credentials",
  "token_url": "https://api.example.com/oauth/token",
  "client_id_ref": "env:MYBOT_CLIENT_ID",
  "client_secret_ref": "env:MYBOT_CLIENT_SECRET"
},
"auth_lifecycle": {
  "type": "reauth_on_401"
}
```

`grant` is `client_credentials` | `password` | `refresh` — use `refresh` with
`refresh_token_ref` for a mobile-style refresh-token flow. Other `auth.type` values are
`static` (bearer / api_key / basic / cookie), `mtls` and `csrf`.

> Secrets are `env:NAME` references, never inline literals — a config carrying a real token
> is refused. That is deliberate: configs get committed, pasted into tickets and shared.

| `auth_lifecycle.type` | use when | behaviour |
|---|---|---|
| `static` (default) | the credential outlives any run | never re-acquired |
| `refresh_on_ttl` | the token has a known TTL, or is a JWT | re-mints once `ttl_s` elapses, or when the JWT `exp` is within `skew_s` |
| `reauth_on_401` | expiry is unpredictable, or revocation happens | on a challenge status (default 401) re-acquires and retries the probe **once** |
| `cookie_rotation` | session-cookie targets | re-acquires on `interval_s` and whenever a response sets a new cookie |

This works for **every** adapter, because it is applied at the shared call seam rather than
inside individual adapters. `agentforce`, `copilot_studio` and `amazon_connect` additionally
mint and re-mint their own vendor credentials, so they need no `auth` block at all.

An `oauth2` config with no `auth_lifecycle` still refreshes on a fixed TTL, which is the
long-standing behaviour — but if the target's token is shorter-lived than that, say so
explicitly with `reauth_on_401`, or every probe between expiry and the next refresh is
scored as a refusal.

## Timeouts: never pin a value sized for a fast bot

Agentic targets routinely take **2-3 minutes** per reply and some take considerably
longer. A short timeout does not degrade gracefully — it converts a healthy slow target
into 100% probe failures, which then trips the platform's auto-pause. Measured live: a
110s target under a 20s config timeout failed *every* probe.

Only pin `timeout_ms` when you have measured the target and want to *cap* it. Otherwise
leave it out: the adapter's timeout is derived from the platform's per-probe window, so
there is nothing extra to set.

### The ceiling you cannot configure away

`timeout_ms` is not the binding constraint. **The platform gives a bridge a bounded window
to return each probe result** (~120s), and the bridge gives up just under it rather than
hold a worker open for a result nobody will accept.

So a target that reliably takes **longer than that cannot be assessed through the bridge
today**, no matter how large you make `timeout_ms`. That is a platform-side limit, not an
adapter bug. When you hit it:

- Do **not** keep raising `timeout_ms` — through the bridge it changes nothing.
- Say so explicitly rather than reporting the target as failing its probes.
- The platform window has to be raised first; then tell the CLI with
  `$ASCEND_PLATFORM_PROBE_WINDOW_MS`. That single variable moves the bridge's give-up point
  and the adapter timeout with it.

`ascend adapter validate` checks this for you: it prints the measured reply time and warns when the
target is at or beyond the window (unassessable) or close enough that queueing alone can blow it.
Treat that warning as a stop sign — the config being green does not mean the target can be run.

One subtlety worth knowing: the probe's clock starts when the platform **queues** it, not when the
bridge calls the target. A target comfortably under the window can still time out while waiting to
be leased, which is why QPM and `max_workers` matter for slow targets beyond simple politeness.

`timeout_ms` still matters everywhere else — `adapter validate`, `chat`, and any target
*under* the window — which is where a pinned 20-30s value silently fails everything.

## Mobile apps

You do not red-team the app binary; you red-team the **backend it calls**. Capture the
app's traffic (a proxy with the device trusting its CA, or a HAR from the web equivalent),
then build an adapter against that API exactly as for any other HTTP target. Mobile
backends are also the most likely place to need Layer 3 above: their tokens are usually
short-lived and refresh-token based.

**Ask for the API contract before you ask for a device.** The app is only a client; the API behind
it is reachable without it. One example request — a cURL, a Postman entry, an OpenAPI spec — plus
the auth scheme gets you to `--api` / `--curl` and skips device capture entirely. This is almost
always faster than arranging a proxied handset, and it is the same surface the app talks to.

If you must capture from the device, know the three walls before you promise a date:

| Wall | What you see | What it needs |
|---|---|---|
| CA not trusted | nothing decrypts | iOS: install the profile **and** enable it under Certificate Trust Settings. Both steps. |
| Android 7+ (API 24+) | browser traffic decrypts, app traffic does not | apps ignore user-installed CAs. Needs the CA in the **system** store (emulator/rooted) or a debug build whose `network_security_config` trusts user CAs. |
| **Certificate pinning** | app shows a network error; proxy logs a TLS handshake failure | **No proxy configuration fixes this** and no adapter source changes it — the app rejects the connection before anything is recorded. Needs a build with pinning disabled (ask the app team), or a runtime bypass (Frida/objection) which is invasive, breaks on updates, and usually requires written approval. |

Do not spend days on a pinning bypass. Escalate it as an app-team dependency and pursue the API
contract in parallel — that is the path that actually unblocks the engagement.

## Which adapter, and how each one bites

`adapter build` picks this for you from evidence. Read this when the pick looks wrong, when
validation fails, or when you are deciding whether a target is even reachable. The third
column is the failure that is *specific* to that shape — the one that does not look like a
bug when it happens.

| Target shape | Adapter | The way it fails |
|---|---|---|
| Plain REST, one request one answer | `direct_api` | `response_path` points at the wrong key: the scorer grades an envelope, not the reply |
| Answer arrives as a token stream | `sse_stream` | Read as REST you capture the first fragment. Choose `done_when` (a terminal event) over `idle_ms` when the stream declares an end; a mid-stream read timeout truncates silently |
| Reply framed by BEGIN/END markers | `sentinel_stream` | If the markers go undetected it falls through to `direct_api` and captures **wire protocol as the answer** — a config that validates while grading framing |
| WebSocket chat | `websocket_direct` | `framing: json` vs `text` is the whole game: wrong pick drops tokens or never assembles. Pick by `json.loads`-ing a frame |
| Create a session, then send | `session_api` | A mandatory greeting on the first turn scores as a PASS. Set `warmup_message` so the throwaway turn absorbs it |
| Create → send → poll for the answer | `session_poll` | Needs two budgets: per-HTTP-call and total-wait. One global timeout gives up mid-answer |
| Endpoint 403s any non-browser replay | `browser` | Anti-automation. `adapter build --url` falls back here automatically; `--manual` lets you drive the widget while it records |
| Salesforce Agentforce, authenticated | `agentforce` | Needs JWT-format bearer tokens enabled and an agent that is not type "Agentforce (Default)"; mints and re-mints its own credential |
| Salesforce public chat widget | `scrt2_direct` | The unauthenticated path — do not reach for it when the org has a real Agent API |
| Microsoft Copilot Studio | `copilot_studio` | Three credential sources (token endpoint, Direct Line secret, pre-minted bearer). Entra-gated bots need the delegated token, not the secret |
| Amazon Connect chat | `amazon_connect` | Participant/connection tokens are short-lived by design; the poll budget is separate from the request timeout |
| Slack-hosted bot | `slack_direct` | Needs a `xoxp` user token and replies arrive on a thread, so the read is a poll, not a response |
| Vertex AI / Agent Engine | `vertex_ai` | Defaults to ADC. Some orgs block service-account keys by policy, so ADC is the only route |
| AWS Bedrock | `bedrock` | Three modes; pick deliberately rather than letting the default decide |
| Fits nothing above | `custom_module` | `adapter build --code` writes the module and `adapter validate` proves it. A generated module that has not validated is a guess |

Two rules that apply to every shape:

- **Secrets are `env:NAME` references.** A config with a literal token in it is rejected, because
  configs get committed, pasted into tickets and shared.
- **A greeting, a consent banner or an error envelope can all validate.** Validation proves the
  target *answered*, not that you captured the *right* text. Read the `verified_answer` in the
  config's `_probe` block before trusting it.

## Workflow

### 1. Gather evidence
Get at least one **real answered turn** from the target, captured end to end:

- **HAR** — export from browser devtools (Network → Save all as HAR). Best when a
  login precedes the chat call (reveals L2 `derived_multihop` / L3 lifecycle).
- **Browser in-page capture** — when the target is only reachable inside a page
  (SPA, widget). Yields L1 `browser_dom` or an intercepted fetch/xhr.
- **Proxied send** — a single request you drove through a proxy.

You need the request(s) *and* the target's actual answer text, so validation has
a ground truth to compare against.

### 2. Run the deterministic classifiers
```
ascend adapter build --har <evidence.har>            # human summary
ascend adapter build --har <evidence.har> --json     # per-layer {value, params, confidence, evidence}
```
The output is one classification per layer: the chosen `value`, its `params`, a
`confidence`, and the `evidence` (which frames/headers drove the pick). Read it as
a draft config plus a confidence map — **not** a finished answer.

> If `discover` is unavailable in your build (it is the composable-layers phase; a
> scaffold exits non-zero pointing at the matrix), fall back to composing the
> config by hand from `docs/CAPABILITY_MATRIX.md` using the detect-by column for
> each layer, then jump straight to step 4 (validate). The validation gate is the
> real contract; discovery is an accelerant, not a substitute.

### 3. Resolve the low-confidence layers (this is the judgment step)
For every layer the classifier flagged low-confidence, decide with the evidence in
front of you. Do **not** guess blindly — pick the alternate that the evidence
supports and let validation arbitrate. The recurring hard cases:

- **WebSocket: chunked text vs JSON framing.** Try `json.loads` on each frame. If
  every frame parses as JSON → `framing: json` with a `response_path` into the
  frame. If frames are raw text fragments to concatenate → `framing: text` with
  `aggregate: concat`. Getting this wrong yields either dropped tokens or a stream
  that never assembles. Decide `done_when` (a sentinel/terminal frame) vs `idle_ms`
  (quiet-period close) the same way — prefer an explicit sentinel if one exists.
- **Multi-step create-conversation.** If a response **id reappears in a later
  request's URL or body** (id-flow), it is L4 `create_conversation`: capture the
  `create_req -> conversation_id`, then send to `/conversations/{id}/messages`.
  Distinguish from `create_session` (a session id used by sends but no per-message
  path) and from `warmup` (a mandatory greeting/consent turn whose first reply you
  discard).
- **Cookie / token re-auth.** If a login request **precedes** the chat request and
  its response value reappears downstream → L2 `derived_multihop` (chain the
  extract into the send). If `Set-Cookie` churns or the session dies after an
  interval → L3 `cookie_rotation`. If you observed a re-login after a 401/403 →
  L3 `reauth_on_401`. If the token carries an `exp` / documented TTL →
  `refresh_on_ttl`.
- **Rotating identity.** Mostly an ROE decision, not a wire signal. Choose
  `rotate_per_conversation` / `fresh_per_probe` when the target rate-limits or
  tracks per-user and you need probe isolation; supply the `identity_pool`. Default
  `fixed` unless there is a reason.
- **Rate / concurrency.** Leave `max_workers` on its auto-default (1 stateful, 10
  stateless) unless the target is fragile; set `qpm` to the agreed ROE cap.

### 4. Validate — the hard gate
Replay the captured turn **and** a fresh probe through the composed config against
the live target and compare to the observed answer:
```
ascend adapter validate --config <config> --json
```
Green (both replay and fresh probe match the observed answer) → the config is
shippable. Anything else → not done.

**Green is not enough on a streaming target — read the answer.** A 200 with a non-empty body is
indistinguishable from success, so a streaming target described as `direct_api` passes this gate
while its "answer" is the raw wire frames (`data: {"type": "text.delta", …}`). That config then
scores protocol noise for the whole assessment: the run completes, every probe is answered, and
nothing was measured. Check two things before you trust a green:

- the reply is the agent's **words**, not JSON frames or a `data:` prefix
- for a streaming target the config has `adapter: sse_stream` and a `stream` block naming
  `text_path` / `token_types` — not `response_path`

The CLI now detects this and re-validates as `sse_stream` automatically on every source, but the
check is cheap and it is the difference between a pass and a false pass.

**Name the config yourself.** Which flag depends on the command:

| Command | Flag | Where it writes |
|---|---|---|
| `adapter build`, `map`, `discover` | `--out <name>` | bare name → the config dir; `./name.json` or `dir/name` → exactly there, `.json` always appended |
| `target add`, `onboard` | `--save-as <name>` | the config dir, under the name you chose |

Left to itself the name is derived from the URL's host, so you get `myhost-com` or
`127-0-0-1-8791` and have to read it back out of stderr before you can pass `--config`.

Re-running against the **same** endpoint refreshes the config in place and carries forward its
`_ascend` app binding, so re-deriving does not unbind the target. A **different** endpoint under
an already-used name is saved as `<name>-2` instead of overwriting, and both are named in the
output. When the endpoint cannot be read from a config at all (`bedrock` carries only a region,
`session_poll` carries no URL), a re-run is treated as a refresh — never as a new target.

> The same gate, by target name once it is registered: `ascend target check <name>`. It
> replays a prompt through the live endpoint, times it, and warns when the reply time is
> close to the per-probe window. A config that cannot return one correct live answer is
> not validated.

### 5. Iterate the failing layer, not the whole config
On mismatch, the classifier's confidence map tells you which layer to suspect
first. Change **one** layer's value/params to its evidence-supported alternate
(WS `json`↔`text`, `done_when`↔`idle_ms`, `create_conversation`↔`create_session`,
add a `warmup`, add L3 `reauth_on_401`), then re-validate. Repeat until green. Do
not stack speculative changes — one variable at a time keeps the signal clean.

### 5b. When it CANNOT be derived: write the adapter as code

Derivation is deterministic composition from evidence. Some contracts cannot be expressed
that way at all, and iterating layers on those is wasted effort. **Stop deriving and write
the adapter** the moment you see any of these:

| Symptom | Why no config can express it |
|---|---|
| A signature or HMAC over body + timestamp | the value must be COMPUTED per request, not replayed |
| A nonce fetched per request | same — one-shot, cannot be a static value |
| A rotating conversation id (new id each turn) | the config would pin the id captured once |
| A reply assembled from several fields, or content blocks | there is no single `response_path` |
| SOAP / XML / protobuf / gRPC-Web framing | the readers parse JSON, SSE, NDJSON or text |
| A job you must poll to completion (`status: done`) | no shipped adapter models submit-then-poll-status |
| Two unrelated credentials, or an ordered multi-step handshake | one auth block cannot hold it |
| `transport` stays low-confidence after two evidence-supported alternates | the shape is not one of the known ones |

The contract is **one function**:

```python
def send_prompt(prompt: str) -> str:
    # anything: signed requests, a multi-step handshake, streaming reassembly,
    # an async poll, driving a browser. Return the agent's WORDS.
```

Do it in three commands:

```bash
ascend target add --scaffold ./my_adapter.py --api https://the-target/chat   # writes a stub
# edit send_prompt() until it returns the agent's reply
ascend target add --module ./my_adapter.py --name '<target>'                 # proves + registers
```

`--scaffold` seeds the stub with the target URL when you pass `--api`/`--url`. The module is
run by the bridge exactly like a built-in adapter, in a worker thread, and it passes the SAME
hard gate — nothing registers unless it answered the live target. Raise `timeout_ms` in the
pointer config if the target is slow; a custom adapter may take as long as it needs.

**Return the agent's words and nothing else.** A status line, a progress frame or a JSON
envelope returned from `send_prompt` becomes what the scorer reads as the agent's answer —
that is how a run comes back clean having measured nothing. See
`configs/example-custom_module.py` for a worked example (bootstrap token, message call,
nested reply extraction) and `docs/ADAPTER_AUTHORING.md` for the full contract.

A custom adapter is a first-class outcome, not a failure. Shipping a guessed config is the
failure.

### 6. Confirm and hand off
```
ascend adapter show <config>      # inspect the final composition
ascend adapter list               # confirm the transport/preset type resolves
```
Only a green-validated config proceeds to `onboard-target` / `assess run`. If you
genuinely cannot get a layer green, emit the low-confidence discover report plus
the raw evidence and escalate that specific layer — do **not** ship a guess.

## Troubleshooting: symptom -> what it actually is

**Read this before re-building anything.** Nearly every failure in this tool presents as a
different failure than it is: a platform pause reads as a dead bridge, an expired token reads
as a well-behaved bot refusing, and probes split across two relays read as nothing at all.
Diagnose in the order below, because step 1 rules out most of the table.

**Step 1 — always: `ascend bridge ls`. Read `ANS`.** It counts probes the target actually
answered. If it is zero, the target is not being tested and nothing else you observe means
anything yet.

| symptom | what it actually is | what to do |
|---|---|---|
| `answered=0`, `failed` climbing | the **adapter** is failing every probe, not the bridge | fix the adapter (timeout, credential). Restarting the relay changes nothing |
| worked for N probes, then everything "refuses" | a short-lived credential expired mid-run | `auth_lifecycle: reauth_on_401` (or `refresh_on_ttl`) |
| run sits at `paused`, bridge is healthy | the **platform** auto-paused after repeated probe failures | fix the adapter failure, then `assess resume` |
| every probe fails against a slow target | `timeout_ms` shorter than the reply time — 100% failure, not refusal | remove the pin; agents take 2-3 min. Then check the per-probe window below |
| target reliably takes longer than ~110s | the platform's per-probe window, which you cannot configure away | raise it platform-side first; `timeout_ms` will not help |
| clean score, suspiciously fast | probes went unanswered — a **false pass** | confirm `answered > 0` before believing any score |
| replies truncated or arriving as fragments | transport/assembly is wrong — a stream read as REST | re-check `sse` / `ndjson` / `websocket` framing |
| the "answer" looks like protocol, not prose | marker-framed stream misdetected as REST | `sentinel_stream` with the BEGIN/END markers |
| first turn passes, later turns lose context | session/conversation not carried | set the session id lifecycle; some targets also need `warmup_message` |
| every probe 403s but the same request works in a browser | anti-automation on the endpoint | `adapter build --url` (browser), `--manual` to drive it yourself |
| probes seem to vanish, throughput is half | two relays serving one app, splitting its probes | `bridge ls`; stop the one you started by hand |
| a create call errors but the thing exists | the response was dropped after the server acted | check `app list` before retrying, or you will duplicate it |

**When the tool is unhelpful rather than wrong.** Several failures above once surfaced only as
silence or a generic upstream error. If you hit an error that does not name a cause, treat it as
a diagnosis problem and gather evidence before changing config: `bridge ls` for `ANS`,
`adapter validate` for a single timed round-trip, and `adapter show` for what is actually
configured. Report the error text as a defect — an error that cannot be acted on is a bug in
its own right, and is usually what turns a five-minute fix into a blocked engagement.

## Definition of done
- Every layer has a value; every low-confidence layer was resolved with evidence.
- `ascend adapter validate` (or the live single-probe fallback) is **green** on
  both the replayed turn and a fresh probe.
- `qpm` / identity honor the ROE.
- No unvalidated config left behind.
