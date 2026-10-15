# Custom adaptors: engine-side JavaScript for a target no template can drive

An **adaptor** is one JavaScript file that teaches the Ascend engine how to hold a conversation with
a customer's AI application. It runs on the Straiker side, in an isolate the engine destroys after
every turn, and it is stored on the application as `request_template._adaptor_src`.

It is **not** an adapter. The two exist because they solve the same problem from opposite ends of
the wire, and they are spelled differently on purpose:

| | **adapter** | **adaptor** |
|---|---|---|
| runs | on **your** side, behind the bridge | on the **engine's** side, on the app |
| language | Python (`runtime/adapters/`, or a `--code` module) | JavaScript, one file, synchronous |
| made by | `ascend target add` / `ascend adapter build` | you, with `ascend adaptor` |
| the platform sees | nothing but probes and answers | the source, gated before it may run |
| reach for it when | the target is reachable from your machine, or needs a browser | the engine must call the target directly and a template cannot express the flow |

Ascend drives an ordinary `api` target with configuration: `request_template` *is* the request
body, `response_template` picks the reply out. That covers one prompt = one HTTP request with the
right headers and JSON. An adaptor is needed when auth or session is not that: a login, a token
mint, a CSRF handshake, a conversation that has to be opened first, a reply you have to poll for, a
WebSocket, a stream that has to overlap the request. **If an adaptor has been asked for, that
decision has already been made.** The job is to write the one that handles the target, whatever
shape it turns out to be, including the simple shape.

`ascend` below means `python3 shells/cli/ascend.py` (or the installed binary).

## `ascend target add` writes one for you

The default registration IS an adaptor. `ascend target add <url | curl | har | config>` derives
the contract, proves it against the live target, then generates an adaptor from it
(`runtime/discovery/codegen_js.py`: one generator each for a direct request, an SSE/ndjson
stream with an optional create step, a WebSocket, a create-then-message session API and a
create/send/poll transcript; the onboarding scaffold for everything else), gates it through the
engine, creates — or re-wires in place — a direct application whose URL is the transport's real
address, whose headers carry the literal credentials the adaptor needs (an `env:` reference in the
config is resolved onto the application record, because the engine cannot read your environment;
the output says which), and whose `request_template` carries the prompt key, a FRESH
`_adaptor_src` (never the one stored before) and `_adaptor_domains` for every host beyond the
app's URL. It then runs `test` through the engine, confirms the store by reading the app back, and
runs `verify`. The result says `transport: adaptor` and names the file it wrote beside the config,
`<config>.adaptor.js` — the file to edit when the generated one is not enough, with the loop below.
`--via api` keeps a plain template app (no adaptor — and on an app that already carries one, the
stored `_adaptor_src`, `_adaptor_domains` and endpoint keys are dropped and said, so the app really
is a template app; the `_tunnel_*` keys stay); `--via bridge` is the deprecated local path.

Two cases the generator does not finish, and says so (`UNFINISHED` in the output, `finished:
false` in `--json`, and the engine's test fails on it honestly): a target whose contract has no
generator yet, and a target that **authenticates with a login handshake** (`oauth2`, `csrf`,
`derived_multihop` in the config's `auth`). Both get the onboarding scaffold with what the capture
showed in its header — the handshake named, for the second — and the app is adaptor-driven from
the start; finish `sendTurn()` with the loop below. (A handshake target used to fall to the
deprecated bridge by default; `--via bridge` still does that on request.)

A target on a **tunnel or private-link name** is reached by Straiker, so nothing is probed from
here and the contract comes from evidence (`--har`, a cURL, a saved config). A plain request
(`direct_api`) registers as a template app, as before; a stream, a socket, a session, a poll or a
handshake gets the hosted adaptor like any public target, because a template cannot render those.
On a tunnel app every second host the contract names is written as its own tunnel name
(`auth.corp.internal` → `auth.corp.internal.tun.straiker.ai`, in `_adaptor_domains` and in the
generated file), and the output says the tunnel agent must `--allow` it.

## The loop

```
ascend adaptor har customer.har --bodies      # what the target takes, in what order (offline)
ascend adaptor shape --app 'My Bot'           # the reply shape the app expects: read it first
ascend adaptor spec --out host.d.ts           # the COMPLETE capability surface inside the isolate
ascend adaptor scaffold --out my_adaptor.js   # a working starting point (or --example, the thin one)
ascend adaptor gate my_adaptor.js             # static. no target. fast. run it after every edit
ascend adaptor test my_adaptor.js --app <uuid> --prompt 'how do I reset it?'
ascend adaptor store my_adaptor.js --app 'My Bot'
ascend adaptor verify --app <uuid>            # runs what is STORED: the only proof it landed
```

Every verb takes `--json`. Exit codes follow the rest of the CLI: `0` done · `1` the target or
the engine failed a step (a non-200 turn, a failed preflight, a stored adaptor that did not land)
· `2` **the gate refused the file** (the findings code, so a CI job can tell "your code is not
allowed to run" from "the tool broke") · `3` bad invocation.

### Two ids, and they are not interchangeable

| the id | looks like | which verbs | where to find it |
|---|---|---|---|
| the platform's application id | `aapp_…` (or the app's **name**) | `store`, `shape` | `ascend app list`, `ascend target list` |
| the engine's application id | a uuid | `get`, `test`, `verify` | the Console URL for the app: `…/applications/ascend/<uuid>` |

The `aapp_` token is an encrypted form of the uuid that the engine cannot decode, and no platform
payload carries the uuid. The one join is the Console's own listing: give `get`/`test`/`verify` a
name or an `aapp_` id and the CLI resolves the uuid through it with your PAT's token
(`control/console.py`), says so on stderr, and uses that. `--console-id <uuid>` overrides the
lookup for the day the listing cannot be read; without either, the `aapp_` id is tried as given
and, when the engine answers *"application … could not be read"*, the CLI explains this table and
exits `3`. A uuid the engine cannot read exits `1`: it does not exist, or it is not in this
tenant, and the API will not say which.

### The credential

A PAT with **both** Ascend scopes (read and manage): `test` and `verify` execute an adaptor against
the target, which is a manage action. `ascend doctor` reports the scopes a key carries. A key with
read only can run `spec`, `gate`, `shape` and `get`.

## Before anything, get three things

1. **The target URL.** If it is a tunnel or private-link name (`….tun.straiker.ai`,
   `….pl.straiker.ai`), read "Tunnel and private-link apps" below first.
2. **The application it belongs to**, and both of its ids (above). `ascend target list` shows every
   app with its URL; the app whose URL is the target is yours. An app carrying
   `_adaptor_src: v0:passthrough` is waiting for you: the customer proved the link with that
   placeholder and saved the app. `store` replaces it; until then the engine refuses to assess the
   app and `verify` fails. An app still on the retired `https://custom-adaptor` URL needs its real
   URL set in the Console first; the engine no longer resolves it, and `store` refuses it.
3. **The reply shape it expects.** `ascend adaptor shape --app <app>` prints the application's
   `response_template` and the exact `return` statement the adaptor must produce. Read it before
   writing. This is the one that is unforgiving, for the reason given under "What you return".

## Step 1: find out what the target actually takes

The honest source is a **HAR** of one real exchange:

```bash
ascend adaptor har customer.har --bodies
```

Read the **SESSION CHAINS** section first. Each arrow is a value a response produced that a later
request carried (a cookie, a token, a conversation id), and each is a step the adaptor must perform
**in that order**. No chains means one request: write the thin version, and do not add steps
nothing asked for. `--bodies` adds the JSON shape (keys and types) of each request and reply.

The output is safe to paste into a chat with an agent: every credential is redacted to a prefix,
suffix and byte count, bodies are reduced to shapes, and the `--json` structure carries nothing
more than the text does. The HAR itself is a recording of a live session. Treat the file as a
secret and delete it when done.

**A HAR that helps** is captured like this. Pass these steps on when asking for one:

1. Open a **private (incognito) window**, so the capture starts with the login or the token mint
   instead of reusing a session the browser already holds.
2. DevTools (F12) → Network. Tick **Preserve log**. Clear the list.
3. Load the page with the chat. Log in if it needs it, **open the chat**, send ONE message and
   wait for the full reply. Without the chat opened, the HAR holds only the page.
4. Right-click the request list → **Save all as HAR**. A sanitized export is fine; it drops cookies
   and `Authorization` headers, which the adaptor still has to send (see the table in Step 2).

A HAR from a session already in progress hides the auth chain (the token was minted before the
capture began), and one taken without opening the chat holds only the page's own traffic. If
SESSION CHAINS starts from a token nothing in the HAR produced, or no request reaches the app's
host, ask for it again.

For a target you can reach from your machine, `ascend target add <url> --dry-run` (or
`ascend map --api <url>`) is the shallow probe: it sends one benign prompt in a handful of ordinary
body shapes and reports the request and the reply path if one answers. It is deliberately not a
scanner. When it finds nothing, the flow is behind auth or JavaScript, which is the normal case for
a real customer target, and the HAR is the next step. **Do not write your own probing loop**, and
**do not guess at auth**: an adaptor that guesses passes a test and fails a run. With no HAR and no
discovery result, say what is missing and stop.

### When the app's URL is an API, not a page

An app's URL is often the API a chat widget calls, not a page anyone opens. A probe then gets a 404
or an error page, and that does not mean the target is broken. The conversation happens on a page
that loads the widget: ask for **that page** (the customer's site, a support page; do not guess it
from the API host), capture one exchange there, and read only the requests to the app's host. The
rest of the page is noise. An `Origin` or `Referer` header naming the page is part of a request, not
another host to call.

### Tunnel and private-link apps

`https://<real-host>.tun.straiker.ai` (tunnel) or `https://<name>.pl.straiker.ai` (private link)
reaches a host inside the customer's network: through the `ascend-tunnel` agent they run there, or
through a private endpoint Straiker holds into their cloud. For a tunnel the real host is
the name minus `.tun.straiker.ai`, and that is the host a HAR shows. `ascend adaptor shape` and
`store` say when an app's URL is one of these.

- **Your machine cannot reach it.** Work from a HAR captured inside the customer's network. Run a
  probe on the real host only if that host is public.
- **Build every URL from `host.config.endpoint()`** plus the paths the HAR shows. Never write the
  real host into the adaptor: the engine reaches it only through the tunnel and refuses it otherwise.
- **One host per tunnel name.** A second host the adaptor needs must be tunneled too: the customer
  adds it to their tunnel agent's allow list (`--allow host:port`), and the app lists its `.tun`
  name in `_adaptor_domains` (`ascend target add` writes that name for every second host it
  derives, and says which to allow). Say so rather than working around it.
- **`ascend adaptor test` goes through the tunnel**, from the engine, exactly as a run does. It is
  the real check and the only one that reaches the app.

## Step 2: write it

```bash
ascend adaptor spec --out host.d.ts          # read it: the COMPLETE list of what exists inside the isolate
ascend adaptor scaffold --out my_adaptor.js  # a working starting point, typed against ./host
ascend adaptor scaffold --example            # the worked thin adaptor: one POST, no session
```

One file, one exported `sendTurn(turn, host)` function, running in an isolate destroyed after every
turn:

```js
function sendTurn(turn, host) {
  const res = host.http.request(host.config.endpoint(), {
    method: "POST", headers: turn.headers, body: turn.payload, timeoutMs: 30000,
  });
  return { status_code: res.status, body: JSON.parse(res.body).reply };
}
```

The scaffold reports 200 whenever the target **answered**, a 401 or an HTML login page included,
because at onboarding "your target is reachable and here is exactly what it said" is the most useful
thing anyone can say, and that reply is the spec for the adaptor you are about to write. Its only
failure is a target that could not be reached at all.

### Preflight: add `checkReachability` when a turn is expensive

Before an assessment dispatches, preflight checks that the target is reachable. Without help it
calls `sendTurn` once: a real conversation turn against the customer's agent. If the HAR shows a
cheap call that proves the credential works without starting a conversation (a `/me`, a
`users/authenticated`, a token mint), define a second function **in the same file**:

```js
function checkReachability(turn, host) {
  const res = host.http.request(host.config.endpoint() + "/me", {
    method: "GET", headers: turn.headers, timeoutMs: 15000,
  });
  return { status_code: res.status, body: { ok: res.status === 200 } };
}
```

- The host picks which function to call; do not branch inside `sendTurn` on "is this preflight".
- `turn.payload` is empty; `turn.params`, `turn.headers` and `host.*` are the same as a probe's.
- Return **200** when healthy and the target's **401/403** when the credential is bad. A 401/403 or
  a 5xx blocks the run before it starts, which is the point.
- No conversation, no prompt, no session creation. If the only proof the target works is a real
  turn, leave it out; the fallback already does that.
- `gate` prints `preflight: checkReachability` when it found the function. `test` and `verify` run
  it first and print a `preflight` line; a non-200 there fails the check.

### What you return must match the app's `response_template`

**The single most expensive thing to get wrong, because it does not fail. It scores.**

The engine does not read the adaptor's reply directly. It applies the application's
`response_template` to it, exactly as it would to a target's own response. So the body you return
has to have the shape that template describes:

```
response_template   {"response": "{{ RESPONSE }}"}          ->  return { response: text }
response_template   {"data": {"reply": "{{ RESPONSE }}"}}   ->  return { data: { reply: text } }
```

`ascend adaptor shape --app <app>` prints both templates and the exact return statement. If the
shapes disagree, the run does not error: `parsed_response` becomes something like
`{'response': 'the actual answer'}`, a stringified object, and **a detector scores that text as
though the target said it.** Every probe in the assessment is then judged against a reply the target
never gave. Either return the shape the template already describes, or have the template changed.

A dict or list body is marked `application/json` by the host, which is what makes the template apply
at all. An explicit `Content-Type` header wins if you set one, so only set it when the body is
genuinely not JSON.

### Rules the gate enforces (not style advice)

The gate parses the file and refuses, naming kind, detail and line:

- **No `async`, `await`, `Promise`, `for await`.** Host calls are synchronous and return values.
  `await` on a non-promise resolves immediately and `Promise.race` as a timeout times nothing out,
  so the gate refuses them rather than let you write code that looks right.
- **No `fetch`, `XMLHttpRequest`, `require`, `import`, npm.** Network is `host.http` / `host.ws`.
- **No `eval`, `new Function`, timers.**
- **No global the isolate does not have.** Only `host`, `JSON`, `Math`, `Date`, `Object`, `Array`,
  `String`, `Number`, `Boolean`, `Error`, `RegExp`, `Map`, `Set`, `console`, `undefined`, `NaN`,
  `Infinity`, `isNaN`, `parseInt`, `parseFloat` and the URI codecs exist; anything else (`atob`,
  `btoa`, `URL`, `Symbol`, `Buffer`, `TextEncoder`, …) is refused as an unknown identifier.
  `console` IS allowed: it routes to `host.log`.
- **No `.prototype`, `.__proto__`, `.constructor`** on any object, and no `host[expr]`: name the
  capability (`host.http.request`), do not compute it.
- **No `this` outside a class body** (in a plain function it is the sandbox object), no `with`,
  and no name starting with `__` (those belong to the host).
- **JavaScript, not TypeScript.** Type annotations do not parse; keep the compiler with
  `// @ts-check` and JSDoc against `host.d.ts`.
- **`sendTurn` must be defined** (and `checkReachability` may be). No `export` or
  `module.exports`: one self-contained file.
- **No module-level state.** The isolate dies each turn. A token or conversation id from the HAR
  goes in `host.state` (conversation-scoped).

`ascend adaptor gate` is the engine's own gate; the CLI's offline lint (`runtime/adaptor.py`
`lint_source`, run on every generated file) mirrors these rules so the common refusals are named
before a round trip, and the gate's verdict wins where the two disagree.

Deadlines are `timeoutMs` per call. Concurrency is `host.parallel`: you describe operations, you
cannot pass callbacks. `host.d.ts` (from `adaptor spec`) is the complete list.

| the HAR shows | you write |
|---|---|
| `Set-Cookie`, then a cookie on later requests | `host.http.client({cookieJar: "..."})` |
| a token minted once and reused | `host.state.getOrMint(...)` so turn 2 does not log in again |
| a conversation id created then reused | `host.state` |
| a hidden CSRF input in HTML | `host.parseHtml(html, {tag, nameAttr, name})` |
| a POST and a stream that must overlap | `host.parallel` |
| polling until a reply appears | a bounded loop with `host.sleep` **and an exit condition**; tell new from old by the target's own ids or order, not by comparing `host.now()` with its timestamps |
| a reply split over several bot messages | keep polling until no new bot message arrives for a short quiet spell, then return them joined |
| a greeting the bot sends when a conversation opens | **drain it before you send**: wait (bounded) for it, note what you have seen, then send and accept only bot messages new since. A HAR shows one seamless flow, so this only surfaces as a greeting on the `scored :` line |
| a token you minted, then a 401 | drop it (`host.state.set(slot, null)`), mint again and retry once. Only a 401 straight after a fresh mint is the credential failing; return that one |
| requests that succeed with no auth visible | the export dropped it: a sanitized HAR has no cookies or `Authorization`. Find what an earlier response produced (a token in a body usually goes back as `Authorization: Bearer ...`; a `Set-Cookie` needs a cookie jar) and try both. **Never conclude "no auth" from a HAR** |
| a WebSocket with a text protocol (SignalR `\x1e` frames) | `sock.send(string)` is sent verbatim; an object is sent as JSON |
| a cheap "who am I" call that needs no conversation | `checkReachability`, above |

### A shape worth recognising

**Salesforce Messaging for In-App and Web**, the `...my.salesforce-scrt.com` host behind many
enterprise support chats, is the whole table above in one flow:

1. `POST .../authorization/unauthenticated/access-token` (the path varies by API version; copy it
   from the HAR) with the deployment's `orgId` and developer name, also from the HAR, returns an
   `accessToken`.
2. `POST .../conversation` with a `conversationId` you generate (`host.uuid()`).
3. `POST .../conversation/{id}/message` with the prompt.
4. Poll `GET .../conversation/{id}/entries` for the bot's `Message` entries.

Every call after the mint carries `Authorization: Bearer <accessToken>`, though a browser HAR shows
none; the bot greets as the conversation opens, so drain it; a reply can span entries. (When the
target is reachable from your side, the CLI's own `scrt2_direct` adapter already speaks this; the
adaptor is for when the engine must call it.)

## Step 3: the correction loop

```bash
ascend adaptor gate  my_adaptor.js                              # static. no target. fast.
ascend adaptor test  my_adaptor.js --app <uuid> --prompt "how do I reset it?"
```

The adaptor's address is the app's URL. `test` takes it from the application, never from your
request, by design: so if the URL is wrong, have it fixed in the Console; do not work around it in
the adaptor.

Then loop: **gate → test → read the transcript → fix → repeat.**

`test` returns what the adaptor *did*: every host call, arguments, timing, result. When a turn
fails, read that before changing code. *"The mint returned 200 and then /conversation returned 401"*
tells you what to fix; "status 500" does not.

- Change **one thing** per `test`. Each run is a real conversation with a real system.
- `gate` is free. Run it after every edit. When it refuses, read the violation: it names kind,
  detail and usually the line.

**Done means the `scored :` line is the assistant's actual answer.** Not the status, and not the
`parsed :` line. `test` and `verify` print three views of the same turn, in this order:

```
scored : Papua New Guinea has the most languages.     <- what a DETECTOR will score
parsed : Papua New Guinea has the most languages.     <- the debugger's own extraction
raw    : {'response': 'Papua New Guinea has the ...'} <- what the adaptor returned
```

`scored` is computed with the same function a run uses, so it is the only one that tells you what
ships. When it disagrees with `parsed`, believe `scored`. If it comes back as a stringified object the
CLI says so loudly and exits `1`: your reply shape and the app's `response_template` disagree, and a
detector would score the wrapper verbatim. Fix that before anything else.

A 200 carrying an error string, an empty string, or an echo of the prompt is not done either, for
the same reason. Nor is a greeting ("Hi, how can I help?") or an unrendered merge field like
`{!$Context.Welcome_Message}`: the greeting was not drained, and every probe would be scored
against it. (Against an older engine the `scored` line is absent. Then read `parsed`, and check the
reply shape against `adaptor shape` by hand.)

## Step 4: store it, prove it, hand over

```bash
ascend adaptor store  my_adaptor.js --app 'My Bot' --dry-run   # the merge, without writing
ascend adaptor store  my_adaptor.js --app 'My Bot'             # the final code
ascend adaptor verify --app <uuid>                             # runs what is STORED
```

`store` gates the file first and refuses on any violation. It then merges the gate's output into the
app's existing `request_template`: **only `_adaptor_src` changes; every other key is sent back
exactly as it was**, because the platform's PATCH replaces the whole field. The one exception is an
endpoint key the engine would never read (`_adaptor_*_endpoint` on an app that has a URL; a
namespaced `_adaptor_<slug>_endpoint` on an app with inline source): it is **dropped and said**,
because dead config that looks live is how a wrong address gets debugged far from the key. An app
with no URL takes `--endpoint https://<the target>`, stored as `_adaptor_endpoint`; on an app that
has a URL, `--endpoint` is refused (the URL is the address). The write is read back before it is
reported as stored.

`verify` is the only check that proves the bytes landed where you think: it runs the **stored**
adaptor, not the file on your disk. If it fails after `test` passed, the stored bytes differ from
the file you tested. Say so plainly rather than retrying.

When `verify` passes, tell the SE:

- which application is configured, by name and id, and the target address stored on it
- what `verify` returned: turn status and the reply preview
- whether the adaptor defines `checkReachability` (cheap preflight) or preflight will spend one real
  turn
- that they can now start an assessment from the Console, and it must be a **NEW** assessment, not
  **Rerun**. An assessment is a snapshot of the application taken when it is created, and Rerun
  clones the previous assessment rather than re-reading the app, so it replays the OLD adaptor.
  Storing a new one has no effect on it. This is invisible: the rerun succeeds and produces wrong
  output, which is how it was found.
- and, if there was a HAR, to delete it.

## Traps

- `turn.payload` is the rendered template **minus** reserved keys; safe to forward whole.
- Always `(turn.params || {})` and `(turn.headers || {})`; a hand-built turn has neither.
- `host.config.endpoint()` is the app's URL (`_adaptor_endpoint` only for an app with none). Prefer
  it to a hard-coded address.
- Egress is allowlisted to the app's endpoint host. Extra hosts the HAR shows need
  `_adaptor_domains` on the application; you cannot widen it from inside the isolate.
- For an app with no URL, `_adaptor_<slug>_endpoint` is read **only** for a `v0:` alias. Inline
  source reads the bare `_adaptor_endpoint`; a namespaced key is silently ignored and the adaptor
  gets no address.
- A **bridge** app cannot carry an adaptor; `store` refuses it. Its bridge client is its
  integration, and an adaptor runs in the engine, which cannot reach a bridged target.
- `host.now()` is integer epoch ms; some targets 400 on a float.
- Keep errors small: an adaptor error becomes the probe's response body and is scored.
- `console.log` works (the gate allows it; it routes to `host.log`), but `host.log("info", msg,
  extra)` carries a structured `extra` the transcript shows.
- `gate --json` carries `templateValue`, the minified base64 the Console's Request Template field
  takes, for the rare case of pasting by hand: `{ "_adaptor_src": "<that>", "message": "{{PROMPT}}" }`.
  `store` does this for you.
- **Three digests, two bases.** `gate`, `test`, `verify` and `store` print the engine's `digest`,
  hashed over the source after the engine strips it; `get` prints the engine's own digest of the
  bytes it resolves, which differs for the same file (the minifier appends a newline). Neither can
  be rebuilt from the application record. To know whether a store landed, compare `store`'s
  `template_digest` (the bytes written) with `stored_digest` (the record read back) — equal means
  it landed; `get --json` carries `stored_digest` on the same basis.

## What this CLI does not do

- **Mint or widen a credential.** A PAT short of a scope is minted in the Console by someone whose
  role allows it; `ascend doctor` tells you what the key you have can do.
- **Mint the engine uuid.** It is joined through the Console's listing by name; when that fails
  the Console URL is the source (`--console-id`).
- **Reach a tunnel app's real host from here.** `ascend tunnel ls` lists the tunnels this machine
  started through the CLI and the state of each link (up, waiting for an app to list its key,
  reconnecting); it does not see an agent started by other means or on another machine. Whether the
  real host is reachable from this machine is a question for the customer's network team either way:
  the adaptor reaches it through the engine.

## Where things live

| Piece | Where |
|---|---|
| the pure rules (template merge, reply shape, the local lint, what a detector sees, the verdict) | `runtime/adaptor.py` |
| the generators `target add` uses (one per derived shape; the scaffold for the rest) | `runtime/discovery/codegen_js.py` |
| the Console join (name → engine uuid) | `control/console.py` |
| the HAR chain reader | `runtime/discovery/har_chains.py` |
| routed-name detection (tunnel / private link) | `runtime/discovery/egress.py` |
| the five engine routes | `control/api.py` (`adapter_spec`, `adapter_gate`, `adapter_test`, `get_app_adapter`, `verify_app_adapter`) |
| the shipped JavaScript | `templates/adaptor_scaffold.js`, `templates/adaptor_example_chattie.js` |
| the command bodies | `shells/cli/ascend.py` (`cmd_adaptor_*`) |
| the agent workflow | `skills/build-custom-adaptor/SKILL.md` |
