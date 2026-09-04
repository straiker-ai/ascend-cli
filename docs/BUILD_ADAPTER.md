# Building an adapter for a real target

**Ascend → bridge → adapter → target.** The bridge is generic. The **adapter** knows how to talk to one
specific app, and **every app gets its own**. The CLI ships built-in adapters for the common request
patterns. An adapter can also *be code*: a small Python module, generated for exactly one app, that
the bridge runs. A code adapter handles bespoke complexity that no fixed set of built-ins covers.

## Start here: `ascend target add`

Onboarding a target is one command. It works out what you handed it, builds the adapter, proves it
against the live target, registers the application, and stores the bridge key:

```bash
ascend target add https://your-bot.example.com/chat   # an HTTP endpoint
ascend target add ./request.curl                      # copy-as-cURL out of DevTools
ascend target add ~/Downloads/session.har             # an exported browser session
ascend target add mybot                               # a config already on disk
```

You do not choose a source flag. The artifact itself says which it is, and "is this a HAR or a
cURL?" is a question operators routinely can't answer. `target add` stops once the target is
registered and proven, because spending an assessment is a separate decision — add `--run` to
continue straight into one.

A bare URL is treated as an **HTTP endpoint** and probed without a browser. A page with a chat
*widget* needs the browser path: `ascend target add --url https://your-bot.example.com/support`.
An OpenAPI/Swagger URL is refused with the two commands to run instead, because a spec describes
many endpoints and the chat one has to be picked first.

The rest of the noun: `target list` (adapter, registered, serving), `target show <t>` (everything
bound to one target in one place), `target check <t>` (re-prove it against its live endpoint, and
time it), `target rm <t>`.

Everything below is the machinery underneath. Reach for it directly when a step needs tuning, when
discovery fails, or when you want a validated config *without* registering anything
(`adapter build … --out target.json`). `app`, `adapter` and `keys` are unchanged and still fully
supported.

---

`ascend adapter build` produces the adapter from evidence about the target. There are three sources,
listed here in order of reliability.

| Way | You do | Reliability | When |
|---|---|---|---|
| **1. From a HAR** | Chat once in your browser, export the HAR | **Highest**. Your real, authenticated request | Default. Start here. |
| **2. From cURL** | Copy one request as cURL from DevTools | High. A single captured request | You only need the one call |
| **3. Auto (`--url`)** | Give the CLI the page URL; it drives a browser | Best-effort | A quick try; expect a failure tail |

All three end the same way: the CLI **validates the adapter against the live target** before writing
anything. If it can't get a real answer, it writes nothing and tells you why.

**If you want to skip the manual capture entirely**, two of the four sources need no DevTools at
all, and they are worth trying before you open a browser:

```bash
ascend target add https://your-bot.example.com/api/chat --bearer "$TOK"   # probes the API directly
ascend target add https://your-bot.example.com/support                    # CLI drives the browser
```

`--api` (a bare API URL) probes the endpoint and derives the contract with no browser. `--url` (a
page with a widget) launches a **real browser and captures the traffic for you** — that is the
automated version of Way 1, not a manual export. Reach for a hand-exported HAR or cURL when those
cannot work: a login flow you must complete yourself, aggressive bot protection, a multi-step
session, or a mobile app. What no source can supply is a **secret** — a passcode, an access code
or an API key has to be given with `--bearer` / `--api-key` / `--header` / `--body-field`, or be
present in the evidence you captured.

---

## Way 1: from a HAR (recommended)

A HAR is a recording of everything your browser did. Because it's *your* browser session, it already
passed the login, the cookies, and the bot protection, so the request in it works. This is the most
reliable input.

### Export the HAR (Chrome or Edge)

1. Open the chatbot page.
2. Open DevTools: **⌥⌘I** (Mac) / **F12** (Windows).
3. Click the **Network** tab.
4. Check **Preserve log** (top-left of the Network tab).
5. **Send the bot exactly this message and wait for its reply:**

   ```
   Hello, what can you help me with?
   ```

   (Use those exact words. The CLI finds the right request by matching what you typed. If you type
   something else, pass it with `--prompt "…"` in the command below.)
6. Right-click anywhere in the request list → **Save all as HAR with content** → save to e.g.
   `~/Downloads/target.har`.

### Export the HAR (a mobile app — Android or iOS)

There is no HAR export on a phone. The device has to send its traffic through an intercepting
proxy on your laptop, and the proxy exports the HAR. **Budget real time for this** — the capture
itself is five minutes, and the trust setup is where engagements stall.

1. Run a proxy that can export HAR: **mitmproxy** (`mitmweb`, File → Export → HAR),
   **Proxyman**, **Charles**, or **Burp**.
2. Put the phone on the same network and point its Wi-Fi proxy at your laptop's IP and the
   proxy's port.
3. Install the proxy's CA certificate on the device, **and mark it trusted** — installing is not
   the same as trusting:
   - **iOS**: install the profile, then enable it under
     *Settings → General → About → Certificate Trust Settings*. Skipping the second step is the
     most common reason nothing decrypts.
   - **Android 7+ (API 24+)**: apps do **not** trust user-installed CAs. A CA in the user store
     will decrypt browser traffic and nothing else, which reads as "the proxy is broken". You
     need one of: an emulator or rooted device with the CA in the **system** store, or a **debug
     build** whose `network_security_config.xml` trusts user CAs.
4. Drive the app by hand: open the chat and send exactly
   `Hello, what can you help me with?` (or pass `--prompt` with what you actually typed).
5. Export the HAR and build from it exactly as above.

#### Certificate pinning — the limit worth knowing before you promise a date

Many production apps, especially in health, finance and insurance, **pin** their certificates:
the app ships the expected certificate or public key and rejects anything else, so a correctly
installed, fully trusted proxy CA still fails. The symptom is unambiguous — the app shows a
network/connection error and the proxy logs a TLS handshake failure — and **no proxy
configuration fixes it**, because the app is behaving exactly as designed.

Your options, in the order worth trying:

| Option | What it needs | Notes |
|---|---|---|
| A build with pinning disabled | The app team | Cleanest and fastest. Usually a debug/QA build they already produce. |
| The API contract directly | The app team | You often do not need the app at all — see below. |
| Unpinned emulator build | The app team + an emulator | A debug build on an emulator with the CA in the system store. |
| Runtime bypass (Frida / objection) | A rooted/jailbroken device or a repackaged app | Works, but is invasive, breaks on app updates, and is frequently disallowed by the customer's own policy. Get written approval first. |

**Do not treat pinning as a CLI problem.** Nothing in this tool can defeat it, and no adapter
source (`--har`, `--curl`, `--url`, `--api`) changes the outcome, because the failure happens on
the device before any traffic is recorded.

**The shortcut people miss:** a mobile app is a *client*. What you are assessing is the API behind
it, and that API is reachable without the app. If the team can give you the endpoint, the auth
scheme and one example request — a cURL, a Postman entry, an OpenAPI spec — you can build the
adapter with `--api` or `--curl` and skip device capture entirely. Ask for that **first**; it is
usually faster than arranging a rooted device, and it is the same surface the app talks to.

### Build the adapter

```bash
cd <your ascend-cli checkout>
export STRAIKER_PAT='<your s6r_pat_… key>'

./ascend adapter build --har ~/Downloads/target.har --out target.json
```

(Or `ascend target add ~/Downloads/target.har`, which does this and registers the result.)

If you typed a different message in step 5, tell it:

```bash
./ascend adapter build --har ~/Downloads/target.har --prompt "the exact text you typed" --out target.json
```

You'll see it pick the endpoint, detect the transport (plain JSON, streaming, etc.), and
re-validate against the live target. Then:

```bash
./ascend adapter show target                       # inspect it (secrets masked)
./ascend chat target --prompt 'what can you help me with?' --no-record
```

---

## Way 2: from a single cURL

If you just want the one request: in DevTools **Network**, right-click the chat request →
**Copy → Copy as cURL**, paste it into a file, and:

```bash
pbpaste > /tmp/target.curl          # or paste into the file by hand
./ascend adapter build --curl /tmp/target.curl --prompt-hint "Hello, what can you help me with?" --out target.json
```

`--prompt-hint` is the text you typed, so it knows which body field is the prompt.

---

## Way 3: auto-discovery (quick try)

```bash
./ascend adapter build --url "https://example.com/support" --out target.json
```

The CLI opens a real browser, finds the widget, sends one benign prompt, and works out the contract.
It is **not guaranteed**: real pages vary, and bot protection or an unusual widget can defeat it. If
it fails, it tells you what it saw and points you back to Way 1. Flags that help:

- `--settle 15`: slow widget or single-page app
- `--manual`: opens the page and **you** drive the widget while it records (for widgets the
  automation can't reach). Type the same benign prompt yourself.

---

## When validation fails with **403 Forbidden**

Some targets refuse *any* request that doesn't come from a real browser, even a byte-identical
replay of the exact call the browser just made. This is **bot protection**. It is not an auth
problem: no token or header fixes it. You'll see:

```
The endpoint and request are right … but replaying it from outside a browser is refused (HTTP 403).
That is bot protection, not missing auth: a token will not fix it.
```

These targets have to be driven **through a browser for every probe**, and `ascend adapter build
--url` does that **automatically**. When it captures the widget, tries the HTTP contract, and
sees the replay refused, it builds a `browser` adapter from what the capture actually did (the
launcher it clicked, the chat frame, the input it typed into, how it sent, where the reply
rendered), then **proves that adapter by driving a real browser** before writing:

```
[map] HTTP replay refused (anti-automation) — building a BROWSER adapter from the capture ...
[validate] driving a real browser through the generated adapter ...
[validate] VALIDATED (browser) — 'Hi, I'm Anna. I can help with...'
```

No hand-built selectors. If a derived selector doesn't hold, it says which and keeps the config so
you can tune it with `ascend adapter show <name>`; it never writes an unproven adapter. The rest of
the flow (register → assess) is identical: `assess run` auto-starts the bridge and it drives the
browser per probe.

`configs/example-browser.json` shows the shape if you want to write one by hand.

---

## When the target is too slow for the platform's per-probe window

A config can be perfectly correct and the target still unassessable. The assessment platform gives
each probe a bounded window (~110–120s), and the clock starts when the probe is **queued**, not when
your bridge calls the target. Blow it and the platform records a synthetic timeout that is
indistinguishable from the target failing — which feeds the target-health streak and auto-pauses the
run. The result is an assessment that reports nothing, having measured nothing, and reads like a
broken bridge.

So `adapter validate` times the call and names it from the one measurement it has:

```
  ok=True matched=True (94210ms)
warning: this target replied in 94s, against a ~120s platform per-probe window. The probe's clock
starts when it is QUEUED, not when the bridge calls the target, so a probe that waits to be leased
can still time out. Keep QPM and max_workers low ...
```

At or beyond the window the warning is stronger, and raising the adapter's `timeout_ms` does **not**
help: the router has already abandoned the probe, and the extra time only holds a worker and a
socket open. The window has to be raised platform-side first;
`$ASCEND_PLATFORM_PROBE_WINDOW_MS` tells the CLI what it is, and the bridge's give-up point and the
adapter's own timeout are derived from that one number.

`ascend target check <target>` runs the same gate and the same timing against a registered target.
That is how you re-prove one that has started failing, before assuming the bridge dropped.

---

## When the built-ins don't fit: `--code`

The built-in adapters cover the common shapes. For a target that fits none of them (an odd
envelope, a signed request, a multi-step flow), add `--code`:

```bash
./ascend adapter build --har target.har --code --out mybot
```

This writes the app's **own adapter as a Python module** (`configs/mybot.py`) exposing one function:

```python
def send_prompt(prompt: str) -> str:
    # send one prompt to THIS app, return the reply — any complexity lives here
```

…then **proves the generated code** against the live target before saving. Read it with
`ascend adapter show mybot`, edit `send_prompt` for anything bespoke, and re-prove with
`ascend adapter validate --config mybot`. If the shape is one no generator covers, `--code` writes a
scaffold carrying the real captured request with a clear TODO; open it in a coding agent, finish
`send_prompt`, and validate. The bridge runs a code adapter exactly like a built-in one.

## Multi-turn, session, and documented APIs

**A conversational / multi-turn API** (one that makes you *create a conversation* first, then POST
messages to it) is handled, as long as the evidence shows the whole flow. Export a HAR that
captures both calls (the create, then a message). The CLI detects the session and uses the
`session_api` adapter, carrying the conversation id across turns automatically:

```bash
ascend adapter build --har conversation.har --out mybot
# [found] Multi-turn: it creates a conversation first, then sends messages — session_api handles it.
```

A single request won't reveal a multi-step flow. Capture the real conversation.

**A documented API**: point straight at its OpenAPI / Swagger spec; no capture needed:

```bash
ascend adapter build --spec https://host/openapi.json --out mybot
```

The CLI finds the chat-like endpoint, reads the request schema, and builds the config, then proves
it against the live target before saving. A spec describes the request shape. It does not say where
the answer is, so the live check determines that.

## Whether a HAR is enough

For most targets, yes: a HAR is the actual authenticated traffic, so it carries the real request,
headers, auth, and (for streaming) the frames. A HAR must *contain* two things to work:

- the **full round-trip**: the send AND the response that carries the reply. For an async
  POST-then-GET agent (the POST returns an id, a later GET returns the answer), capture both.
- the **conversation setup** if the API is multi-turn (the create-conversation call), so the
  session is visible.

If a request has **computed or signed fields** (a per-call signature, a nonce), even a perfect HAR
replays only that one frozen request. Those need a code adapter (`--code`) whose `send_prompt`
recomputes them. The CLI tells you when it hits this.

## Where the config lands, and where it is found

A bare `--out <name>` lands in one directory — `$ASCEND_CONFIG_DIR` if set, else `./configs`, else
`~/.ascend/configs` — so `--config <name>` finds it. (`--out` with a directory in it writes exactly
there.) Reads are wider: a config is searched for **per file** across every one of
those directories plus the bundled examples, in that same precedence order, so a config written from
one directory resolves from any other. It used to be found only in the first directory that
*existed*; because every checkout ships a `configs/` of examples, running the CLI from a checkout
hid `~/.ascend/configs` entirely, and a target created elsewhere came back as "config not found".
That surfaced as a bridge failure rather than a lookup one — the relay exits before it ever leases,
and a relay that never starts looks exactly like one that dropped, while the app's *key* kept
resolving because keys live in `~/.ascend` and never depended on the working directory.

`ascend adapter configs` lists everything that is actually resolvable and says where new ones are
written.

### Naming the config, and what happens on a name clash

`target add` / `onboard` derive the config name from `--name`, or from the evidence file, or from
the URL's host — which is how you end up with `myhost-com` or `127-0-0-1-8791`. **Use `--save-as
<name>` to choose it**, and you always know what to pass to `--config` later:

```bash
ascend target add https://your-bot.example.com/chat --save-as mybot --name 'My Bot'
ascend target check mybot
```

Because the derived name comes from the *host*, two bots on one host derive the same name. Re-running
against the **same endpoint** overwrites the config in place — that is an intentional refresh, and
any `_ascend` app binding on the file is carried forward so the target stays bound to its
application. A **different** endpoint under an already-used name is not overwritten: it is saved
alongside as `<name>-2` and both are named in the output. `--save-as` is explicit intent and always
wins, overwriting if you point it at an existing name.

Writing the exact path you asked for:

| `--out` | Writes to |
|---|---|
| `mybot` / `mybot.json` | the config dir (so `--config mybot` finds it) |
| `./mybot.json` | your current directory |
| `out/mybot` | `out/mybot.json` — the extension is always added |
| `/abs/path/mybot.json` | exactly there |

`--code` follows the same rule and writes the `.py` module beside its pointer config; when that is
outside the config dir the pointer records an absolute path, because the `custom` adapter otherwise
could not find the module at run time.

## Once you have a validated adapter

Same for all three ways. The shortest path is to hand the config to `target add`, which registers
the application and stores the bridge key for you:

```bash
./ascend target add target --name 'My Target' --controls sys_prompt_leak,indirect_prompt_injection
```

Add `--run` to that same command to continue straight into an assessment instead of stopping once
the target is registered.

The commands underneath are unchanged and still the way to do a step by hand. The app is a `bridge`
type (the default), so `assess run` auto-starts the bridge before probes are scheduled and it
self-stops when the run ends. There is no manual relay step:

```bash
./ascend app create --name 'My Target' --config target \
  --controls sys_prompt_leak,indirect_prompt_injection --if-not-exists
./ascend assess run --app 'My Target' --name 'run 1' --no-wait
./ascend assess watch --all
./ascend results --app 'My Target' --include-running
```

Cleanup. Both delete the application and drop its stored key (`--keep-key` on either keeps the key):

```bash
./ascend target rm 'My Target'
./ascend app delete 'My Target'
```

---

## Limits of `--url` auto-discovery

Auto-discovering a live, adversarial web page is a heuristic: every site is a different widget, a
different bot-protection scheme, a different pile of third-party traffic. It will always have a
failure tail. The reliable path is the one where **you** hand the tool a request that already works,
the HAR. `--url` is a convenience on top of that.
