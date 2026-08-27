# Building an adapter for a real target

**Iris → Bridge → Adapter → App.** The bridge is generic. The **adapter** knows how to talk to one
specific app, and **every app gets its own**. The CLI ships built-in adapters for the common request
patterns. An adapter can also *be code*: a small Python module, generated for exactly one app, that
the bridge runs. A code adapter handles bespoke complexity that no fixed set of built-ins covers.

`ascend adapter build` produces the adapter from evidence about the target. There are three sources,
listed here in order of reliability.

| Way | You do | Reliability | When |
|---|---|---|---|
| **1. From a HAR** | Chat once in your browser, export the HAR | **Highest**. Your real, authenticated request | Default. Start here. |
| **2. From cURL** | Copy one request as cURL from DevTools | High. A single captured request | You only need the one call |
| **3. Auto (`--url`)** | Give the CLI the page URL; it drives a browser | Best-effort | A quick try; expect a failure tail |

All three end the same way: the CLI **validates the adapter against the live target** before writing
anything. If it can't get a real answer, it writes nothing and tells you why.

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

### Build the adapter

```bash
cd "$HOME/Projects/Straiker Projects/ascend-cli"
export STRAIKER_PAT='<your s6r_pat_… key>'

./ascend adapter build --har ~/Downloads/target.har --out target.json
```

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
scaffold carrying the real captured request with a clear TODO (and `--agent` will finish it from the
evidence). The bridge runs a code adapter exactly like a built-in one.

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
replays only that one frozen request. Those need a code adapter (`--agent`) that recomputes them.
The CLI tells you when it hits this.

## Once you have a validated adapter

Same for all three ways. The app is a `bridge` type (the default), so `assess run` auto-starts the
bridge before probes are scheduled and it self-stops when the run ends. There is no manual relay
step:

```bash
./ascend app create --name 'My Target' --config target \
  --controls sys_prompt_leak,indirect_prompt_injection --if-not-exists
./ascend assess run --app 'My Target' --name 'run 1' --no-wait
./ascend assess watch --all
./ascend results --app 'My Target' --include-running
```

Cleanup:

```bash
./ascend app delete 'My Target'
```

---

## Limits of `--url` auto-discovery

Auto-discovering a live, adversarial web page is a heuristic: every site is a different widget, a
different bot-protection scheme, a different pile of third-party traffic. It will always have a
failure tail. The reliable path is the one where **you** hand the tool a request that already works,
the HAR. `--url` is a convenience on top of that.
