# Multi-turn and session state over pull-mode

Many red-team probes are multi-turn: an attack primes the bot on turn 1 and lands on turn 3. For
that to work the *conversation* has to persist across probes. In pull-mode the runtime is
responsible for that continuity. The default policy is *sequential*.

---

## Why the client owns continuity

Ascend's assessment engine (Iris) puts **only the prompt** on the wire. A probe body carries the
rendered prompt and nothing else. There is no `conversation_id` field: Iris `Probe` has a `prompt`
field and no `conversation_id`. For a *direct* `api` app, Iris runs the per-target
session/conversation logic server-side in its own plugins. For a **bridge** app that logic is
absent, so it lives in the runtime, in `runtime/dispatch.py`.

The mechanism: **one persistent adapter instance per conversation.** A stateful adapter (e.g.
`session_api`) mints a session/conversation id on its first call and reuses it on every subsequent
call to the *same instance*. So as long as successive turns are routed to the same instance, the
target sees one continuous conversation.

`ConversationRouter` (in `dispatch.py`) is what caches those instances. It keys them by
`adapter:config:conversation` and runs their coroutines on a shared asyncio loop, with a
per-conversation lock so a stateful adapter's turns stay strictly ordered even under threads.

---

## The correctness problem and the default policy

Iris gives the runtime **no correlation id**, so the runtime cannot tell which in-flight probe
belongs to which conversation. If it ran probes concurrently against a single shared stateful
instance, turns from different logical conversations would interleave and corrupt each other.

The default policy that avoids this is **sequential**:

- The runtime runs the app at **concurrency 1** for stateful adapters, so only *one* conversation
  is ever in flight.
- The single persistent instance threads the turns in order.

This is why the legacy Go bridge forced `max_workers: 1` for session/browser targets. The
constraint is inherent to "no correlation id on the wire".

### Which adapters are stateful

`STATEFUL_ADAPTERS` in `dispatch.py`:

```
session_api, browser, amazon_connect, scrt2_direct,
agentforce*, slack_direct, copilot_studio, websocket_direct
```

> Note: `agentforce` appears in `STATEFUL_ADAPTERS`, but it creates a fresh session per prompt and
> is parallelizable in practice; treat the set as the routing default and override with
> `max_workers`/`conversation_key` where a target is genuinely stateless. `direct_api`, `sse_stream`,
> and `vertex_ai` are stateless.

### How the concurrency is chosen

`TargetCaller.recommended_workers()` (in `call_target.py`):

1. If the config sets `max_workers`, use it.
2. Else if the adapter is stateful **and** no `conversation_key` is set → **1** (sequential).
3. Else → **10** (concurrent).

`TargetCaller.is_stateful` is `adapter_type in STATEFUL_ADAPTERS and not config.get("conversation_key")`.

For a normal run this is automatic: `ascend assess run` auto-starts the bridge, which reads the
adapter/config and picks the worker count from the rules above. The `bridge start` invocations
below are the **advanced** path (a manually pre-started or remote relay), where `--max-workers N`
overrides all of this:

```bash
ascend bridge start --adapter session_api --config mybot          # auto → 1 worker (sequential)
ascend bridge start --adapter direct_api  --config mybot          # auto → 10 workers (concurrent)
ascend bridge start --adapter session_api --config mybot --max-workers 4   # explicit override
```

---

## Running conversations concurrently: `conversation_key`

The sequential policy is a default that you can override. If the target **echoes a stable
correlation value** you can read off the probe, you can demux concurrent conversations. Set
`conversation_key` in the config:

| Value | Reads from |
|---|---|
| `header:<Name>` | The rendered probe's `payload.headers[<Name>]` |
| `body:<field>` | The rendered probe's `payload.body[<field>]` |

`conversation_key(probe_message, config)` returns that value; `ConversationRouter` then keeps a
*separate* persistent instance per key, so conversation A and conversation B each get their own
session and can run in parallel. Setting `conversation_key` also flips `is_stateful` to false, so
`recommended_workers()` allows concurrency.

```json
{
  "adapter": "session_api",
  "conversation_key": "header:X-Conversation-Id",
  "max_workers": 4,
  "...": "..."
}
```

If no `conversation_key` is set, `conversation_key(...)` returns `None`, everything collapses to the
single `default` conversation, and the sequential policy holds.

---

## Resetting sessions (identity rotation)

Sometimes you want to *drop* accumulated state: rotate to a fresh identity, clear a poisoned
context, or start a clean conversation:

- `ConversationRouter.reset(adapter_type=None)` drops cached instances (all, or just one adapter
  type) and returns the count dropped. The next probe rebuilds a fresh instance → a fresh
  session/token/cookie jar.
- `TargetCaller.reset()` calls through to the router's `reset()`.

Rotation strategies:

- **Per-run**: a fresh runtime process is a fresh router with an empty cache, so a bridge
  auto-started by `ascend assess run` (or a manual `ascend bridge start`) already starts clean.
- **Per-conversation identity**: for adapters whose identity is a config value (e.g.
  `slack_direct.slack_token`, `agentforce.client_id`, an `Authorization` header), point the runtime
  at a different config to run under a different identity. Because instances are cached per
  `adapter:config:conversation`, two configs never share a session.
- **Mid-run reset**: call `caller.reset()` (the `TargetCaller` is kept on the client as `_caller`)
  to force every next turn onto a brand-new session without restarting the process.

Adapters that re-mint credentials on their own (e.g. `agentforce` re-mints an expired OAuth token,
`sse_stream` re-bootstraps after a 403) handle *token* rotation internally; the router-level reset
is for rotating the whole *identity/session*.

---

## Summary

| Concern | Where it lives | Default |
|---|---|---|
| Prompt-only wire, no conversation id | Iris `Probe` | — |
| Per-conversation session continuity | persistent adapter instance in `ConversationRouter` | one instance per key |
| No correlation id → interleave risk | sequential policy | `max_workers=1` for stateful |
| Opt-in concurrency | `conversation_key` (`header:` / `body:`) | off (sequential) |
| Fresh identity/session | `router.reset()` / distinct config / new process | fresh per run |
