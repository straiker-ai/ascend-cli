# Multi-turn and session state over pull-mode

Many red-team probes are multi-turn: an attack primes the bot on turn 1 and lands on turn 3. For
that to work the *conversation* has to persist across probes. In pull-mode the runtime is
responsible for that continuity. The default policy is *sequential*.

---

## Why the client owns continuity

Ascend AI puts **only the prompt** on the wire. A probe body carries the
rendered prompt and nothing else. There is no `conversation_id` field: a probe carries a `prompt`
and no `conversation_id`. For a *direct* `api` app, the platform runs the per-target
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

## What is on the wire, and the default policy

A probe carries **only the prompt**. Measured on 176 captured envelopes: `header.id`,
`header.type`, `metadata.timestamp`, `metadata.version`, `payload.body.prompt` -- no conversation
key, no turn number, no strategy. The controls API carries no multi-turn flag either. So the relay
cannot tell a single-shot probe from turn 3 of a multi-turn attack, and the platform cannot manage
a conversation's lifecycle (a refresh, a new id) on the bridge's behalf.

The default is therefore **per-probe**: every probe is its own conversation. That is what a
single-shot control means, it is what the platform's own direct plugins do, and it never chains
hundreds of unrelated attacks into one thread on the target. `session_api` opens a fresh session
per probe; `direct_api` never echoes a conversation id across a probe boundary.

**`sequential`** is the opt-in for a run of multi-turn controls: consecutive probes share one
conversation. `session_api` keeps its session; `direct_api` carries the target's conversation id
when the config names one (`carry`), including a rotating id. It is **bounded**: after
`conversation.max_turns` (default 10) the next probe starts a fresh conversation, so an attack
that needs five turns gets them and a long run does not accumulate a thousand. A session or id
the target refuses (expired, closed) is dropped and a fresh one opened.

```bash
ascend assess run --app mybot --name agentic --controls <multi-turn ids> --conversation sequential
ascend bridge start --app mybot --conversation sequential
```

`assess results` prints which policy the relay ran under, next to the answered line, and
`--json` carries it as `relay_conversation`. Config form:

```json
"conversation": {"policy": "sequential", "max_turns": 10}
```

On the record: under `sequential`, a multi-turn attack still shares its conversation with
whatever single-shot probe the platform dispatched just before it. Until the platform puts a
conversation key on the wire, that is the best the bridge can do -- and it says so here.

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
| Prompt-only wire, no conversation id | the probe payload | — |
| Per-conversation session continuity | persistent adapter instance in `ConversationRouter` | one instance per key |
| No correlation id → interleave risk | sequential policy | `max_workers=1` for stateful |
| Opt-in concurrency | `conversation_key` (`header:` / `body:`) | off (sequential) |
| Fresh identity/session | `router.reset()` / distinct config / new process | fresh per run |
| Queue wait counts against the probe's budget | platform per-probe window, from queue time | ~120s ([PERFORMANCE.md](PERFORMANCE.md)) |
