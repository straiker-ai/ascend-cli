# Bridge pull-mode protocol — build-your-own-client guide

For customers who can't run Straiker-provided binaries/containers (the Ascend bridge, its Docker
image) but can write and run their own code inside their private network. This document
describes the wire protocol directly, independent of any Straiker-provided client
implementation. A companion machine-readable spec is at `openapi.yaml` in this same folder.

Ready-to-adapt reference implementations are included:
- `bridge_client.py` — stdlib-only Python, run as a standalone process.
- `bridge_client.browser.js` — paste directly into a browser DevTools console on any page in
  your private network (e.g. your own target app's page); no install at all. Requires
  the lease service's `/v2/lease`/`/v2/result` to allow cross-origin browser requests (see
  server-side) — already live, nothing extra to set up.
- `bridge_client.term.py` — for a target that's only reachable as an interactive CLI program
  (e.g. a terminal-based coding agent) rather than over HTTP. Stdlib-only Python; requires the
  `tmux` binary. You start your agent yourself inside a named tmux session (so any one-time
  interactive setup - login, trust prompts - is done once, by you, and never repeated); this
  script attaches to that session by name and drives it via `tmux send-keys`/`capture-pane`
  instead of making an HTTP call. It never launches or owns your agent's process, so
  restarting this script never resets your agent's state. Since a single tmux session can only
  hold one conversation at a time, probes are processed one at a time rather than
  concurrently, unlike the other two clients.

## Why pull mode, not WebSocket

There are two transports; this guide only covers pull. A hand-rolled WebSocket client needs
persistent-connection lifecycle handling (reconnect, backoff, keepalive/ping) to be reliable —
easy to get subtly wrong. Pull mode is two plain HTTP endpoints called in a loop: poll for
work, do the work, submit the result, poll again. It's the simpler, safer thing to review and
implement from scratch, and it's what we recommend for a self-written client.

## What your client needs to do, end to end

1. Long-poll `POST /v2/lease` for probes addressed to your app.
2. For each probe returned, take its `payload.body` / `payload.headers` and make the actual
   call to **your own target application** (the thing being assessed) — however your app
   expects to be called: your own auth, your own endpoint, your own request shape. This is the
   one piece that's genuinely yours to write; everything else in this doc is fixed protocol.
3. Submit your target's real response back via `POST /v2/result`.
4. Repeat from step 1. There is no separate "register"/"connect" call — the first successful
   `/v2/lease` call *is* how your client becomes visible as connected.

## Authentication

Every call carries `Authorization: Bearer <thin_api_key>` — the same per-app token used by
every bridge client today (including the Straiker bridge itself). Your `app_id` is derived from this
token server-side; it is never read from the request body, so there's no way to
accidentally (or maliciously) lease/answer probes for a different app. Straiker provisions
this token per application — request it for whichever app you're onboarding.

## `POST /v2/lease` — long-poll for work

Request body (all fields optional):

```json
{
  "consumer": "my-bridge-client-1",
  "max": 10,
  "wait_ms": 25000
}
```

- `consumer` — **pick one stable string for this process's entire lifetime and reuse it on
  every call** (e.g. a hostname, or a fixed config value). This is your identity in the
  underlying consumer-group dispatch. If you omit it, the server mints a fresh random one
  *every call*, which works but means a crash-recovery reclaim (see below) takes longer to
  notice your process is gone. If you run more than one instance of your client in parallel,
  give each a distinct `consumer` value.
- `max` — how many probes to lease at once. Default 10, clamped to 1-50 server-side.
- `wait_ms` — how long the server holds the connection open waiting for work before returning
  empty. Default 25000ms, clamped to 0-55000ms server-side. Pick something comfortably under
  whatever timeout your own HTTP client/proxy enforces (a typical reverse-proxy idle budget is
  the reason 55s is the ceiling, not an arbitrary number).

Response:

```json
{
  "consumer": "my-bridge-client-1",
  "probes": [
    {
      "request_id": "e4f90ed2-c80e-4006-a6a5-2db99acc8b6b",
      "msg_id": "1721234567890-0",
      "message": {
        "header": {"type": "probe", "id": "e4f90ed2-c80e-4006-a6a5-2db99acc8b6b"},
        "metadata": {"timestamp": "2026-07-20T12:00:00.000Z", "version": "1.0.0"},
        "payload": {
          "body": {"message": "the actual probe content to send to your target"},
          "headers": {}
        }
      }
    }
  ]
}
```

- An empty `probes` array is the normal, expected outcome of a timed-out long-poll — **not an
  error**. Just call `/v2/lease` again immediately.
- `request_id` and `msg_id` are both opaque — echo them back verbatim in `/v2/result`, don't
  try to parse or derive meaning from them. `request_id` identifies the probe (used later for
  submitting the result); `msg_id` is the underlying delivery receipt (used for acknowledging
  it) — they are different values.
- `message.payload.body` is the exact, already-rendered request body meant for your target
  application (whatever prompt/message content Straiker's assessment is testing this turn).
  `message.payload.headers` carries any headers the assessment config attached — commonly
  empty for a bridge app since your own client supplies its own auth to your target.
- 401 if the bearer token is missing/invalid.

## `POST /v2/result` — submit the response

After you've called your own target application with `message.payload.body`, submit what it
actually returned:

```json
{
  "request_id": "e4f90ed2-c80e-4006-a6a5-2db99acc8b6b",
  "msg_id": "1721234567890-0",
  "payload": {
    "status_code": 200,
    "body": {"response": "whatever your target actually replied with"},
    "headers": {}
  }
}
```

- `request_id`/`msg_id` — the exact same values from the `/v2/lease` response for this probe.
- `payload.status_code` — the real HTTP status your target returned (or your own client's
  synthesized status if the call to your target failed outright — see error handling below).
- `payload.body` — your target's actual response body. Any JSON-serializable value; doesn't
  need to match any particular schema beyond what Straiker's assessment config for your app
  already expects to parse.
- `payload.headers` — pass through anything meaningful from your target's response, or just
  `{}`. `Content-Length`/`Date` are stripped automatically on the way back regardless.

Response on success: `{"status": "ok"}`. `400` if any of the three required fields
(`request_id`, `msg_id`, `payload`) is missing.

## Error handling and retries

- **Network error calling `/v2/lease` or `/v2/result`**: retry with backoff. Nothing on the
  server side is lost by a delayed retry.
- **Your call to your own target app fails or times out**: still submit a `/v2/result` for
  that `request_id` — set `status_code` to whatever's accurate (e.g. `500`, or `504` if you
  timed out waiting on your target) and describe the failure in `body`. Don't just drop the
  probe; a submitted-but-failed result completes the assessment's accounting for that probe.
  A dropped one (never submitted) will eventually get reclaimed and redelivered — safe, but
  slower and noisier than just answering it.
- **Your process crashes mid-probe** (leased via `/v2/lease`, never submitted via
  `/v2/result`): after ~90 seconds of inactivity on that specific probe, the server
  automatically reclaims it and redelivers it on a future `/v2/lease` call (yours or another
  instance's, if you're running more than one). You don't need to build any of this yourself.
- **Submitting a result twice for the same `request_id`** (e.g. you retried a `/v2/result`
  call that actually succeeded, or a redelivered probe got answered by two of your instances):
  tolerated server-side, logged as a duplicate, not an error. Safe to just answer whatever
  you're handed rather than trying to track "have I seen this one already" yourself.

## What you do *not* need to implement

- Any notion of "registering" or "connecting" as a distinct step — the first `/v2/lease` call
  is sufficient.
- Retry/redelivery bookkeeping for crashed instances — handled server-side via the ~90s
  reclaim described above.
- Anything related to WebSockets, push notifications, or persistent connections.
