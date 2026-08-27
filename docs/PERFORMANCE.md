# Caching and performance

Two changes reduced per-command latency:

| Cost | Before | Now |
|---|---|---|
| PAT→JWT exchange, **every command** | 1.14s | 0s while a cached token is valid |
| HTTP connections | a fresh TCP+TLS handshake per call | one pooled connection (~64% faster over 6 calls) |
| `ascend controls list` (end to end) | 1.54s | **0.41s** |
| `ascend app list` | ~1.5s | **0.42s** |

## The JWT cache

A platform PAT is exchanged for a short-lived JWT (**~10 minutes**). That token is cached at
`<state-dir>/jwt.json`, mode **0600**, and reused until 60s before it expires.

Safety properties:
- keyed by `sha256(PAT | token_url)`; the PAT itself is never written;
- **tenant-scoped**, and the cached token's own `iss|straikerId` fingerprint must match the pinned
  tenant before it is used, so a token can never leak across tenants;
- dropped on a 401 (so a rejected token isn't re-read by the next process) and on `tenant switch`;
- a token whose `exp` cannot be decoded is kept briefly in memory but **never** persisted.

The long-lived PAT already sits in the environment; the cached JWT is a 10-minute credential in a
0600 file.

## What is never cached

- **`get_assessment`**. It is the live status; caching it would freeze `assess watch` and the
  poller.
- **The assessments list on any liveness path**. A stale `complete` would hide a running
  assessment whose relay died, which is how a false pass happens. `assess run`
  auto-manages the bridge, so this is now mainly a risk when auto-management is off or a remote
  bridge dies. The liveness path stays uncached so `bridge sync` and the NO-BRIDGE alarm see current state.
- Anything non-GET, and any response carrying a one-shot `tc-` key.

`ASCEND_NO_CACHE=1` disables caching entirely.

## Operations spanning all apps

There is no tenant-wide assessments endpoint, so anything spanning apps (`app list --with-runs`,
`reports`, `status`, `relay ls`'s orphan check) is **one call per app**, run 12-wide in parallel with
a progress line. On a 38-app tenant that is ~2s. A spinner shows progress during the scan.

Shortcuts when you don't need the scan:
```
ascend status --quick          # skip the per-app assessment scan
ascend app list                # apps only, no runs (~0.4s)
ascend bridge ls --no-check     # local bridge state only, no tenant lookup
ascend reports                 # cheap columns; --detail adds a call per run
```

## Retries and pooled connections

Pooled keep-alive sockets go stale when the server closes an idle connection, which surfaces as
`RemoteDisconnected`. Idempotent methods (GET/HEAD/OPTIONS) retry automatically. **POSTs do not**,
because replaying one could create a second app or assessment. When a create hits a transport
error the CLI **verifies against the server** before reporting, so a create that actually succeeded
is not reported as failed.
