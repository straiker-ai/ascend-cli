# GitHub Actions example

`ascend.yml` runs an Ascend AI assessment on a release (or on demand) and fails
the build when findings breach a severity threshold. Copy it to
`.github/workflows/ascend.yml` in the repository you want to gate.

## Requirements

- A Straiker PAT with `ascend:read` and `ascend:write`, stored as the repository
  secret `STRAIKER_PAT`.
- An application already onboarded in the Straiker Console. Set `ASCEND_APP` to
  its name.
- Ascend CLI 1.1 or later. 1.0 can report no findings while measuring nothing.

## Gate behavior

| Exit | Meaning | Build |
|------|---------|-------|
| 0 | clean | passes |
| 1 | results could not be read or trusted | fails |
| 2 | findings gate failed | fails |
| 3 | bad invocation | fails |

Exit 1 and 2 are distinct on purpose: 2 found real problems, 1 learned nothing.

## Two things that catch people out

**Without a baseline, every finding is new**, and failing on new findings is the
default — so a first run fails on any finding at all, whatever
`--fail-on-severity` says. Pass `--allow-new` to gate on severity alone, or keep
a baseline:

```bash
ascend export --app "$ASCEND_APP" --assessment "$AID" --format json --out current.json
ascend ci --file current.json --baseline .ascend/baseline.json --fail-on-severity high
```

Both flags read local files, so that form needs no network.

**The credible-probe floor is read from the application's control set when the
gate runs**, not from the set the assessment used. If a job re-scopes the
application between the run and the gate, the verdict can change on an unchanged
assessment. Pass `--min-probes` explicitly in that case, or gate an exported file
with `ascend ci --file`, which does not consult the application.

## Ephemeral runners

The CLI keeps state in `~/.ascend` — the tenant pin, bridge keys, token cache —
and a fresh container has none of it. `ascend app create --if-not-exists` is safe
to repeat. Bridge-type applications need their `tc-` key supplied as
`STRAIKER_BRIDGE_API_KEY`, or `ASCEND_STATE_DIR` persisted between jobs.
