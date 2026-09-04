# Change control

**A changelog records what changed. It does not stop a regression.** This file describes what
does, why each gate exists, and what still depends on a person.

Everything here was written after a release in which every shipped bug shipped *green* — because
"green" meant "green on the machine that wrote it".

---

## The gates

| Gate | Runs | Catches |
|---|---|---|
| `pytest tests/` | CI, every push and PR | logic regressions |
| `scripts/back_compat.py --check` | CI | a pre-1.1 command form that changed |
| `scripts/golden_output.py --check` | CI | piped stdout that changed |
| `scripts/gen_command_map.py --check` | CI | `docs/COMMAND_MAP.md` gone stale |
| clean `pip install .` + run | CI | a half-done version bump; a broken package |
| `scripts/live_matrix.py` | **release only, by hand** | an adapter that cannot talk to a real target |
| `scripts/live_auth_matrix.py` | **release only, by hand** | a target behind a login the CLI can no longer onboard, or a credential stored in a config |
| mutation check | **by hand, per fix** | a test that passes against the bug |

CI lives in `.github/workflows/ci.yml`. Before it existed, `.github/` held only `dependabot.yml`,
and every gate above ran only when somebody remembered.

> **Status:** the workflow file is written and verified but not yet committed — adding a file under
> `.github/workflows/` requires a token with the `workflow` scope. Until it lands, every row in the
> table above marked "CI" is still a manual step. Run them with the commands in this file.

### What each gate is actually protecting

**Back-compat corpus (33 forms).** People are scripting `adapter build`, `app create`, `relay ls`
mid-engagement. Their exit codes and stdout are an interface. When this fails, the fix is the
code — *re-recording the corpus to make it pass is how the promise gets broken quietly.* If a
change is genuinely intended, say so in the commit message and the changelog, then re-record.

**Golden output (13 cases).** `ascend --help | grep` appears in customer runbooks. This is why the
launch-screen diagram is TTY-gated: piped output must be byte-identical.

Both corpora are **pinned to Python 3.12**, the interpreter that recorded them, and skip elsewhere.
argparse's own wording is version-dependent — 3.10 renamed `optional arguments:` to `options:` — so
a corpus recorded on 3.12 reports a diff on 3.9 that this project did not cause. Two spurious
failures a contributor cannot tell from a real regression is worse than no check. Re-record on 3.12
if you ever need to move the pin; the rest of the suite still runs on every version in the matrix.

**Command map.** `docs/COMMAND_MAP.md` and `docs/command-map.html` are *generated* from the live
argparse tree. Never hand-edit them; regenerate and commit. This is also why the block diagram is
printed from `main()` and not from a parser `description`/`epilog` — anything placed there gets
committed into the generated docs and goes stale there permanently.

**Clean install.** Runs the *installed* entry point from a temp directory, not the working tree.
That distinction matters: a fix that exists locally and was never committed passes every local
check and still ships broken.

---

## Per-fix discipline

These are not automatable, and they are where most of the value is.

**1. Write the test so it fails against the bug.** Revert the fix, watch the new test fail, restore
it. A regression test that passes against the bug is not a test. Several tests in this repo were
strengthened only after a mutation showed they could not fail.

**2. When the rule is shared, test the CALL SITES, not just the helper.** This is the single most
common defect in this codebase. A rule gets fixed in one place and not the other, and a unit test
on the helper passes, because the helper was never the broken half. Real instances:

- `response_path` derived in both `classify.py` and `probe.py` — fixed in one, the live path kept
  the old behaviour
- control resolution in `cmd_app_create` and `cmd_onboard` — one had it, one 400'd 100% of the time
- assessment-id resolution in `cmd_ci` and `cmd_export` — `ci` was fixed, `export` was not, and
  `export` is how a report reaches a customer

The guard is a source-level test asserting each call site uses the shared helper and none
re-implements it. Grep code, not comments — a guard that fires on prose gets muted.

**3. Check the scope of the claim before writing it down.** A test that states something untrue
about the code is worse than no test, because it is read as documentation. `assess results` looked
like a third instance of the resolution bug and was not — its flag is `required=True`, so the case
can never arise.

**4. Verify from a clean clone, not the working tree.** `git clone` the repo and run the thing.
This is the check that catches uncommitted fixes, missing files, and anything `.gitignore` ate —
two test fixtures were swallowed by a `*.har` rule and the tests passed only for their author.

**5. Measure; do not assert.** Probe counts, latency, payload sizes, cell widths. `MIN_CREDIBLE_PROBES`
was set to 5 before anyone measured that a one-control run produces 4 — so the cheapest run the
tool recommended could never pass its own gate.

---

## What CI cannot do

`scripts/live_matrix.py` drives **real agents and a real tenant with a real PAT**. It cannot run on
a pull request: a fork PR would hand a token to untrusted code. It is a release step, run by hand:

```bash
export STRAIKER_PAT=s6r_pat_...
python3 scripts/live_matrix.py
```

This is the only gate that proves an adapter can actually talk to something. The offline suite
mocks transport by design (`tests/test_adapters_config.py` says so: *"No sockets"*), so a green
suite says nothing about whether the CLI can reach a target. **Every field failure this release was
in that gap.**

---

## Release checklist

1. Full suite and all gates green in CI on the merge commit.
2. `scripts/live_matrix.py` green — with the measured probe count recorded.
3. `scripts/live_auth_matrix.py` green — ten auth gates derive as expected, no secret in any written config.
4. A real end-to-end run against a real agent: `target add` → `target check` → `assess run` →
   `results` → `ci`. Every step, not just the ones that changed.
5. Version bumped in **both** `shells/cli/ascend.py` and `pyproject.toml`
   (`tests/test_version_sync.py` enforces this).
6. `CHANGELOG.md` entry under the new version, moved out of `[Unreleased]`.
7. Clean-clone check: `git clone`, run `./ascend`, confirm the change is actually there.
8. Tag and release. **A merge to `main` is not a release** — anyone installing a released binary is
   on the last tag, not on `main`.

---

## The changelog's role

`CHANGELOG.md` is the record, not the control. It exists so that six months later someone can find
out *why* a line of code is the way it is — every entry names the failure, not just the fix.

Entries go under `[Unreleased]` as work lands, and move to a version heading at release. One entry
per user-visible behaviour change; a refactor with no behaviour change does not need one.
