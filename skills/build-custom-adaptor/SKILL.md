---
name: build-custom-adaptor
description: >-
  Build, test and apply a custom Ascend adaptor (engine-side JavaScript stored on the
  application) for a target URL, with `ascend adaptor har|shape|spec|scaffold|gate|test|store|verify`.
  Use when an SE asks to build or fix a custom adaptor for a customer's chat application, names
  a target URL and an Ascend app that needs one, or when the app's auth or session cannot be
  expressed as a request/response template (a login, a token mint, a conversation to open, a
  reply to poll for). Not for a CLI adapter config; that is build-adapter.
---

# build-custom-adaptor

Full instructions are in `docs/CUSTOM_ADAPTOR.md`. Read it now and follow it; it is the contract
for this job, not a summary. An **adaptor** is one JavaScript file the Ascend engine runs against
the target. It is not an **adapter** (the CLI's own Python, run on your side behind the bridge); if
the target is reachable from this machine and a template can drive it, the `build-adapter` skill
and `ascend target add` are the shorter road.

`ascend` below means `python3 shells/cli/ascend.py`.

**One job, end to end.** Find out how the target works → write the adaptor → gate, test and
correct it until it genuinely works → store it on the application → tell the SE it is ready. If
asked to onboard an app, change controls or start an assessment, say that this skill does not and
point at `target add` / `assess run` / the Console.

## The short version

1. **Credential**: `ascend doctor`. `test` and `verify` execute an adaptor against the target, so
   the key needs both Ascend scopes (read and manage). This CLI never mints one; ask for one if it
   is short.
2. **The app**: `ascend target list`; yours has the target as its URL. Keep **both** ids:
   the name or `aapp_…` for `store`/`shape`, the engine uuid from the Console URL
   (`…/applications/ascend/<uuid>`) for `get`/`test`/`verify`. Give those three a name or an
   `aapp_` id and the CLI joins it to the uuid through the Console's own listing (and says so);
   `--console-id <uuid>` overrides when that listing cannot be read, and the CLI explains the
   mix-up when the engine answers "could not be read". Note that `ascend target add` now
   generates, stores and verifies an adaptor by default (`<config>.adaptor.js`): this skill is
   for finishing or replacing one — a target with a login handshake, or a contract no generator
   covers, is registered with the scaffold and marked `UNFINISHED`, and this loop finishes it.
3. **The reply shape**: `ascend adaptor shape --app <app>` prints the app's `response_template`
   and the exact `return` statement to write. Read it before writing a line. An app carrying
   `v0:passthrough` is waiting for its real adaptor; an app on the retired `https://custom-adaptor`
   URL needs its real URL set in the Console first.
4. **Find out what the target takes**: ask the SE for a HAR, captured in a private window with the
   chat opened and one message answered (`docs/CUSTOM_ADAPTOR.md` has the steps to pass on), and
   read it with `ascend adaptor har <file> --bodies`. The **SESSION CHAINS** section is the
   adaptor's step list, in order. No chains means one request: write the thin version. Never guess
   at auth. If the app's URL is an API rather than a page, get the page with the chat and capture
   one exchange there. For a tunnel or private-link app, build every URL from
   `host.config.endpoint()`; this machine cannot reach it, `adaptor test` can.
5. **Write it**: `ascend adaptor spec --out host.d.ts` first, then start from
   `ascend adaptor scaffold --out my_adaptor.js`. One file, `sendTurn` defined, synchronous, no
   `fetch`/`async`/`Promise`/npm, no global the isolate lacks (`atob`, `URL`, `Buffer`… are refused;
   `console` is allowed), no `this` outside a class, no `with`, no `host[expr]`, no `__` names, no
   TypeScript, no module state. If the target has a cheap credential check
   (`/me`, `users/authenticated`), also define `checkReachability(turn, host)` in the same file so
   preflight does not spend a real turn. Drain a greeting the bot sends when a conversation opens;
   on a 401 for a token you minted, mint again and retry once; a HAR showing no auth does not mean
   there is none.
6. **Loop**: `ascend adaptor gate my_adaptor.js` → `ascend adaptor test my_adaptor.js --app <uuid>`
   → read the host-call transcript → fix → repeat. One change per test; each test is a real
   conversation with a real system.
7. **Apply**: `ascend adaptor store my_adaptor.js --app <app>` (gated first; only `_adaptor_src`
   changes, except an endpoint key the engine would never read, which is dropped and said;
   `--endpoint <url>` only for an app with no URL; the write is read back — in `--json`,
   `template_digest` equal to `stored_digest` is the proof it landed, not the engine's `digest`),
   then `ascend adaptor verify --app <uuid>`, which runs what is **stored**. Then tell the SE it is ready, to delete the HAR, and to start a **NEW** assessment,
   not **Rerun**: an assessment snapshots the app when it is created, and Rerun clones the previous
   assessment, so it replays the old adaptor and silently produces wrong output.

**Return the shape the app's `response_template` describes.** `{"response": "{{ RESPONSE }}"}`
means `return { response: text }`. The engine applies that template to your reply; if the shapes
disagree, `parsed_response` becomes a stringified object and a detector scores *that*.

Done means the **`scored :`** line is the assistant's actual answer, not the status and not
`parsed`. `scored` is computed with the same function a run uses, so it is the only view that tells
you what a detector will see; when it disagrees with `parsed`, believe `scored`. The CLI exits `1`
on a stringified or empty scored line and `2` when the gate refuses the file. An error string, an
empty string, a greeting or an echo of the prompt is not done.

## Definition of done

- `ascend adaptor gate` passes, and `test` shows a real answer on the `scored :` line for every
  prompt, with no host call erroring.
- `store` reported the write read back, and `verify` passed on the stored bytes.
- The SE has the app's name and ids, the stored address, the `verify` output, whether preflight
  is cheap (`checkReachability`) or spends a turn, and the NEW-not-Rerun note.
- The HAR is deleted.
