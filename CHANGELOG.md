# Changelog

All notable changes to the Ascend CLI. Newest first. Format follows
[Keep a Changelog](https://keepachangelog.com/); versions follow [SemVer](https://semver.org/).

---

## [Unreleased]

### Added

- **CI (workflow pending a token scope — see `docs/CHANGE_CONTROL.md`).** `.github/` contained only `dependabot.yml`. The test suite, the back-compat corpus, the
  golden-output corpus and the command-map check all existed and all ran only when somebody
  remembered. Every bug that shipped this release shipped green, because green meant green on the
  machine that wrote it. `.github/workflows/ci.yml` now runs all of them on every push and pull
  request, on the declared Python floor (3.9) and a current release, plus a clean `pip install .`
  that runs the *installed* entry point from a temp directory — the check that catches a fix which
  exists locally and was never committed. `docs/CHANGE_CONTROL.md` describes what each gate
  protects and what still depends on a person.

- **`ascend ci --app <name>` resolves the latest finished run.** `--assessment` is now optional.

### Fixed

- **A wedged relay blocked its own replacement, and the run waited on it to the timeout.** A
  relay that was alive but had stopped heartbeating was "not serving" to the auto-lifecycle and
  "already running" to `supervisor.start()`, so every watchdog tick printed *a relay is already
  running for this app* while the run sat paused — ten minutes of the same line, then exit 1.
  `_ensure_bridge` now stops a relay that has not beaten in `HEARTBEAT_STALE_S` and starts a fresh
  one in its place, saying which pid it replaced. A relay that reported a fatal error (a bridge key
  the lease service rejected) is not churned — its error is surfaced instead. The relay's heartbeat
  loop is guarded so a crash in it can no longer end liveness silently while the process lives on.

- **A run the platform paused during a relay outage stayed paused after the relay came back.**
  The watchdog restarted the bridge and nothing resumed the run. A `_PauseGuard` in the `assess run`
  poll now lifts a pause that follows an outage this command saw and fixed (at most
  `AUTO_RESUME_MAX` times per run, never a pause it did not see happen — an operator's
  `assess pause` is left alone and said once), and when a paused run has had no relay startable for
  `PAUSED_NO_BRIDGE_TICKS` polls it exits 1 immediately with the reason and the two commands that
  continue the run, instead of polling to the timeout. `--json` gets the same as an object.

- **`assess watch --all --once` never returned.** `--once` was honoured only by the single-app loop.

- **A probe is never sent unauthenticated when the target's login failed.** When the auth layer
  recorded an error, `TargetCaller.handler` still sent the probe naked — the target's refusal then
  scored as the target's answer. The probe is now answered locally with a 401 and `_error: auth: …`
  and never leaves the machine; the same applies when a re-authentication after a 401 fails.

- **`assess run` exited 0 with the assessment still running.** The platform truncates the
  create-assessment response often enough that the CLI's recovery path is the common one, not the
  rare one. Recovery found the run, saw `running`, and returned that row — from a `wait=True`
  call — so `assess run` printed the `--no-wait` hints and exited 0 in two seconds while the
  probes were still being answered. A pipeline read that as a passing gate. Two seams fed it:
  `poll_assessment` raised on a single failed GET, and `run()`'s recovery returned whatever state
  it found regardless of `wait`. Polling now absorbs a few consecutive transport errors, recovery
  re-resumes and keeps polling when asked to wait, and `assess run` exits non-zero if it was asked
  to wait and the run is not terminal — a wait that returns early can never be green.

- **`ascend ci` and `ascend export` requested `/assessments/None`.** Both take an optional
  `--assessment` and passed it straight into the URL, so omitting it produced

      GET /ascend/applications/aapp_.../assessments/None -> 404 assessment_not_found
        not found — check the app id/name with `ascend app list`

  on every app — and the advice named the one thing that *had* resolved correctly. `ci` was fixed
  first, on its own; `export` was found afterwards, by re-running the audit against a clean clone.
  Both now call one `_resolve_assessment`, which defaults to the latest **finished** run (a run
  still in progress carries partial counts, so gating or exporting those reports numbers that
  change after the file is written). `assess pause`/`resume`/`results` require the flag and are
  deliberately untouched.

- **The CI trust floor was smaller than the smallest legitimate run.** `MIN_CREDIBLE_PROBES = 5`
  guards something real — a completed run with almost no probes and no findings is what a dead
  bridge produces — but the number predates anyone measuring a scoped run. One control at size
  `small` produces exactly **four** probes, so `--controls sys_prompt_leak`, the cheap run the cost
  guidance recommends, could never pass its own gate, and the refusal blamed a bridge that had
  answered every probe. The floor is derived from the app's control set now: at least one probe per
  control. Four probes for one control is a complete run; four for sixty-two is the dead bridge the
  check exists to catch.

- **`probes ? failed / N total` printed a literal question mark.** The v3 assessment payload
  carries `total` but not `failed` — that number lives in `category_summary[].failed`.
  `summarize_result` rendered `a.get('failed', '?')` while the *same line* computed the percentage
  by treating the missing value as zero, so two adjacent expressions disagreed about whether the
  number was knowable. `api.probe_counts()` derives it, and the `?` is kept only for a genuinely
  unreadable payload — 0 means "measured, nothing failed", which is a different claim. The same
  placeholder was reaching `export --format markdown`, a customer-facing artifact.

- **`target add --app <existing>` resolved a control catalog it then discarded.** The control set
  was resolved before the branch that decides whether to create or adopt; the adopt path ignores
  `--controls` entirely, so adopting cost a wasted `list_controls()` round trip and printed
  `no --controls given — registering with all 62 catalog controls` while registering nothing at
  all. Reported by @ryan-straiker in #36.

- **The launcher ignored the clone's own virtualenv.** `./ascend` resolved `python3` off PATH
  before `.venv/bin/python` sitting beside it, so a fresh clone died on `No module named
  'requests'` with a working virtualenv one directory away — the first command a new user runs,
  failing with an error that names a package rather than the problem. `$ASCEND_PYTHON` still wins.
  Fixed by @ryan-straiker in #36.

### Known

- **`export --format csv` writes only failed controls**, so a clean assessment produces a header
  and nothing else: 63 bytes, exit 0, hard to distinguish from a broken export. `to_markdown`
  handles the same case by saying "No failed controls"; CSV has nowhere to put that sentence.
  Widening it to a full control table would change what a row means — `wc -l` on that file is a
  findings count in somebody's pipeline — so it is left as-is pending a deliberate format decision.

### Fixed (earlier in this cycle)

### Fixed

- **Playwright is no longer imported unless a browser target is used.** `adapters/__init__`
  imported the browser adapter eagerly and the adapter imported Playwright at module scope, so
  every run path required it — `adapter validate`, `chat`, `target add`, `assess run` — even for a
  plain REST target, contradicting `pyproject.toml`, the README and `doctor`. Anyone with it
  installed never noticed; a clean install got `No module named 'playwright'`. The import is lazy
  now, matching `websocket_direct` and `bedrock`, and a missing package produces a
  `pip install playwright` hint through the normal failure path instead of a traceback.

- **`ascend target add` failed 100% of the time without `--controls`.** The platform accepts
  exactly one shape for the control selection — `control_type: "custom"` plus an explicit id
  list — and rejects `control_type: "all"` with a bare 400 ("the request was rejected by the
  upstream service"). `app create` resolved the whole catalog client-side to avoid that.
  `cmd_onboard` did not: it had `if controls:` with nothing in the else, so with no `--controls`
  it sent the rejected shape every time. That is the *default* invocation of the command 1.1.2
  makes the primary path, and registration is step 3 of 5 — so the adapter was derived and
  proven against the live target, and then the app could not be created.

  The resolution now lives in one function with two callers, and a source-discipline test
  asserts both registration paths call it and neither re-implements it. A unit test on the
  helper alone would have passed against this bug, because the helper was never the broken half
  — two copies of one rule was the defect.

  Found by recording the docs walkthrough: the failure was captured on screen mid-take.

- **A command that changes or deletes an app takes its exact name.** `_resolve_app` falls back
  from an exact name to a case-insensitive substring match — right for `assess results --app bot`,
  wrong for `target rm bot`, which deleted "Demo Bot" when that was the one app containing "bot".
  `app update`/`delete`, `target rm`, `keys add`/`rm`, `bridge stop`, `assess pause`/`resume` and
  `policy push` now refuse a near miss and list the candidates (exit 3). The three deletes confirm
  on a terminal — never in a pipeline or under `--json`; `--yes` skips it — and share one retire
  path that stops the relay, deletes the app, and only then drops the stored bridge key. `target rm`
  used to drop the key first and exit 0 when the delete then failed, leaving an app nobody could
  serve; it now keeps the key and exits 1 with the reason. Intended `--help` change: `app delete`
  and `keys rm` gain `--yes` (both back-compat corpora re-recorded; nothing else moved).

## [1.1.2] — 2026-09-03

### Security
- **A credential under an unanticipated header name was written into the config in cleartext.**
  `classify.py`'s docstring promises secrets "carry an `env:` `value_ref` placeholder instead,
  and record only the header". It did not hold. `_SECRET_HEADERS` is a fixed list of nine names,
  and that one list answered both "is this auth?" and "is this safe to bake into a config?" — so
  a custom-named credential (`X-Tenant-Key`, `X-Subscription-Key`, `X-Nonce`, `X-Session-Token`)
  was neither recognised as auth nor dropped, and landed on disk beside `auth: none`. It
  *validated green* precisely because the credential had been copied, so nothing signalled a
  problem. Same shape as the two 1.1.1 leaks: the secret escaped through the path least likely to
  be suspected of holding one.

  Recognition is open-ended now, since the whole point is a name nobody listed in advance: a
  broad name vocabulary first, then an entropy backstop scoped to `x-*` headers. The scope
  matters — a `User-Agent`, a `traceparent` and a request id are all long and opaque and none are
  credentials, and over-dropping is its own outage because the config then 401s missing a header
  the target required. Withheld header **names** are reported so they can be re-supplied with
  `--header` / `--bearer` / `--api-key`; the values are never recorded.


### Changed
- **`target` is now the primary noun; `app`, `adapter` and `keys` are the machinery underneath
  it.** An adapter is *how the CLI speaks one target's protocol* — a property of a target, not a
  peer object to manage and keep in sync. Having both at the top level meant `adapter build` vs
  `target add` was a coin flip between two commands with different side effects (one registers the
  app, one does not), and it is the single thing about this CLI that has needed re-explaining most.
  `app`, `adapter` and `keys` are now hidden from the top-level command list and each carries a
  description saying what `target` verb does the same job.

  **Nothing you already script has changed.** Every pre-1.1 form still resolves with the same
  stdout and the same exit code — `adapter build`, `adapter validate`, `app create`, `keys add`,
  `relay ls`, all of it. This is enforced by a new gate rather than promised: 33 legacy invocation
  forms are frozen in `tests/backcompat/` and checked by `scripts/back_compat.py` and
  `tests/test_back_compat.py`. The only new behaviour is a one-line pointer on **stderr** naming
  the current verb, and it is suppressed entirely under `--json`, so a pipe, a script or an agent
  sees byte-identical output on both streams.

  The mapping, also printed under `COMPATIBILITY` in `ascend --help`:

  | still works | current way |
  |---|---|
  | `adapter build` | `target add --dry-run` (`target add` also registers it) |
  | `adapter validate` | `target check` |
  | `adapter show` | `target show` |
  | `adapter configs` | `target list` |
  | `adapter list` | `target types` |
  | `app create` | `target add` |
  | `app list` / `app get` / `app delete` | `target list` / `target show` / `target rm` |
  | `keys add` / `keys list` | `target add` / `target list` |

- Three `--help` screens gained explanatory prose (`adapter`, `app`, `keys`) describing what they
  are relative to `target`. Additive only — 20 inserted lines, nothing removed, and no verb, flag
  or exit code touched.

### Added
- **`ascend target types`** — the kinds of target the CLI can speak to (the adapter-type registry).
  This was previously reachable only as `adapter list`, which was the last remaining reason to use
  that noun at all.

### Fixed
- **A GraphQL target produced a FALSE PASS: the real prompt was frozen and every probe re-asked
  the captured question.** The worst outcome the tool can produce, because nothing looks wrong.
  A GraphQL body is `{"query": "<document>", "variables": {"input": {"message": "<question>"}}}`.
  `query` is in `_PROMPT_FIELDS` (plenty of REST bots do call their field that) and
  `_request_has_prompt` returned the first top-level field-name match — so it returned the
  GraphQL *operation*, templated that to `{{PROMPT}}`, and left the real question in `variables`
  as a literal. `target add` then reported `validated: true` with a genuine on-topic answer, and
  re-deriving with a completely different `--prompt` produced the same answer to the capture-time
  question. An entire assessment would have scored replies to one stale question.

  Two independent guards now, because either can be absent: when `--prompt` supplied ground
  truth, an exact match anywhere in the body beats field-name order outright; and a `query` value
  that looks like a GraphQL document is skipped. A prompt nested below the top level (GraphQL
  `variables`, DTO wrappers) is now found too, and the `_longest_string` fallback no longer hands
  back the document that was just skipped — which is how the first version of this fix undid
  itself.

- **A CSRF-gated chat page could not be onboarded, because the page was thrown away.** Two
  defects stacked. `_worth_recording` keeps every POST but keeps a GET only if its URL matches a
  hardcoded "chatty" word list — and the page being captured is served from `/`, which matches
  none of them. So the one response that bootstraps everything (the CSRF token in a `<meta>` tag,
  the session cookie, inline config) was discarded before classification saw it; that function's
  own docstring makes this exact argument for POSTs and left GETs subject to it. Second,
  origin-scanning only walked JSON string leaves, so an HTML page could not yield the token even
  when captured. Auth then composed `bootstrap_url: ""`, which the auth layer refuses outright.

  The document is now always kept, and a token is found in a `<meta>` tag, a hidden input, or an
  inline script. The emitted regex is keyed on the attribute NAME, never the token value — the
  value rotates every session, so a value-anchored regex would work exactly once and then fail as
  a mysterious auth error — and it uses a lookahead so either attribute order re-extracts. When
  the origin genuinely is not in the capture, the config now says what is missing instead of
  emitting an empty `bootstrap_url` that fails like a tool bug.

### Known
- `_headers_to_dict` lowercases header names at normalization and the original spelling is lost,
  so `_orig_header_name` returns a canonicalized guess (`X-CSRF-Token` → `X-Csrf-Token`). Header
  names are case-insensitive per RFC 7230, so this is harmless for CSRF — but the same path turns
  `SOAPAction` into `Soapaction`, which strict SOAP stacks and some gateways reject.

- **A WebSocket target can now be onboarded from its URL.** `websocket_direct` shipped as an
  adapter, with an example config and its own tests — but nothing could *derive* one. `probe.py`
  spoke only HTTP, and `classify.py` reached `websocket_direct` solely from a HAR that already
  contained a WebSocket entry. Measured against a real socket agent:
  `ascend target add ws://host/chat` exited 3 with "is not a URL, a file, or a known config",
  and `--url wss://host/` was worse — it drove a real browser at a socket and then reported
  "the capture never delivered the prompt". So a customer with a WebSocket bot and no HAR export
  had no path at all, for an adapter that was already written and working.

  A socket is perfectly probeable: connect, send a frame, read one back. `ascend target add`
  now accepts `ws://` and `wss://` (and there is an explicit `--ws` flag), tries the frame
  shapes that actually occur in the wild, and derives `send_template`, `response_path`,
  `aggregate` and a terminal-frame `done_when`. It reuses the same `score_answer` as the HTTP
  path, so "which field is the reply" is decided identically everywhere. Stopping on a terminal
  frame rather than waiting out the idle window matters across a few thousand probes: it is the
  difference between an assessment finishing and timing out.

- **A plain-text bot could not be onboarded at all, and its stream terminator became the answer.**
  Two defects found by pointing the CLI at a real chunked `text/plain` agent.

  For a non-JSON body `_guess_response_path` still returns its `"response"` fallback, and both
  `_http_params` and `compose` wrote that key unconditionally. `direct_api` then saw a
  response_path, demanded JSON, and failed with "expected JSON for response_path 'response' but
  got non-JSON". With the key **absent** the same adapter treats the raw body as the answer,
  which `test_direct_api_non_json_response_no_path_is_text` has asserted since v1.0 — so
  discovery was the only thing standing between a text/plain target and a working config, and it
  was inventing the obstacle. Fixed in both places; fixing one left the other to re-add the key.

  Separately, a chunked text agent closes its body with a marker (`<<<END>>>`, `[DONE]`,
  `<EOS>`). With no JSON envelope to separate transport from speech, that marker is simply the
  last characters of the answer and the scorer reads it as something the agent said — quietly, on
  every turn, which is worse than failing loudly once. Same class as SSE progress chatter
  arriving as the reply. Discovery now records a `stop_marker` when it observes one and
  `direct_api` strips it. Strictly opt-in, and the detector is deliberately narrow: the final
  line must be short, whitespace-free and either bracket-wrapped or a known terminator word, so a
  target whose answer genuinely ends in a short word cannot lose it.

- **`ASCEND_FORCE_COLOR=0` forced colour ON, and `ASCEND_PLAIN=0` turned it off.** Every non-empty
  string is truthy in Python, so both switches did the opposite of what `=0` plainly means. The
  damaging case is a pipe: someone sets `ASCEND_FORCE_COLOR=0` intending "off" and gets ANSI
  escapes written into a log or a file. `ASCEND_PLAIN` is worse in principle — it is the
  "something is corrupting my terminal, make it stop" hatch, the one switch that must never
  invert. Both now accept `0`, `false`, `no`, `off` and empty as off.
  `NO_COLOR` is deliberately unchanged: its spec is presence-based, so `NO_COLOR=0` correctly
  disables colour, and "fixing" it for consistency would break a documented convention.
- **The spinner padded and erased by escape bytes instead of visible columns.** `Progress._write`
  measured `len(line)`, but `_line()` wraps the elapsed clock in dim/reset codes — so bytes and
  cells diverge by 8 exactly when the clock appears at the 3-second mark, which is the moment the
  padding has to be right, because the frame before it is narrower. Left remnants of the previous
  frame on screen and over-erased on the way out. Same defect already fixed in `bar()` and
  `_watch_many`; all three now measure cells.
- **`ascend version --json` printed bare text.** It was wired straight to `print(VERSION)` and was
  the only command that ignored `--json`, so an agent that explicitly asked for JSON got `1.1.1`
  and a parse error. Both `ascend version --json` and `ascend --version --json` now emit
  `{"version": "..."}` and are asserted to agree. The human form is still exactly `1.1.1`.

  All three were invisible to the suite for the same reason: nothing ran the CLI on a TTY or asked
  what a switch does when set to a falsy value, so the entire opt-out path was unexecuted. Each
  fix is mutation-checked — the fix is reverted, the new test is confirmed to fail, then restored.

## [1.1.1] — 2026-09-02

### Security
- **`app list` and `app get` no longer print bridge keys.** The platform returns `thin_api_key` on
  GET and in the application list, not only at creation, so a read-only listing emitted every
  bridge-type app's key in full — into CI logs, agent transcripts and screen shares, from the
  command least likely to be suspected of holding a secret. They are masked now, as `creds` already
  promised everywhere else. `app create` still shows the key once, on purpose.
- **A credential in a URL query string is now redacted.** Masking matched on key *names* only,
  while the CLI itself bakes credentials into the endpoint (`--api-key ...:in=query`, a Gemini-style
  `?key=`). The credential therefore survived redaction in a *value*: printed by `adapter show`
  while it claimed "secrets masked", logged on every probe, written to capture transcripts, and
  posted to the platform inside a failing probe's error text. Redaction is value-aware now, and the
  adapter scrubs the URL before logging or reporting it.

### Fixed
- **A create-then-stream target is now built correctly from captured evidence.** compose() picks
  one branch by transport and the streaming branch never consulted the session layer — only
  `direct_api` got a "session upgrade". So an agent that makes you create a conversation before
  streaming (create a thread, then stream the turn) was composed as a plain POST to the captured
  path, which still contained the conversation id from the capture: every probe posted into one
  dead conversation, and the create step vanished even though it had been detected. The `create`
  block is now emitted and the path is templated with `{{CONV}}`.
- **The prompt is substituted into the create call.** These APIs routinely name the conversation
  after the question (`{"description": "{{PROMPT}}"}`); only `{{CONV}}` was substituted, so the
  literal placeholder was posted as the title.
- **Progress chatter no longer arrives as the agent's answer.** A stream can type its frames on
  the SSE `event:` line rather than a field in the payload. Those payloads have no `type`, so the
  frame filter fell through and collected EVERY frame — prepending "Analyzing query…",
  "Searching resources…" to every reply, which the scorer then reads as the agent's words. The
  event name is now used as the frame type, and only when `token_types` is explicitly configured,
  so a stream relying on the collect-everything default is unaffected.
- **The streaming field mapping is derived from captured evidence** instead of emitting a bare
  `{"format": "sse"}` that collects no frames. Derivation is event-aware on purpose: picking the
  field that appears most often selects the progress chatter, because status frames outnumber
  answer frames.
- **`--login-url` records a repeatable login, not just the token it produced.** Its own docstring
  claimed it returned "an `auth` block so the bridge re-authenticates on its own during a long
  run"; the code returned only a header, so the config carried a static token that died with it.
  It now writes a `derived_multihop` auth block plus `reauth_on_401`, and credentials written as
  `env:NAME` stay out of the config file.
- Tests that pin a config directory now clear `ASCEND_CONFIG_DIR` as well as the legacy name, so
  an ambient value in the developer's shell no longer causes spurious failures.
- **A streaming target with a query string no longer loses it, or forks a config on every run.**
  Promoting a config to `sse_stream` split the endpoint into `base_url` + `chat_path` and dropped
  the query, while the probe path deliberately keeps it. Where the query is *required* — Azure
  OpenAI's `?api-version=`, Vertex's `?alt=sse` — the upgraded config called a URL the target does
  not serve, so the re-validation failed and the streaming upgrade silently never applied, leaving
  a `direct_api` config that hands the scorer raw `data:` frames. Where it was optional, the stored
  endpoint no longer matched what the next run derived, so an ordinary re-run looked like a
  different target: the freshly captured credential was written to `<name>-2` while `--config
  <name>` kept serving the expired one.
- **A second bot on the same host no longer destroys the first one's config.** The config name is
  derived from the URL's *host*, so two endpoints on one host (`https://h/chat` and
  `https://h/v1/chat`) derived the same filename and the second run overwrote the first — including
  the `_ascend` app binding it carried — and exited 0 with a success message. A genuinely different
  endpoint under an already-used name is now saved alongside as `<name>-2`, with both targets named
  in the output.
- **Re-deriving a config no longer unbinds it from its application.** A refresh rewrote the file
  wholesale, discarding the `_ascend` binding written at registration, so the target silently lost
  its app. Binding metadata is now carried forward.
- **An update rewrites the file it resolved from**, instead of writing to whichever config
  directory the current working directory happened to select — which produced a second copy
  elsewhere rather than updating the one in use. Writes stay inside a real config directory: reads
  deliberately search wider (the working directory, and a frozen build's unpacked examples), and a
  write must never follow them there.

- `--out ./mybot.json` now writes to the current directory. `Path("./x").parent == Path(".")`, so an
  explicitly written path was indistinguishable from a bare name and the file appeared in the config
  directory instead.
- `--out out/mybot` now writes `out/mybot.json`. The extension was only added for bare names, so
  this wrote a file literally named `mybot` — which nothing that looks for `*.json` can ever pick
  up, including `adapter configs` and name-based `--config` resolution. (A config written outside a
  config directory is still reached by path, not by bare name: `--config out/mybot.json`.)
- **`--out` pointing at a directory is now a usage error** instead of silently writing a file named
  after that directory (`--out out/` wrote `./out.json`), or crashing with a raw pathlib
  `ValueError` after the probe and the live validation had already run (`--out ./`).
- `--code` honours the directory in `--out` instead of reducing it to a stem and writing to the
  config dir regardless — which is what the docs already promised. When the module lands outside
  the config dir its pointer records an absolute path, because the `custom` adapter looks only in
  the config dir and would otherwise fail to load a module that had just validated.

- **A config now resolves the same way from every directory.** Config lookup picked the first
  configs *directory* that existed and then searched only inside it. Every checkout of this repo
  ships a `configs/` of examples, so running the CLI from a checkout made `~/.ascend/configs`
  invisible: a target created from one directory was "config not found" from another, and after
  upgrading by re-installing, a working target could disappear entirely. What the operator saw was
  a bridge — because `runtime start` exits before it ever leases, and a relay that never starts is
  indistinguishable from one that dropped. The app's *key* kept resolving throughout (keys live in
  `~/.ascend` and never depended on the working directory), which is exactly what made it read as
  a flaky bridge rather than a lookup bug. Configs are now searched per *file* across every config
  directory, `adapter configs` lists all of them and says where new ones are written, and precedence
  is unchanged — an explicit `$ASCEND_CONFIG_DIR` still wins, and a local `configs/` still shadows
  home, so nothing that resolves today resolves differently.

### Added
- **`--app <name|aapp_id>` on `target add` / `onboard`: bind to an application that already
  exists** instead of creating a second one, fetching its bridge key for you. This is the shape of
  a stalled engagement — the app was configured in the Console (system prompt, controls, size,
  QPM), someone starts an assessment, it fails, and nobody can say where the bridge is. There is
  nothing to find: a bridge is a process this CLI runs. Creating a fresh app instead stranded all
  of that configuration on an application nobody assesses.
- **`configs/example-create-then-stream.json`: a complete target definition** for the hardest
  common shape — bearer auth, a conversation that must be created first, and an answer streamed
  back as named SSE events interleaved with progress chatter. Every section is annotated with what
  it controls and how it fails. Copy it, change the ALL-CAPS values, `adapter validate` it: a
  deterministic path that needs no capture and no inference.
- **`--save-as <name>` on `target add` / `onboard`.** The config name was derived from the URL and
  never choosable, so it came out as `myhost-com` or `127-0-0-1-8791` and the only way to learn it
  was to read a line of stderr — then you had to pass exactly that to `--config` later. Name it
  once and every later step is deterministic.

- **`ascend target` — one noun for the thing you actually assess.** A target used to be spread
  across an adapter config, an application record, a stored key and a purpose string, and you had
  to hold all four in your head and keep them in sync. `target add | list | show | check | rm` is
  now the everyday surface: `show` puts everything bound to a target in one place, `check`
  re-proves it against its live endpoint and times it, and `list` says which are registered and
  which are serving. `app`, `adapter` and `keys` are unchanged underneath and still fully
  supported — nothing was removed or renamed.
- **`target add <thing>` works out what you gave it.** A URL, a request copied out of devtools, an
  exported browser session, or a saved config — it detects which and onboards from it. Choosing
  between five mutually-exclusive source flags was a question people often could not answer; the
  artifact itself says which it is. It stops once the target is registered and proven, because
  spending an assessment is a separate decision (`--run` to continue straight into one).

- **The MCP shim can onboard a target.** It exposed nine tools that could run and read an
  assessment but could not *create* the thing being assessed, so an agent driving Ascend over MCP
  hit a wall at the first step and had to drop to a shell. `ascend_target_add` and
  `ascend_target_check` close that gap, and lead the tool list because an agent reads it top-down.

- `adapter validate` reports the target's measured reply time and warns when it cannot survive the
  platform's per-probe window — a config can be correct and the target still unassessable. Learned
  from one probe instead of from a whole failed run.
- `$ASCEND_PLATFORM_PROBE_WINDOW_MS` sets the per-probe window the CLI assumes the platform
  enforces. It is the only timeout knob: the bridge's give-up point and the adapter's own timeout
  are derived from it, so raising the platform-side window is a config change, not a release.

### Changed
- The skills carry a troubleshooting playbook and a per-target-pattern catalog: which adapter
  suits which target shape, and the way each one specifically fails. Most failures here present
  as a different failure than they are, so the playbook is ordered by symptom and starts with the
  one number that settles it — `ANS` in `bridge ls`.
- `ascend --help` leads with the one command that does the whole flow (`onboard`) and shows the
  seven you use day to day, with the rest listed by name. 71 lines to 44. No command changed or
  moved — every one still runs exactly as before.

### Compatibility
Nothing that works today changes. Specifically, and covered by tests:
- a bare `--out <name>` still lands in the config dir, so `--config <name>` still finds it;
- an absolute `--out` path is untouched;
- re-running against the **same** endpoint still overwrites the config in place — that is an
  intentional refresh and scripts depend on it. Only a *different* target under a used name is
  moved aside, and only when the name was derived rather than given;
- `--save-as` is explicit intent and overwrites deliberately;
- no existing file is moved, renamed or migrated.

### Documentation
- **The shipped docs and the architecture diagrams now describe the tool as it is.** They still
  taught the old shape — onboarding framed as picking among source flags, `target` absent
  everywhere, and the interactive map's lifecycle stepping through build → register → assess. The
  README, architecture, lifecycle, surface, usage and adapter guides now lead with `target`, and
  the interactive map's lifecycle is `identify → add target → assess → analyze`, with `app`,
  `adapter` and `keys` documented as the machinery underneath rather than as the way in.
- Corrected while auditing them, since a wrong reference is worse than a missing one: the adapter
  count was documented as 13 or 14 in five places and is **15**; the stateful-adapter set was
  documented as 8 and is **12**; `terminal` was listed as a transport and does not exist; the
  usage guide claimed the `app` verbs only covered bridge apps and sent readers to a Python
  snippet, when `app create --type` has covered all four types for some time; the README claimed
  45 commands against a generated reference that counts 53; and the architecture diagram gave the
  cloud lease service and your local bridge process the same node id, so they rendered as one box
  with a self-loop. The two are now named separately, in the glossary as well.
- Documented the per-probe window (~110–120s, timed from when a probe is **queued**) and the fact
  that exceeding it returns a synthetic timeout indistinguishable from a target failure — the
  single most misread behaviour in this system, because it presents as a dropped bridge.

## [1.1.0] — 2026-09-01

Relay management was the consistent failure point for customers ("the bridge keeps dying", "probes
stopped flowing"). Every fix below was found by running the CLI against the real platform.

### Fixed
- **Relay lifecycle.** A relay now stops only for the assessment it is bound to (it used to infer
  "done" from any assessment on the app, and reap itself mid-run); an unbound relay never
  self-stops, which is what makes a standalone `runtime start` persistent. A hand-started relay
  registers itself under the app it serves, so the CLI can no longer start a second relay for the
  same app and split its probes. `assess run` releases only a relay it started, and only once the
  run is genuinely terminal. Dead relay state older than a day is pruned from `bridge ls`.
- **Credentials that expire mid-run.** The `auth_lifecycle` block (`static | refresh_on_ttl |
  reauth_on_401 | cookie_rotation`) is applied at the shared call seam, so an auth challenge
  re-acquires credentials and retries the probe once for every adapter. Previously an expired token
  turned every later probe into a 401 that scored as a target refusal.
- **`app create --type bridge` without `--controls`.** The CLI sent a control selection the platform
  rejects; it now resolves the control catalog itself. `create_app` also recovers when the response
  is dropped after the app was created, instead of reporting a failure that succeeded.
- **Target timeouts.** Adapters each hardcoded a short ceiling and `adapter build` pinned the
  discovery timeout into the config it wrote, which turned a healthy slow target into 100% probe
  failures. One derived value now governs, and `adapter build` no longer pins one.

### Known limitation
The platform bounds how long each probe may take (~120s), and the clock starts when the probe is
**queued**, not when the bridge calls the target. A target that reliably takes longer cannot be
assessed through the bridge, whatever `timeout_ms` says — agentic targets at 2-3 minutes per turn
are past it. Raising the adapter timeout does not help; the platform-side window has to be raised
first, and then `$ASCEND_PLATFORM_PROBE_WINDOW_MS` tells the CLI about it.

## [1.0.0] — initial release

First release for the SE team. A single, scriptable CLI that connects the **Straiker Ascend**
assessment cloud to any AI target and runs a red-team assessment end to end.

The model is **Iris → Bridge → Adapter → App**: the bridge is generic; the *adapter* is the
per-app piece that knows how to talk to one specific target.

### Connecting to targets
- `ascend adapter build` derives a **validated** adapter from a HAR, a cURL, an OpenAPI spec, a live
  URL (drives a real browser), or an API endpoint, and proves it against the live target before
  writing anything. An unvalidated config is never saved.
- 15 built-in adapters (REST/JSON, SSE and marker/sentinel streaming, WebSocket, multi-step session
  APIs, browser widgets, and the platforms: Salesforce Agentforce, Slack, Vertex AI, Copilot
  Studio, Amazon Connect, AWS Bedrock).
- **Per-app adapters as code**: when no built-in pattern fits, `--code` generates a self-contained
  adapter module for that one app and proves the generated code live.
- **Anti-automation targets** (endpoints that 403 any non-browser replay) are handled
  automatically: `adapter build --url` falls back to a generated **browser** adapter, driven and
  validated through a real browser.
- Auth-first throughout: bearer, API key, basic, cookie, login/access-code flows, mTLS, custom CA,
  proxy; an SSRF guard that allows internal RFC-1918 targets but blocks cloud metadata.

### Running and managing assessments
- `app create` (types `thin | api | gcp | bedrock`), `bridge start` (the CLI *is* the bridge; one
  per app, keyed and adapter-bound), `assess run/watch/pause/resume`, and a single-tenant lock so
  an SE cannot cross customers.
- Local `tc-` bridge-key store, one per app; keys are shown once and never printed in full.

### Reading results
- `ascend results` — assessments as a table, or a Console CSV export analysed in depth: rollups by
  the platform's own taxonomy (risk tag, category, control, data class) and by evasion technique,
  a data-harvest view with value provenance, and a guardrail confusion matrix.
- `ascend ci` — pipeline gate with a stable exit-code contract (`0` clean · `1` could not
  read/trust the results · `2` findings). Fails safe: a run that measured nothing (dead bridge,
  server-side failure, undeterminable severity) is never reported as a pass.
- `ascend export` — SARIF / Markdown / CSV / JSON.

### Agent- and CI-friendly
- One-object-per-call JSON on `--json` (success and failure), human prose to stderr only, so
  redirecting one never corrupts the other. Idempotent create flags (`--if-not-exists`).

### Safety properties
- Nothing is written that did not answer the live target. Unanswered probes are never counted as
  passes. `doctor --api-compat` watches for API drift. One tenant per machine.
