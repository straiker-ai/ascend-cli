# Changelog

All notable changes to the Ascend CLI. Newest first. Format follows
[Keep a Changelog](https://keepachangelog.com/); versions follow [SemVer](https://semver.org/).

---

## [Unreleased]

### Changed
- **App type `thin` is now `bridge`** everywhere a user sees it: `app create --type` choices are now
  `bridge|api|gcp|bedrock` (default `bridge`), and `app create|list|status` output and help all say
  `bridge`. The v3 API wire value is unchanged (`api_type: "thin"` internally) — only the
  user-facing label moved, so no API or protocol change.
- **The bridge is auto-managed.** `ascend assess run` on a bridge-type app auto-starts the CLI's
  built-in relay *before* probes are scheduled, and the bridge self-stops when the assessment reaches
  a terminal state. While an assessment is paused the bridge stays alive and keeps serving (idle
  cleanup is opt-in via `--idle-timeout`, off by default). `ascend assess resume` re-ensures a bridge (the reliable path after a Console-side resume,
  since the SaaS cannot start a process on your machine). `ascend bridge start` still exists for
  advanced/remote/continuous/pre-start use but is no longer a required step in the normal flow.
- A bridge is **per-app**: one relay is shared across that app's assessments with no cross-assessment
  contamination — the v2 lease/result protocol carries only opaque `request_id`/`msg_id` that the
  bridge echoes back, and the platform attributes each probe to its assessment.

### Added
- `ascend bridge sync` — reconciles local bridges to platform assessment state (start for
  running/paused apps, stop for terminal). The manual fallback when state changed in the Console.
- **Live run view for `ascend assess run`.** While an assessment runs, the terminal shows the Ascend
  logo header (the weapon-star drawn in braille next to the `ASCEND` wordmark) and a live probe feed:
  each completed probe streams in as a red-star-bulleted line with `pass`/`FAIL`, paced to read like
  the Console live view. Driven by the run's aggregate progress counts (no live prompt text). Three
  render tiers, auto-selected: the real logo PNG inline on image-capable terminals
  (iTerm2/WezTerm/Kitty/Ghostty), the braille logo on any truecolor or 256-color terminal (VS Code,
  Apple Terminal), and the `ASCEND` wordmark as a mono fallback. TTY-only: scripts, pipes, agents, and
  `--json` render nothing. Override the tier with `ASCEND_LOGO=image|block|wordmark|off`.

### Removed
- `ascend app create-thin` — use `ascend app create --type bridge` (`bridge` is the default type, so
  `ascend app create` already creates a bridge app).

### Safety
- False-pass safety is preserved: a bridge never self-stops when it cannot verify assessment state.

### Fixed
- **The bridge no longer self-stops while a run is stalled.** Previously the relay idle-timeout (30
  min) treated a `created`/pending run the same as a genuinely paused one, so a platform stall would
  reap the bridge at the worst moment and strand the run. The bridge now stops only when the run
  reaches a terminal state and rides through `created`/`paused`/stalled states. Idle cleanup is now
  opt-in via `--idle-timeout` (0 by default), and reaps only a paused run that actually relayed a
  probe and then went quiet.

---

## [1.0.0] — initial release

First release for the SE team. A single, scriptable CLI that connects the **Straiker Ascend**
assessment cloud to any AI target and runs a red-team assessment end to end.

The model is **Iris → Bridge → Adapter → App**: the bridge is generic; the *adapter* is the
per-app piece that knows how to talk to one specific target.

### Connect to any target
- `ascend adapter build` derives a **validated** adapter from a HAR, a cURL, an OpenAPI spec, a live
  URL (drives a real browser), or an API endpoint — and proves it against the live target before
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

### Run and manage assessments
- `app create` (types `thin | api | gcp | bedrock`), `bridge start` (the CLI *is* the bridge; one
  per app, keyed and adapter-bound), `assess run/watch/pause/resume`, and a single-tenant lock so
  an SE cannot cross customers.
- Local `tc-` bridge-key store, one per app; keys are shown once and never printed in full.

### Read results
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
  passes. `doctor --api-compat` watches for API drift. One tenant per machine, by design.
