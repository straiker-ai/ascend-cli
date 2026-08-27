# Discovery pipeline: `capture → classify → compose → validate → iterate`

> Internals of how `ascend adapter build` derives an adapter. For the user-facing guide (sources,
> auth flags, the browser fallback) see [BUILD_ADAPTER.md](BUILD_ADAPTER.md).


Building an adapter for a new target detects one value per orthogonal layer from
captured evidence, composes those values into a runnable config, and proves that
config against the live target before it ships. This is the deterministic
`build-adapter` procedure from [`CAPABILITY_MATRIX.md`](CAPABILITY_MATRIX.md),
implemented in `runtime/discovery/` and `runtime/layers/`.

```
   evidence (HAR / captured pairs)
            │
            ▼
   load_har() ─────────────► normalized evidence  {pairs, ws_messages}
            │
            ▼
   classify_evidence() ────► per-layer {value, params, confidence, evidence}
            │                         │
            │                         ▼
            │                 compose() ──► runnable adapter config (env-ref secrets)
            ▼
   validate_config()  ◄── HARD GATE: replay ONE prompt against the LIVE target
            │                 ok=True  ⇒ config is usable
            │                 ok=False ⇒
            ▼
   iterate(alternates) ───► first variant that validates, else low-confidence report
```

The classification half is **pure** (no network, no clocks that change the
answer) so it is fully unit-testable over evidence dicts. Only `validate_config`
and `iterate` touch the live target, and only when called.

---

## 1. `discover`: gather evidence

Evidence is either a **HAR export** (browser DevTools → Save all as HAR) or a
list of captured request/response **pairs**. Normalized form:

```python
{
  "pairs": [
    {"request":  {"method","url","headers","query","json","raw_body"},
     "response": {"status","headers","json","raw_body","content_type"},
     "started_ms": 1723716000000.0},
    ...
  ],
  "ws_messages": [ {"url","type","data"}, ... ]   # WebSocket frames, if any
}
```

`load_har(path)` parses a HAR file into this shape. `classify_evidence` also
accepts a raw HAR dict or a bare list of pairs and normalizes internally, so any
of these work:

```python
from discovery import load_har, classify_evidence
report = classify_evidence(load_har("captures/target.har"))
report = classify_evidence({"pairs": [...]})
report = classify_evidence([ {"request": {...}, "response": {...}} ])
```

---

## 2. `classify`: one bounded classifier per layer

`classify_evidence` first picks the **chat pair** (the request that carries the
scored prompt/answer: non-asset, prompt-like body, chat-ish response), then runs
six independent classifiers. Each returns
`{value, params, confidence (0–1), evidence}`.

| Layer | Detects | Example values |
|---|---|---|
| **transport** (L1) | response content-type & shape | `rest_json` (application/json), `sse` (text/event-stream), `ndjson`, `websocket` (HTTP 101 / captured frames), `poll` (submit→id then a separate GET) |
| **auth** (L2) | which header/cookie/query carries a secret; whether a login/token call *precedes* the chat request and its value **reappears** downstream | `none`, `static` (bearer / api_key header·query / basic / cookie), `oauth2` (token endpoint + reused `access_token`), `csrf` (token fetched then echoed), `derived_multihop` (login value chained in) |
| **auth_lifecycle** (L3) | `401/403 → retry` patterns, JWT `exp`, `Set-Cookie` churn | `static`, `refresh_on_ttl`, `reauth_on_401`, `cookie_rotation` |
| **session** (L4) | **id-flow**: a response id reappearing in a later request URL/body; a mandatory greeting | `stateless`, `create_session`, `create_conversation`, `warmup`, `multi_turn` |
| **identity** (L5) | mostly an ROE choice; per-user rate-limit / 429 hints | `fixed` (+ a rotation hint when rate-limit signals appear) |
| **rate** (L6) | observed request spacing (HAR timestamps) → `qpm`; concurrency from the session verdict | `qpm`, `max_workers` (1 stateful / 10 stateless) |

Secrets seen in evidence are **never** copied into a classifier's `params`. The
auth params instead carry an `env:` `value_ref` placeholder (e.g.
`env:DISCOVERED_TOKEN`) and record only the header *name*.

---

## 3. `compose`: pick the closest adapter + its knobs

`compose(classified)` maps the detected transport to the closest of the 11
existing adapters and fills in its known config keys:

| Detected transport / session | Adapter emitted |
|---|---|
| `rest_json` | `direct_api` |
| `rest_json` **+** `create_session`/`create_conversation` (id-flow) | `session_api` |
| `sse` | `sse_stream` (`stream.format=sse`) |
| `ndjson` | `sse_stream` (`stream.format=ndjson`) |
| `websocket` | `websocket_direct` |
| `poll` | `session_api` (submit + fetch approximation; verify polling) |

**Platform host hints override the transport pick** (these are integration
*types*): a `salesforce-scrt` host → `scrt2_direct`,
`einstein/ai-agent` → `agentforce`, `directline`/`powerplatform` →
`copilot_studio`, `slack.com` → `slack_direct`, `reasoningEngines`/`:streamQuery`
→ `vertex_ai`, `connectparticipant` → `amazon_connect`.

The composed config also carries the layer blocks used by `runtime/layers/`:

```jsonc
{
  "adapter": "direct_api",
  "endpoint": "...", "method": "POST", "body": {...}, "response_path": "...",
  "auth":            { "type": "static", "mode": "bearer", "value_ref": "env:DISCOVERED_TOKEN" },
  "auth_lifecycle":  { "type": "refresh_on_ttl", "ttl_s": 3600 },
  "identity":        { "mode": "fixed" },
  "qpm": 30, "max_workers": 10,
  "_discovery": { "transport": {"value":"rest_json","confidence":0.85}, ... }
}
```

`classify_evidence` returns the whole report:

```python
{
  "layers": { <name>: {value, params, confidence, evidence} },
  "config": { ...composed config... },
  "overall_confidence": 0.5,        # the weakest layer's confidence
  "unresolved": ["auth_lifecycle"], # layers below the 0.5 floor or with no value
  "chat_pair_index": 2,
}
```

---

## 4. `validate`: the hard gate

A composed config is **not usable** until it has produced a clean answer from the
live target. `validate_config` resolves the `auth` block from the environment
(via `layers.auth.AuthProvider`), merges the headers/cookies into a *copy* of the
config (the secret is never written to disk), runs **one** prompt through the
adapter, and reports:

```python
from discovery import validate_config
v = validate_config("direct_api", cfg, "sample prompt",
                    expected_substr="echo:")     # optional content assertion
# -> {"ok": bool, "response": str, "error": str|None, "matched": bool, "adapter": str}
```

`ok` is True **only** when the adapter reported success *and* non-empty text came
back (and, when `expected_substr` is given, it matched). Ship a config only when
`ok=True`.

---

## 5. `iterate`: resolve a low-confidence layer

When a layer is low-confidence, the exact knob is often one of a small, known set
(WebSocket `json` vs `text` framing; `done_when` vs `idle_ms`; an `sse` vs
`ndjson` stream format). `iterate` validates the base config, then each alternate
override in turn, and returns the first that passes:

```python
from discovery import iterate
result = iterate(
    "websocket_direct", cfg,
    alternates=[{"framing": "json"}, {"framing": "text"}],
    sample_prompt="hello",
    evidence=evidence,           # echoed back if every variant fails
)
# success -> {"ok": True, "config": <winning>, "attempt": 1, "validation": {...}, "tried": [...]}
# failure -> {"ok": False, "tried": [...], "evidence": ..., "confidence": "low", "message": ...}
```

Each alternate is deep-merged onto the base config, so an override only needs to
name the field(s) it changes. On total failure `iterate` hands back the raw
evidence and a `low` confidence marker so an operator or agent can resolve the one
flagged layer by hand. Never ship an unvalidated config.

---

## The layers themselves (`runtime/layers/`)

`compose` emits the config; these classes consume it at runtime.

- **`layers.identity.IdentityManager`** (L5): pure, deterministic selection of
  the identity vars for a conversation key / probe index. Modes: `fixed`,
  `rotate_per_conversation` (stable hash into the pool), `rotate_per_n`
  (`pool[(index // n) % len]`), `fresh_per_probe` (pool-indexed or generated from
  a `{{N}}` template). No network, no clock.
- **`layers.auth.AuthProvider`** (L2): turns the `auth` block into
  `AuthMaterial` (headers / cookies / params / body-vars). `none` and `static`
  need no network; `oauth2` / `csrf` / `derived_multihop` make timed HTTP calls
  **only** inside `.materialize()`. Every secret is an `env:` reference. An
  inline literal is refused by `resolve_secret_ref`.
- **`layers.auth.AuthLifecycle`** (L3): pure decisions about *when* to refresh:
  `static`, `refresh_on_ttl` (fixed TTL or JWT `exp`), `reauth_on_401`
  (`should_reauth(status)`), `cookie_rotation` (`note_response` + interval).

---

## Layer composition and preset adapters

Finite layers × a bounded classifier per layer = coverage of the whole
combinatorial space. A new target that is "SSE transport + oauth2 + per-N
identity rotation" needs no new adapter class. It is one value per layer,
composed and validated. The monolithic preset adapters (`agentforce`,
`copilot_studio`, `scrt2_direct`, `session_api`, `amazon_connect`,
`slack_direct`, `vertex_ai`) remain as pinned compositions and golden references,
and `compose` still prefers them when a platform host hint fires.


## Live capture: `ascend adapter build --url`

```
ascend adapter build --url https://site.example/support \
  --save-evidence /tmp/ev.json --out configs/mybot.json --settle 8
```

Drives a real Chromium via Playwright, intercepts every request/response **and WebSocket
frame**, opens the chat widget, sends one benign prompt, then runs the same layer
classifiers used for HAR input. A real browser is used deliberately:

* bot protection (Cloudflare/Akamai) rejects plain HTTP clients but accepts a real browser;
* a HAR export **loses WebSocket frames** and redacts auth headers;
* the page authenticates itself, so cookies/SSO/CSRF are already present.

### Accuracy rules

1. **The typed prompt is ground truth.** During a live capture the typed prompt is known, so
   the chat call is the request whose body *contains that prompt*. This is checked first and
   overrides every scoring heuristic.
2. **A WebSocket is only the transport if it carried the conversation.** Pages routinely open
   analytics/personalization sockets; a socket with no frames, or one that never carried the
   prompt, is ignored. (Without this rule a marketing vendor's socket wins at 0.9 confidence.)
3. **Low confidence is reported.** Unresolved layers are listed explicitly and the
   config is not marked usable until `ascend adapter validate` passes against the live target.

### Known limits
* SPA timing, shadow DOM and cross-origin iframes can hide the input. The capture still records
  the page bootstrap, and the evidence JSON can be classified manually.
* Multi-step flows may need you to drive the widget yourself while the capture records.


## Running without a browser

**The browser is only ever used for DISCOVERY, and discovery is optional.** Running an
assessment, which touches the customer's target in production, is pure HTTP:
`ascend bridge start` never launches a browser, never records a screen, and has no
Playwright dependency in its path. If you already know the contract, you never need a
browser at all.

Four ways to obtain a contract, in order of least customer friction:

| Path | Browser needed? | When to use |
|---|---|---|
| **`--har <file>`** | No (customer uses their own browser) | Customer exports a HAR from their normal DevTools session and sends it. Nothing runs on their machine. Note a HAR loses WebSocket frames. |
| **Hand-written config** | No | The contract is already documented (vendor API docs, an internal spec). Write the config and go straight to `ascend adapter validate`. |
| **`--manual`** | Yes, but a human drives | The tool opens the page and records; *you* click and type. No automation touches the widget. Useful when automation can't reach it, or when policy forbids automated interaction. |
| **`--url` (automated)** | Yes | Fastest. The automation opens the widget and sends one benign prompt. |

Chromium install: `pip install playwright && playwright install chromium` (~150MB, local
only). If Playwright is absent, `--url`/`--manual` fail with a clear message and every
other path still works.

### Capture is verified

A capture only counts if the typed prompt **appears in real traffic** (a request body or
a WebSocket frame). Typing into a box proves nothing. A site search field accepts text
too. When verification fails, discover **writes nothing and exits non-zero**:

```
[capture] prompt sent .... YES
[capture] seen in traffic  NO
error: capture did not deliver the prompt to the target, so no contract can be derived.
  Nothing was written: an unverified capture cannot produce a real config.
```

The alternative, emitting a plausible-looking config built from page bootstrap
traffic, produces a confidently wrong answer. Measured on a live hunt across 20
public sites, the naive version "succeeded" on sites where it had actually typed
into a search box and captured nothing.

### Picking the right input

Candidate inputs are **scored**: `textarea`/`contenteditable`/`role=textbox`
score up; chat-ish `placeholder`/`aria-label`/`id` score up; anything matching
search/zip/email/login scores **down** and is never used; inputs inside a chat-vendor iframe
score up. The tool then presses Enter and, if that does not submit, clicks a nearby send button.
