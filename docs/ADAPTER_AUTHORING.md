# Adapter authoring

An **adapter** turns Ascend's prompt-and-answer contract into the protocol a specific target
speaks: REST, SSE, WebSocket, a multi-step session API, a browser, or a platform bot. This
reference covers the `BotAdapter` contract, the config schema for each of the 15 shipped
adapters, and how to add your own. `ascend adapter list` prints the authoritative set:

```
agentforce  amazon_connect  bedrock  browser  copilot_studio  custom  direct_api  scrt2_direct
sentinel_stream  session_api  session_poll  slack_direct  sse_stream  vertex_ai  websocket_direct
```

Picking one is normally not your job: `ascend target add <url | file | config>` derives the
adapter, proves it against the live target and registers it. Read on when you are writing an
adapter, or reading a config the CLI produced.

The deterministic composable-layer model that decides which adapter and config a target needs
is documented in `docs/CAPABILITY_MATRIX.md`.

---

## The `BotAdapter` contract

Every adapter subclasses `runtime/adapters/base.py::BotAdapter` and implements one async method:

```python
class BotAdapter(ABC):
    async def send_prompt(self, prompt: str, config: dict) -> dict:
        """
        Returns:
          {
            "response":    str,        # the bot's text answer
            "success":     bool,
            "error":       str | None,
            "duration_ms": int,
            "metadata":    dict        # adapter-specific extras
          }
        """
```

Two helpers on the base class build that dict for you. Always return through them:

```python
start = time.time()
...
return self._ok(answer_text, start, adapter="my_adapter", any="metadata")
# or, on failure:
return self._fail("what went wrong", start, status_code=502)
```

Rules for adapters:

- **Never raise** for an expected failure (bad HTTP, timeout, missing field). Return `_fail(...)`.
  The dispatcher turns a raised exception into a generic error, while `_fail` lets you attach an
  accurate `status_code` and message that Ascend can score.
- **Derive your timeout; don't invent one.** Call `resolve_timeout_s(config)` from
  `runtime/adapters/base.py`. There is one real number here — the per-probe window the platform
  enforces (`PLATFORM_PROBE_WINDOW_S`, 120s, overridable with `$ASCEND_PLATFORM_PROBE_WINDOW_MS`) —
  and the bridge's give-up point and the adapter's own timeout are both derived from it, because
  three knobs for one quantity is three ways to set them inconsistently. A config's `timeout_ms`
  still wins where it is set, but is **clamped** to the bridge give-up point: waiting past it cannot
  help, since the router has already abandoned the probe and the extra time only holds a worker and
  a socket open. If the target can exceed the budget, return the text collected *so far* with
  `truncated: true` metadata rather than failing. Ascend can score partial evidence. It cannot score
  `[ERROR] Timeout`.
- **Substitute `{{PROMPT}}` safely.** When injecting the prompt into a JSON template, use
  `_json_escape(prompt)` (exported from `websocket_direct`) so quotes/newlines don't break the JSON.
- **Import heavy deps lazily** inside `send_prompt` (e.g. `websockets`, `playwright`) so the
  module imports without them installed.

### Where the prompt and response cross the boundary

The dispatcher (`runtime/dispatch.py`) pulls the prompt out of the leased probe body and shapes
your result back for Ascend:

- `extract_prompt(body, config)` finds the prompt: `config["prompt_field"]` if set, else the first
  of `prompt / message / input / text / query / content / question`, else the deepest lone string.
- `shape_result(result, config)` always surfaces the answer under `response`, mirrors it under
  `config["response_field"]` if different, attaches `_meta`, and on failure returns an accurate
  status code (never drops the probe).

---

## Composable layers

An adapter *type* is a bundle of orthogonal choices: transport, auth, auth-lifecycle,
session, identity, rate. Two adapters that share a transport differ only in the other layers. This
is why configs look similar across adapters and why `build-adapter` can be deterministic. The
six-layer table lives in `docs/CAPABILITY_MATRIX.md`; keep new adapters aligned to it so
they compose with the rest of the toolkit.

---

## Config schema by adapter

Configs live at `configs/<name>.json`. A config may set `"adapter": "<type>"` so `bridge start`
can infer the type. Optional cross-adapter keys read by the dispatcher/runtime:
`prompt_field`, `response_field`, `conversation_key`, `max_workers`.

**Which `configs/`.** New configs are written to one directory — `$ASCEND_CONFIG_DIR` if set, else
`./configs`, else `~/.ascend/configs`. Lookup searches per *file* across all of those plus the
bundled examples, in that same precedence order, so a config written from one directory resolves
from every other. Lookup used to pick the first directory that *existed* and search only inside it;
since every checkout ships a `configs/` of examples, running from a checkout hid `~/.ascend/configs`
completely and a config written elsewhere came back as "config not found". It read as a bridge
problem rather than a lookup one, because the relay exits before it ever leases and a relay that
never starts is indistinguishable from one that dropped — while the app's key kept resolving, since
keys live in `~/.ascend` and never depended on the working directory. `ascend adapter configs` lists
every config that is actually resolvable and names the directory writes land in.

Where a `timeout_ms` default is shown as *derived* below, the adapter calls `resolve_timeout_s`:
with no `timeout_ms` the value comes from the platform's per-probe window, and an explicit
`timeout_ms` is honoured but clamped to the bridge's give-up point.

### `direct_api` — stateless REST *(not stateful)*
Single POST, extract the answer by dot-path.
| Key | Default | Meaning |
|---|---|---|
| `endpoint` | *(required)* | Full URL to call |
| `method` | `POST` | HTTP method |
| `headers` | `{}` | Extra headers (e.g. `Authorization`) |
| `body` | `{}` | Body template; `{{PROMPT}}` is substituted |
| `response_path` | `response` | Dot-path to the answer, e.g. `choices.0.message.content` (syntax below) |
| `timeout_ms` | *derived* | Request timeout |

**`response_path` syntax.** Segments are separated by `.`; a numeric segment indexes a list.
Two more segments exist because real replies are not always one string at one place:

| segment | meaning | example |
|---|---|---|
| `*` | every element of a list, **joined** — for a reply split across blocks | `content.*.text` → `"How can" + " I help?"` |
| `~json` | the value at this segment is a JSON document encoded as a **string**; decode it and keep walking — for envelopes | `envelope~json.result.reply` |

`target add` derives both automatically. A reply that is itself JSON used to derive as
`response_path: envelope`, validate green on the encoded blob, and score every probe against the
encoding rather than the reply inside it.

### `session_api` — two-step session then message *(stateful)*
| Key | Default | Meaning |
|---|---|---|
| `session_endpoint` | *(required)* | POST to create a session; `{{UUID}}` auto-filled |
| `session_body` | `{}` | Session-creation body |
| `session_extract` | `sessionId` | Dot-path to the session id in the session response |
| `session_variable` | `SESSION_ID` | Name substituted into the message endpoint/body |
| `message_endpoint` | *(required)* | Message URL; `{{SESSION_ID}}` substituted |
| `message_body` | `{}` | Body with `{{PROMPT}}` and `{{SESSION_ID}}` |
| `response_path` | `messages.0.message` | Dot-path to the answer |
| `session_greeting` | — | Optional first turn sent after create and before the prompt. Some widgets refuse any question until greeted (`409 … first turn must be a greeting`); `target add` records this when it hits that gate |
| `headers` / `timeout_ms` | `{}` / *derived* | Shared headers / timeout |

### `sse_stream` — reassemble a streamed answer *(not stateful)*
For `text/event-stream` or NDJSON targets that emit one frame per token. Reassembles the stream
into one string.
| Key | Default | Meaning |
|---|---|---|
| `base_url` | *(required)* | `scheme://host:port` of the target |
| `chat_path` | *(required)* | Streaming endpoint path |
| `method` | `POST` | Chat method |
| `request_template` | `{"message":"{{PROMPT}}"}` | Body; `{{PROMPT}}` substituted |
| `headers` | `{}` | Merged onto every request (keep UA/Accept-* stable if the target fingerprints sessions) |
| `bootstrap` | — | `{url, csrf_regex, csrf_header, refresh_on_403, post_actions[]}` for session priming/CSRF/setup |
| `stream` | see below | Wire-format description |
| `timeout_ms` | *derived* | Overall budget; on timeout returns partial text with `truncated: true` |
| `verify_tls` | `true` | Set `false` for self-signed |

`stream`: `format` (`sse`/`ndjson`), `type_path` (`type`), `token_types`
(`token`/`delta`/`content_block_delta`), `text_path` (`content`), `ignore_types`
(`status`/`ping`/`keepalive`), `done_when` (`{"path":"type","equals":"done"}`), `aggregate`
(`concat`/`last`), `idle_ms` (`20000`).

### `websocket_direct` — handshake / envelope / streamed WS *(stateful)*
Use when a WS needs a pre-prompt handshake, an envelope, terminal-frame detection, or stays open
(so "collect until close" would hang). See the two worked examples below.
| Key | Default | Meaning |
|---|---|---|
| `ws_url` | *(required)* | `wss://…` endpoint |
| `headers` | `{}` | Handshake headers (Authorization, Cookie, Origin) |
| `subprotocols` | — | WS subprotocols to negotiate |
| `init_messages` | `[]` | Frames sent right after connect (auth/subscribe); str or dict; `{{PROMPT}}` allowed |
| `send_template` | `{"type":"message","text":"{{PROMPT}}"}` | The prompt frame |
| `response_path` | — | Dot-path to answer text in a frame; omit to heuristically pull common keys |
| `done_when` | — | `{"path","equals"}` or `{"contains"}` terminal-frame signal |
| `idle_ms` | `1500` | Stop after this much silence when no `done_when` |
| `timeout_ms` | *derived* | Hard timeout |
| `aggregate` | `concat` | `concat` join chunks or `last` |

### `browser` — headless Chromium DOM driving *(stateful)*
Needs `playwright` + Chromium. Keeps one session open; runs `pre_actions` once.
| Key | Meaning |
|---|---|
| `url` | Target URL |
| `pre_actions` | Actions before interacting (click, wait, dismiss_popup, …) |
| `iframe.selector` | Chat widget iframe selector (null if none) |
| `wait_for_widget` | Selector + `timeout_ms` for the input to be ready |
| `input.selector` | Chat input field selector |
| `send.method` / `send.selector` | `click` or `enter`; send-button selector for click |
| `response` | `wait_strategy`, `container_selector`, `text_selector`, `timeout_ms`, … |

### `amazon_connect` — AWS Connect Chat *(stateful)*
| Key | Meaning |
|---|---|
| `token_endpoint` | CloudFront `/token` URL (returns JWT) |
| `start_endpoint` | Connect widget start endpoint |
| `participant_base` | Participant Service base (default us-east-1) |
| `display_name` / `attributes` / `snippet_id` | Chat name / contact attrs / snippet header |
| `reuse_session` | Reuse session across prompts (default false) |
| `greeting_wait_ms` / `poll_interval_ms` / `poll_timeout_ms` / `timeout_ms` | Timing knobs |

### `scrt2_direct` — Salesforce Agentforce public widget (SCRT2) *(stateful)*
| Key | Meaning |
|---|---|
| `scrt_base` | SCRT2 API base (`https://<org>.my.salesforce-scrt.com`) |
| `org_id` / `developer_name` | Org ID / deployment developer name |
| `widget_origin` / `url` | Widget iframe origin / main site URL (CORS origins) |
| `capabilities_ver` / `sse_timeout` / `warmup_message` | Version / SSE timeout / warm-up (recommended `"Hello"`) |

### `agentforce` — Salesforce Agentforce authenticated Agent API *(stateful)*
OAuth client-credentials; caches + re-mints the token. Fresh session per prompt.
| Key | Meaning |
|---|---|
| `instance_url` | My Domain (token endpoint + `instanceConfig.endpoint`) |
| `agent_id` | BotDefinition / Agent ID |
| `client_id` / `client_id_env`, `client_secret` / `client_secret_env` | Literal or env-var credential |
| `api_base` / `bypass_user` / `region` / `end_session` / `timeout_ms` / `token_ttl_s` | Data plane + behaviour knobs |

### `slack_direct` — Slack Web API via xoxp user token *(stateful)*
| Key | Meaning |
|---|---|
| `slack_token` | User OAuth token (`xoxp-…`) |
| `channel_id` | DM channel id with the bot (`D…`) |
| `user_id` | Your Slack user id (`U…`) to filter self-messages |
| `target_bot_id` / `timeout_ms` / `poll_interval_ms` / `warmup_message` | Bot filter / timing / greeting warm-up |

### `vertex_ai` — Vertex AI Agent Engine (ADK `:streamQuery`) *(not stateful)*
Uses Application Default Credentials (no SA key).
| Key | Default | Meaning |
|---|---|---|
| `endpoint` | *(required)* | Full `…/reasoningEngines/{ID}:streamQuery` URL |
| `user_id` | `ascend-probe` | user_id sent to the agent |
| `sa_key_file` | — | Service-account JSON key, for a host with no ambient ADC |
| `timeout_ms` | *derived* | Request timeout |

### `copilot_studio` — Microsoft Copilot Studio (Direct Line 3.0) *(stateful)*
Fresh conversation per prompt. Provide one token source.
| Key | Meaning |
|---|---|
| `directline_token_endpoint` | Copilot Studio Mobile-app token URL (No-auth agents only) |
| `directline_secret` / `directline_secret_env` | Classic Direct Line secret (or env-var name) |
| `bearer_token` / `bearer_token_env` | Pre-minted / delegated token (or env-var name) |
| `user_id` | Direct Line user id (must start `dl_`) |
| `warmup_message` / `warmup` | Greeting warm-up (default `"Hello"`; `warmup:false` disables) |
| `directline_base` / `poll_interval_ms` / `bot_settle_ms` / `locale` / `timeout_ms` | Host / timing / locale / budget |

### `session_poll` — create → send → GET-poll *(stateful)*
For the very common shape where the reply is **not** in the send response: create a conversation,
POST the message, then poll a transcript endpoint until the agent turn appears. Generalises the
hardcoded polling in `copilot_studio` / `amazon_connect` / `slack_direct`.
| Key | Meaning |
|---|---|
| `create` | `{url, method, body, headers, extract}` — `extract` is the dot-path to the conversation id |
| `send` | `{url, method, body, headers}`; `{{CONV}}` and `{{PROMPT}}` substituted |
| `poll` | `{url, method, list_path, role_field, bot_roles, text_path, interval_ms, timeout_ms, stability_ms}` |
| `bootstrap` | Ordered list of `{url, method, headers, body, required}` calls made before `create` |
| `headers` / `timeout_ms` | Shared headers merged into every call / per-HTTP-call timeout (*derived*) |

Defaults: `poll.list_path` `messages`, `role_field` `role`, `bot_roles`
`["assistant","bot","agent"]`, `text_path` `text`, `interval_ms` `1000`, `stability_ms` `0`
(return the first hit rather than waiting for the reply to stop growing). A step whose
Content-Type is `x-www-form-urlencoded` is form-encoded.

### `sentinel_stream` — marker-framed JSON in a plain-text body *(stateful)*
For platforms that stream one HTTP body framed with literal begin/end markers
(`BOT_CHAT_EVENT_BEGIN{…}BOT_CHAT_EVENT_END`), usually served as `text/plain`, so neither the SSE
nor the NDJSON reader applies.
| Key | Meaning |
|---|---|
| `url` / `method` / `headers` | Endpoint (same for start and message on most platforms), verb, headers |
| `begin_marker` / `end_marker` | Frame sentinels (default `BOT_CHAT_EVENT_BEGIN` / `BOT_CHAT_EVENT_END`) |
| `start` | Optional session bootstrap: `{body, conv_path, key_path}` |
| `message.body` | Message template; `{{PROMPT}}`, `{{CONV}}`, `{{KEY}}`, `{{INDEX}}` substituted |
| `extract` | `{events_path, message_path, author_field, agent_authors, text_field, skip_flags, aggregate}` |
| `timeout_ms` | *derived* |

### `bedrock` — AWS Bedrock via boto3 *(stateful)*
Three modes. boto3 does the two things the HTTP adapters structurally cannot: SigV4 signing and
`application/vnd.amazon.eventstream` decoding. Credentials come from the standard AWS chain, so
nothing secret lives in the config. The reason it exists is a **private / VPC-only** runtime where
the bridge is the only path in; the Console assesses cloud-reachable Bedrock natively.
| Key | Meaning |
|---|---|
| `mode` | `converse` (default) · `agent` · `agentcore` |
| `region` / `profile` | AWS region / profile name (else the standard chain) |
| `model_id` / `system` / `max_tokens` | `converse` mode: model, optional system prompt, token cap (default 1024) |
| `agent_id` / `agent_alias_id` | `agent` mode (classic Bedrock Agents) |
| `runtime_arn` / `qualifier` / `input_key` / `payload_extra` | `agentcore` mode: runtime ARN, endpoint qualifier (default `DEFAULT`), prompt key (default `prompt`), extra payload fields |
| `response_path` | Dot-path to the answer in a JSON agentcore response (best-effort otherwise) |
| `session_id` | Pin a session; otherwise threaded per conversation in `agent`/`agentcore` |

### `custom` — the app's own adapter, as code *(stateful)*
A per-app adapter written as a small Python module the bridge runs like a built-in. This is what
`adapter build --code` emits.
| Key | Meaning |
|---|---|
| `adapter_module` | The `.py` implementing `send_prompt`; a filename resolved beside the config, or an absolute path |

```python
def send_prompt(prompt: str) -> str:
    # One prompt to THIS app, one reply back. Signed requests, a multi-step handshake,
    # streaming reassembly, an async poll — anything goes here.

META = {"target": "https://…", "kind": "custom", "generated_from": "har"}   # optional, for `adapter show`
```

The module runs in a worker thread, so a blocking turn cannot stall the event loop, and — like
every adapter — it is not accepted until it has answered the live target.

---

## Two `websocket_direct` examples

### A. Chunked *text* streaming with a terminal frame
The server streams the answer as many small JSON frames and marks the end with `{"type":"end"}`:

```json
{
  "adapter": "websocket_direct",
  "ws_url": "wss://bot.example.com/stream",
  "headers": {"Origin": "https://bot.example.com"},
  "send_template": {"type": "user", "text": "{{PROMPT}}"},
  "response_path": "delta",
  "done_when": {"path": "type", "equals": "end"},
  "aggregate": "concat",
  "timeout_ms": 28000
}
```
Each `{"type":"chunk","delta":"…"}` frame contributes its `delta`; the `{"type":"end"}` frame
stops collection; the chunks are concatenated into one answer.

### B. Multi-step session (auth/subscribe) then a single JSON answer
The socket needs an auth frame and a subscribe frame before the prompt, and the answer arrives as
one complete JSON object under `data.message`:

```json
{
  "adapter": "websocket_direct",
  "ws_url": "wss://bot.example.com/ws",
  "subprotocols": ["chat.v1"],
  "init_messages": [
    {"type": "auth", "token": "…"},
    {"type": "subscribe", "channel": "assistant"}
  ],
  "send_template": {"type": "ask", "id": "1", "text": "{{PROMPT}}"},
  "response_path": "data.message",
  "idle_ms": 2000,
  "timeout_ms": 28000
}
```
`init_messages` fire in order right after connect; with no `done_when`, collection stops after a
2s idle gap. Because this needs an ordered handshake, the adapter is stateful and runs sequentially.

---

## Adding a new adapter

1. Create `runtime/adapters/my_adapter.py` with a `class MyAdapter(BotAdapter)` implementing
   async `send_prompt`. Return through `self._ok` / `self._fail`. Import heavy deps lazily.
   Document the config keys in the module docstring. That docstring is the source of truth for
   this reference.
2. Export it from `runtime/adapters/__init__.py`.
3. Register it in `runtime/dispatch.py`: add `"my_adapter": MyAdapter` to `ADAPTER_REGISTRY`, and
   add the name to `STATEFUL_ADAPTERS` if it carries per-conversation state (see `docs/MULTI_TURN.md`).
4. Add a `configs/<name>.json` example, with `"adapter": "my_adapter"` in it, and confirm
   `ascend adapter list` shows the new type.
5. Prove it: `ascend adapter validate --config <name>`. The adapter type comes from the config's
   `adapter` key; `--adapter my_adapter` overrides it.
6. Run it: `ascend target add <name>` to register a target on it, then
   `ascend bridge start --app '<target>' --config <name> --foreground` to watch one bridge serve it
   in this terminal.

No change to `call_target.py`, `lease_client.py`, or the CLI is needed. The registry is the only
wiring point.
