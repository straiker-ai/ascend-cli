# Adapter authoring

An **adapter** turns Ascend's prompt-and-answer contract into the protocol a specific target
speaks: REST, SSE, WebSocket, a multi-step session API, a browser, or a platform bot. This
reference covers the `BotAdapter` contract, the config schema for each of the 11 shipped
adapters, and how to add your own.

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
- **Stay under the bridge's 30s ceiling.** Most adapters default `timeout_ms` to 26000. If the
  target can exceed it, return the text collected *so far* with `truncated: true` metadata rather
  than failing. Ascend can score partial evidence. It cannot score `[ERROR] Timeout`.
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

### `direct_api` — stateless REST *(not stateful)*
Single POST, extract the answer by dot-path.
| Key | Default | Meaning |
|---|---|---|
| `endpoint` | *(required)* | Full URL to call |
| `method` | `POST` | HTTP method |
| `headers` | `{}` | Extra headers (e.g. `Authorization`) |
| `body` | `{}` | Body template; `{{PROMPT}}` is substituted |
| `response_path` | `response` | Dot-path to the answer, e.g. `choices.0.message.content` |
| `timeout_ms` | `30000` | Request timeout |

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
| `headers` / `timeout_ms` | `{}` / `30000` | Shared headers / timeout |

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
| `timeout_ms` | `26000` | Overall budget; on timeout returns partial text with `truncated: true` |
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
| `timeout_ms` | `30000` | Hard timeout (keep < 30s bridge ceiling) |
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

### `agentforce` — Salesforce Agentforce authenticated Agent API *(not stateful)*
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
| `timeout_ms` | `60000` | Request timeout |

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
4. Add a `configs/<name>.json` example and confirm `ascend adapter list` shows the new type.
5. Run it: `ascend bridge start --adapter my_adapter --config <name>`.

No change to `call_target.py`, `lease_client.py`, or the CLI is needed. The registry is the only
wiring point.
