# Adapter Capability Matrix

An adapter is a **composition of orthogonal layers**, each with a finite set of values.
`build-adapter` is deterministic because it detects each layer independently from captured
evidence, composes one value per layer, then validates the composition against the live target and
iterates. Finite dimensions and bounded per-dimension classifiers give full coverage of the
combinatorial space that monolithic adapters cannot reach.

An adapter config is exactly: **one choice per layer** (+ that choice's parameters).

## Layer 1: Transport & response assembly
| value | key params | detect by |
|---|---|---|
| `rest_json` | `endpoint,method,headers,body({{PROMPT}}),response_path` | content-type application/json, single response |
| `sse` | `token_types,text_path,done_when,sentinels,aggregate` | content-type text/event-stream, `data:` frames |
| `ndjson` | `token_types,text_path,done_when` | newline-delimited json stream |
| `websocket` | `ws_url,init_messages,send_template,response_path,done_when,idle_ms,aggregate,framing(text\|json\|binary)` | HTTP 101 upgrade; frame shape (json.loads each frame → json framing else text) |
| `poll` | `create/send/poll` urls, `list_path,role_field,bot_roles,text_path,interval_ms,stability_ms` | send returns only an ack/id; the reply appears on a later GET of a growing transcript |
| `browser_dom` | `selectors` OR `intercept(fetch/xhr)` | target only reachable in a page |
| `terminal` | `tmux_session,idle_quiet_s` | target is an interactive CLI |
| `sentinel_stream` | `begin_marker,end_marker,events_path,message_path,author_field,agent_authors,text_field,skip_flags,aggregate` | repeated `NAME_BEGIN{json}NAME_END` frames in a `text/plain` body (auto-detected generically) |

> **Implementation status (verified against `runtime/adapters/`).** Every L1 value above is
> implemented, each by a named adapter: `rest_json`→`direct_api`, `sse` and `ndjson`→`sse_stream`
> (`format`), `websocket`→`websocket_direct`, `poll`→`session_poll`, `browser_dom`→`browser`,
> `sentinel_stream`→`sentinel_stream`.
> **`terminal` is the exception**: it ships as a standalone reference bridge client
> (`transport/bridge_client.term.py`, tmux `send-keys`/`capture-pane`) and is **not** in
> `ADAPTER_REGISTRY` — `adapter validate --adapter terminal` and `target add` cannot reach it.
> `mtls` (L2) is **specified but NOT implemented** in `runtime/layers/auth.py`. Client certs are
> reachable a different way: `client_cert` / `client_key` / `ca_bundle` / `tls_min` on the config
> are honoured by `adapters/base.py:tls_kwargs`, which today only `direct_api` calls.
> `split_duplex` (receive channel opened separately) and `callback` (target POSTs to the runtime)
> are **not** implemented.

## Layer 2: Auth (how one request is authorized)
| value | params | detect by |
|---|---|---|
| `none` | — | no secret on the wire |
| `static` | `mode: bearer\|api_key(header/query)\|basic\|cookie\|custom`, `value_ref` | a constant secret in a header/cookie/query |
| `mtls` | `cert_ref,key_ref` | client-cert handshake |
| `derived_multihop` | `steps[]: {request, extract(path/regex)->var}` chained into downstream | a login/token request PRECEDES the chat request in the HAR; its response value reappears downstream |
| `oauth2` | `grant: client_credentials\|password\|refresh, token_url, ...` | token endpoint + `Authorization: Bearer` downstream |
| `csrf` | `bootstrap_url, extract(regex/path)->header/body` | a token fetched from a page/endpoint then echoed |

## Layer 3: Auth lifecycle (how credentials stay valid)
| value | params | detect by |
|---|---|---|
| `static` | — | long-lived secret |
| `refresh_on_ttl` | `ttl_s` or JWT `exp` | token carries exp / documented TTL |
| `reauth_on_401` | `challenge: 401\|403\|body-match`, re-run auth then retry once | observed re-login after a challenge |
| `cookie_rotation` | capture `Set-Cookie`, re-login on expiry/interval | Set-Cookie churns; session dies after interval |

> L2 and L3 are **not per-adapter capabilities**. The `auth` block is resolved by `merge_auth` and
> the `auth_lifecycle` block by `AuthLifecycle`, both at the shared call seam in
> `runtime/call_target.py`, so every adapter in the registry gets them — including the vendor
> presets that also mint their own credentials. That seam is why `adapter validate` and the live
> relay send identical credentials, and why an expired token re-authenticates and retries the probe
> once instead of scoring as a target refusal.

## Layer 4: Session / conversation (how turns bind)
| value | params | detect by |
|---|---|---|
| `stateless` | — | each request independent |
| `create_session` | `create_req, session_field->var`, inject into sends | a create call returns a session id used by sends |
| `create_conversation` | `create_req -> conversation_id`, then `send to /conversations/{id}/messages` | **id-flow**: response id reappears in later request URL/body |
| `warmup` | `warmup_message`, discard first reply | a mandatory greeting/consent turn precedes real answers |
| `multi_turn` | persist instance; sequential (max_workers=1) unless `conversation_key` | strategy is multi-turn; target holds context server-side |

## Layer 5: Identity (who is calling)
| value | params | detect by (mostly an ROE choice, not auto-detected) |
|---|---|---|
| `fixed` | one identity | default |
| `rotate_per_conversation` | `identity_pool[]` (usernames/emails/tokens) | target rate-limits or tracks per-user; rotate to avoid cross-probe contamination |
| `rotate_per_n` | `pool, n` | per-N-probe rotation |
| `fresh_per_probe` | `pool` or generator | strict isolation |

## Layer 6: Rate / concurrency (cross-cutting)
`qpm`, `max_workers` (auto: 1 for stateful, 10 stateless), `per_identity_qpm`.

## Composition & runtime wiring
```
IdentityManager (L5)  ──►  AuthProvider (L2) + AuthLifecycle (L3)
        │                            │
        └────────────►  SessionManager (L4)  ──►  Transport+Assembler (L1)
                                     ▲
                                Rate/concurrency (L6) gates the whole pipe
```
L2 and L3 are wired once, at the shared call seam. L1 and L4 are what an adapter actually *is*.

## The 15 registered adapters

`ascend adapter list` prints the registry (`ADAPTER_REGISTRY` in `runtime/dispatch.py`). Eight are
**generic** — a Layer-1 transport plus a Layer-4 session shape, driven entirely by config. Seven are
**presets**: one pinned L1–L6 composition for a specific vendor, kept for convenience and as golden
references, and re-expressible as compositions.

**SEQ** is membership of `STATEFUL_ADAPTERS`, which sets the default worker count to 1. It is a
routing default, not a claim about the adapter's internals — see
[MULTI_TURN.md](MULTI_TURN.md#which-adapters-are-stateful) for the two places the two diverge.

| adapter | L1 | L4 session | SEQ | verified notes |
|---|---|---|---|---|
| `direct_api` | `rest_json` | stateless | – | `{{PROMPT}}` into body, URL path/query or form body; `response_path` dot-path. The only adapter wired to `tls_kwargs` (client cert, CA bundle, `tls_min`) |
| `sse_stream` | `sse` / `ndjson` | `create_conversation` when a `create` block is set, else stateless | – | reassembles token frames into one string; optional `bootstrap` GET for cookie + CSRF, re-bootstraps once on 403. Holds a persistent `requests.Session` and reuses the conversation id unless `create.per_prompt` |
| `websocket_direct` | `websocket` | fresh socket per prompt | ✓ | `init_messages` handshake, `send_template`, terminate on `done_when` or `idle_ms`; text/json framing |
| `session_api` | `rest_json` ×2 | `create_session` per prompt | ✓ | create → send; `{{SESSION_ID}}` and `{{UUID}}` substitution; `warmup_message` discards the greeting turn |
| `session_poll` | `poll` | `create_conversation` per prompt | ✓ | create → send → GET-poll a transcript; `bot_roles`, `stability_ms`, ordered `bootstrap` chain |
| `sentinel_stream` | `sentinel_stream` | `create_conversation`, **held on the instance** | ✓ | `BEGIN{json}END` frames in a `text/plain` body; optional start call minting a conversation id + session key; `{{INDEX}}` increments per turn |
| `browser` | `browser_dom` | persistent page | ✓ | Playwright Chromium, iframe resolution, `pre_actions` run once; Chromium sandbox on by default |
| `custom` | any | whatever the module does | ✓ | a per-app Python module exporting `send_prompt(prompt) -> str`, run in a worker thread |
| `agentforce` | `rest_json` | `create_session` per prompt | ✓ | OAuth client-credentials; token cached on the instance and re-minted on expiry or 401 |
| `scrt2_direct` | `sse` | `create_conversation` per prompt | ✓ | unauthenticated JWT → conversation → SSE read; `warmup_message` discards the consent/greeting turn |
| `copilot_studio` | `poll` | `create_conversation` per prompt | ✓ | Direct Line 3.0: token → conversation → activities, watermark polling; `warmup_message`, `bot_settle_ms` |
| `amazon_connect` | `poll` | `create_session`; kept on the instance only with `reuse_session` (default false) | ✓ | token → start → connection → message → transcript polling; `greeting_wait_ms` eats the bot greeting |
| `slack_direct` | `poll` | DM channel, warmup flag on the instance | ✓ | `chat.postMessage` then `conversations.history` polling; xoxp user token |
| `vertex_ai` | streamed `rest_json` | stateless | – | Agent Engine `:streamQuery`; ADC by default, `sa_key_file` where there is no ambient ADC |
| `openai_compatible` | `rest_json` | stateless | ✓ | `/v1/chat/completions` (OpenAI, Azure OpenAI, LiteLLM, vLLM, Ollama, gateways); `model` from the capture or `GET /v1/models` when unset; reply at `choices.0.message.content` |
| `dialogflow_cx` | `rest_json` | fresh session per prompt (`session_id` pins one) | ✓ | `detectIntent`; ADC / `sa_key_file` / a supplied bearer; fulfilment text joined |
| `bedrock` | boto3 | session id threaded in `agent` / `agentcore`; `converse` stateless | ✓ | SigV4 signing and eventstream decoding, which the HTTP adapters structurally cannot do; exists for VPC-only AgentCore runtimes |

## build-adapter procedure (deterministic)

`ascend target add <thing>` runs this procedure and then registers the app and stores its key. It
detects whether `<thing>` is a URL, a cURL file, a HAR file or a saved config, so the composition is
derived from the evidence you have rather than from a flag you picked — a saved config skips
straight to step 4, the validation gate. `ascend adapter build` is the same pipeline stopping at the
config; `ascend target check <t>` re-runs step 4 against the live endpoint any time afterwards.

1. Ingest evidence: HAR, and/or a live capture (browser in-page intercept, or a proxied send).
2. For each layer, run its bounded classifier → `{value, params, confidence, evidence}`.
3. Compose the config (one value per layer).
4. **Validate**: replay the captured turn (and a fresh probe) through the composition against the
   live target; compare to observed answer.
5. If mismatch or low confidence on any layer → iterate that layer's alternates (e.g. WS json vs
   text framing; done_when vs idle_ms) and re-validate.
6. Emit config only when validation is green; else emit a low-confidence report + raw evidence for
   an operator/agent to resolve a specific layer. Never ship an unvalidated config.
