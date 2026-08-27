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
| `poll` | `submit,poll,watermark_field,stability_ms` | submit returns id/ticket; separate GET returns growing transcript |
| `browser_dom` | `selectors` OR `intercept(fetch/xhr)` | target only reachable in a page |
| `terminal` | `tmux_session,idle_quiet_s` | target is an interactive CLI |
| `sentinel_stream` | `begin_marker,end_marker,events_path,message_path,author_field,agent_authors,text_field,skip_flags,aggregate` | repeated `NAME_BEGIN{json}NAME_END` frames in a `text/plain` body (auto-detected generically) |
| `poll` *(implemented)* | `create/send/poll` urls, `list_path,role_field,bot_roles,text_path,interval_ms,stability_ms` | send returns only an ack; the reply appears on a later GET of a transcript/messages endpoint |

> **Implementation status (verified).** `rest_json`, `sse`, `ndjson`,
> `websocket`, `browser_dom`, `terminal`, `sentinel_stream` and `poll` are implemented.
> `mtls` (L2) is **specified but NOT implemented** in `runtime/layers/auth.py`. Do not
> assume it works. `split_duplex` (receive channel opened separately) and `callback`
> (target POSTs to the runtime) are **not** implemented.

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
Existing transports (rest_json, sse, websocket, poll, browser_dom, terminal) are **Layer-1**
implementations; the legacy monolithic adapters (agentforce, copilot_studio, scrt2_direct,
session_api, amazon_connect, slack_direct, vertex_ai) are **presets**: a pinned composition of
L1–L6, kept for convenience and as golden references, and re-expressible as compositions.

## build-adapter procedure (deterministic)
1. Ingest evidence: HAR, and/or a live capture (browser in-page intercept, or a proxied send).
2. For each layer, run its bounded classifier → `{value, params, confidence, evidence}`.
3. Compose the config (one value per layer).
4. **Validate**: replay the captured turn (and a fresh probe) through the composition against the
   live target; compare to observed answer.
5. If mismatch or low confidence on any layer → iterate that layer's alternates (e.g. WS json vs
   text framing; done_when vs idle_ms) and re-validate.
6. Emit config only when validation is green; else emit a low-confidence report + raw evidence for
   an operator/agent to resolve a specific layer. Never ship an unvalidated config.
