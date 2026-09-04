# Authenticating to a target

Every target worth assessing sits behind something. This page is the one place that says **what
your target uses → what you pass → what the written config carries → which app types can run it.**
The flags below are shared by `ascend target add`, `ascend adapter build`, `map` and `discover`
(they are defined once, so the set is identical everywhere).

## 1. Static credentials — one value, sent on every request

| your target wants | pass | the config carries |
|---|---|---|
| `Authorization: Bearer <token>` | `--bearer env:MY_TOKEN` | `{"auth": {"type":"static","mode":"bearer","value_ref":"env:MY_TOKEN"}}` |
| an API key header | `--api-key 'X-API-Key:env:MY_KEY'` | `mode: api_key, name: X-API-Key, in: header` |
| an API key in the query string | `--api-key 'key:env:MY_KEY:in=query'` | `mode: api_key, in: query` (folded into the URL per request) |
| HTTP Basic | `--basic 'user:env:MY_PW'` | `mode: basic, username_ref: literal:user, password_ref: env:MY_PW` |
| a session cookie | `--cookie 'session=env:MY_SESSION'` | `mode: cookie` |
| any other header | `--header 'X-Auth-Token: env:MY_TOKEN'` | `mode: custom` |
| a key or tenant **in the JSON body** | `--body-field apiKey=…` (repeatable) | the field, baked into the request body |

**Prefer the `env:NAME` form.** The value is read from the environment when the target is probed
and validated, and again by the bridge at run time; the config file only ever holds the reference.
A literal (`--bearer abc123`) still works — it is stored in the config, mode 0600 — and the CLI warns
when a credential-shaped header is stored that way:

```
warning: credential-shaped header(s) stored in plaintext in the config: X-API-Key
    keep secrets out of files with an env: reference, e.g.
      --header 'X-API-Key: env:MY_SECRET'   or   --api-key 'X-API-Key:env:MY_SECRET'
```

One environment-referenced credential per target. Two are refused rather than one silently dropped.

## 2. Handshakes — a login that mints something, repeated when it expires

| your target wants | pass |
|---|---|
| a token from a login POST | `--login-url https://…/login --login-body '{"user":"env:U","password":"env:P"}' --token-path access_token` |
| OAuth2 client credentials | `--login-url https://…/oauth2/token --login-body 'grant_type=client_credentials&client_id=env:CID&client_secret=env:CS' --token-path access_token` (form-encoded, as RFC 6749 wants) |
| a session cookie set by a GET | `--login-url https://…/login --login-method GET` |
| a CSRF token embedded in a page | `--login-url https://…/ --login-method GET --token-regex 'csrf-token" content="([^"]+)' --token-header X-CSRF-Token` |

The exchange runs once, up front, to prove the target answers — and the written config carries
the **repeatable recipe** (`auth` + `auth_lifecycle`), not the token it happened to mint. The
bridge re-authenticates on its own: proactively before a known TTL, and once more on a 401. Proven
live: a token with a 30 s lifetime, an 85 s run, every probe answered.

`--login-body` values written `env:NAME` become environment references in the recipe, so the login
credentials are not stored either.

## 3. Signed or single-use requests (HMAC, nonces, request signing)

These compute something per request that no flag can express. `target add` refuses them and points
at the scaffold:

```
ascend target add --scaffold ./my_adapter.py       # writes a custom adapter with send_prompt() to fill in
ascend target add --module ./my_adapter.py --name 'My Bot'
```

One shape per vendor would fit some and silently mis-sign the rest; a 40-line adapter you can read
is the honest answer. See `docs/ADAPTER_AUTHORING.md`.

## 4. SSO, Entra, SAML — a browser you are already signed into

```
chrome --remote-debugging-port=9222      # then sign in as you normally would
ascend target add --url https://portal.example.com/assistant --cdp --name 'Portal Assistant'
```

`--cdp` attaches to that browser instead of launching one, captures the conversation contract, and
the written adapter attaches the same way at run time. Your browser is never closed. This is the
only route into an identity-provider-gated target; nothing here tries to replay an SSO dance.

## 5. Transport: TLS, mTLS, proxies

`--insecure` (self-signed internal), `--ca-bundle PATH`, `--client-cert PATH --client-key PATH`
(mTLS), `--proxy URL`. All of them are carried into the config and honoured by the probe, the
validation gate and the bridge alike.

## 6. Which app types can run which auth

| app type | who calls the target | auth it can carry |
|---|---|---|
| `bridge` (default) | the bridge on your machine | **everything above** — static, handshakes, CDP, mTLS; env references resolve on your machine |
| `api` | Ascend, from its cloud | static headers and one API key **only**. `app create --type api` refuses a config with a handshake (`oauth2`/`csrf`/`derived_multihop`): the platform cannot re-authenticate |
| `gcp`, `bedrock` | Ascend, natively | the cloud provider's own credentials; nothing here applies |

If the target needs anything dynamic, it is a `bridge` app. That is what `target add` creates.

## 7. The guard in front of the first request

Before `target add` sends anything, the URL is checked: loopback and private ranges are allowed
(that is where most targets under development live); link-local and cloud-metadata hosts
(`169.254.0.0/16`, `fe80::/10`, `metadata.google.internal`) are refused unless `--allow-internal`.

## 8. What gets printed

Printed configs are redacted (`Authorization`, cookies, `X-API-Key`, `X-Auth-Token`, `Set-Cookie`,
`X-CSRF-Token`, … show as `[REDACTED]`); the 0600 file on disk is the store. `ascend adapter show
<config> --reveal` is the explicit way to see values.

## 9. Proving it

`scripts/live_auth_matrix.py` onboards a target behind each of ten authentication gates served by
`agent-forge` and asserts what `target add` derives for each — a release step (it needs a real
target), documented in `docs/CHANGE_CONTROL.md`.
