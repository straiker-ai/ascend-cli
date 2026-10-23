# Published Profile Preparation

`target prepare` exports a symbolic contract for an already-recognized profile.
It does not discover endpoints, create or update applications, authenticate a
platform account, send login/chat requests, or test/store an adapter. It reads
only the profile's bounded, known JSON GET sources at the exact selected origin.
Redirects are not followed, TLS verification stays enabled, and ambient proxy,
netrc and cross-request cookies are not used.

```sh
ascend target prepare --capabilities --json
ascend target prepare https://target.example --expected-profile doppelganger \
  --expected-origin https://target.example --workspace chosen \
  --private-output /caller-owned-private-directory/new-plan.json \
  --credential-slots '[{"origin":"https://target.example","in":"header","field":"x-demo-key","reference":"env:ACCESS"},{"origin":"https://target.example","in":"body","field":"apiKey","reference":"env:KEY"}]' --json
```

Credential arguments are references, never values. The caller supplies only the
required variables in the child process environment. All supplied references
must resolve, belong to the exact origin and profile-supported slot, and be used
in the resulting contract. Multiple references for the same value or duplicate
slots hold rather than guess. GET authentication uses only exact declared header
slots; body slots are never sent to the preparation endpoints.

The current producer supports the existing direct-HTTP published profile. Its
workspace share identifier is credential material. Private mode captures it as
an observed input and substitutes `input:profile_workspace`; no preexisting stored
workspace credential or second operator submission is required. Without a private
output path, an unbound observed identity holds with `private_output_required`.
An explicit existing workspace reference must match the observation; a conflict
never rotates a credential. Unknown credential fields that cannot be safely
symbolized hold. There is no implicit credential-store import.
Copilot Studio is not advertised: its token GET can mint a credential and its
conversation protocol has not been lowered into this read-only producer.
Adding another profile means supplying its read-only source shape, supported
credential slots and `prepare_config` hook, not adding another workflow.

## Capability and Envelope

Recognized supported `target inspect` results include:

```json
{"prepare_capability":{"version":1,"profile_version":1,"command":"target prepare"}}
```

Missing capability means unsupported/old; a consumer must hold instead of invoking
automatic `target add` discovery. `--capabilities` reads no target or credentials.
Preparation never redetects the expected profile: changed source shape or selected
workspace is a conflict, not permission to try another profile or probe.

Without private mode CLI stdout is the sanitized version-1 envelope. The existing
MCP shim wraps successful JSON under `result`; this change adds no agent-client
or MCP tool catalog entry. The successful bundle fields are `version`,
`producer_revision`, `source_kind`, `ok`,
`outcome`, `profile`, `profile_version`, `origin`, `selected_workspace`, `contract`,
`credential_slots`, `read_observations`, `facts`, and `remote_attested`.
`contract.steps` includes exact method/URL, `redirect: "manual"`, complete headers
and body; `reply` declares JSON extraction. Slots use
`{origin, in: "header" | "body", field, reference: "env:NAME"}`.
Facts preserve source-supported native profile system prompt, purpose, tool names,
name and agentic state when observed, with `facts.sources` URL/pointer locations.
Unknown fields are omitted; facts exceeding 24 KiB hold rather than silently trim.

## Private Observed Inputs

`--private-output` is a host-only output channel. Its direct parent must already
be caller-owned and private (0700). The new leaf is created 0600 with
`O_EXCL | O_NOFOLLOW`; existing files/symlinks and unsafe parents refuse before
any GET. Ancestors above the direct parent remain operator-trusted. There is no
overwrite or deletion of unrelated paths. Failed publication removes only the
unpublished leaf whose inode was created by this invocation.

Private-mode stdout contains only version/profile/origin/selection/status metadata,
observation/input counts, and `private_output: {path, sha256, bytes, format}`.
The format is `published_profile_prepare_private_v1`; the SHA-256 measures exact
file bytes. There is no contract, fact prose, capture or observed value on stdout.
The private file contains the complete bundle and `observed_inputs`:

```json
[{"id":"profile_workspace","origin":"https://target.example","in":"body",
  "field":"workspace","reference":"input:profile_workspace","value":"PRIVATE",
  "source_observation":1,"source_url":"https://target.example/api/workspaces/chosen",
  "source_pointer":"/share_id"}]
```

Only this private artifact carries observed slot values and complete raw source
entity bytes (`read_observations[].raw_response_bytes_base64`). These allow the
owner to verify the raw hash, parse the original observation and bind the exact
source pointer to the observed input. Sanitized captures remain complete JSON.
The parent must intercept the artifact before projection, read it securely, verify
its digest/scope, import observed inputs through normal credential-tool admission,
and replace only the declared `input:id` slots with returned references. Prepared
means a plan was prepared, not that inputs were admitted or a connection proved.
The CLI writes no credential store, runs no login/chat, and creates no application.
The parent may delete only its exact owned artifact after successful consumption.

Each private observation retains complete sanitized JSON, not an excerpt:

```json
{
  "method": "GET", "url": "https://target.example/api/config", "status": 200,
  "observed_at": "UTC timestamp",
  "raw_response_bytes_sha256": "sha256 hex", "raw_response_bytes": 123,
  "raw_hash_basis": "decoded_response_entity_bytes",
  "sanitized_capture_sha256": "sha256 hex",
  "sanitized_hash_basis": "canonical_json_ascii_utf8",
  "sanitized_data": {"app_name": "Doppelganger"}, "remote_attested": false
}
```

The raw digest measures complete response entity bytes exposed by Requests before
JSON parsing/replacement, not socket-level wire bytes. The sanitized digest measures
`json.dumps(data, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
allow_nan=False).encode("ascii")`. Neither attests remote authorship, freshness,
semantic correctness, application state or engine execution. Source-derived
credentials and occurrences of scoped credential values are replaced in sanitized
captures; duplicate
JSON keys, injected reference/template markers, unsafe credentials and oversized
sources hold. There is no general inference that arbitrary unlabelled text is
secret-free. Raw bytes and observed values exist only in the private artifact;
all private captures must be intercepted before any model/UI projection.

The owning Session consumer must validate the actual invocation, CLI revision,
scope, source observations, references and complete contract before issuing its
own private receipt. This JSON envelope is not that capability or authorization.
No local-file source receipt is fabricated.

## Bounds and Failure

At most four successful distinct GET observations, 64 KiB per response, a
20-second deadline checked before requests and between body chunks, bounded
socket timeouts, and 512 KiB serialized output. Callers may reduce `--timeout`.
Requests have no retries. The deadline is not a guarantee that an OS/socket
operation can be interrupted at an exact instant.

Only `outcome: "prepared"` is success (exit 0). All holds exit 1 and carry a fixed
`error.code`, no executable contract: `inputs_required`, `selection_required`,
`unavailable`, `conflicting_source`, `unsupported`, or `refused`. Exceptions and
target response bodies never become error text. A failed source may have no
complete capture; earlier complete safe observations are retained. Output-bound
failure explicitly sets `observations_omitted: true`. There are no remote writes
to replay and no proof claims to inherit from a successful process exit.
Missing or unresolved slots can include `required_slot` with the exact scoped
origin/field and, when supplied, its reference, never the credential value.
