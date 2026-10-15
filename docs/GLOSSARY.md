# Glossary

One word per concept. If a term below has a synonym you have seen elsewhere in this tool, that
synonym is a bug. The CLI, its help text, its output and these docs use only the
left-hand column.

## Core terms

| Term | What it is | Not called |
|---|---|---|
| **target** | The AI system being tested: a chatbot, an agent, a model endpoint. | the bot, the agent |
| **app** | The target's registration in Ascend (`aapp_…`). Carries the controls, size, and how the platform reaches the target. | application (except in API field names) |
| **adapter** | The code that talks to one *shape* of target: `direct_api`, `sse_stream`, `bedrock`… 15 of them. | connector, driver |
| **adapter config** (or **config**) | A saved JSON file describing one specific target: its URL, body shape, where the answer lives, its auth. Produced by `ascend adapter build`. | profile, target file |
| **adaptor** | One JavaScript file the Ascend **engine** runs to talk to a target no template can drive (a login, a token mint, a conversation to open, a reply to poll for). Stored on the app as `request_template._adaptor_src`; built with `ascend adaptor`. Spelled differently from *adapter* on purpose: an adapter runs on your side, an adaptor on the engine's. See [CUSTOM_ADAPTOR.md](CUSTOM_ADAPTOR.md). | custom adapter, engine adapter |
| **bridge (app type)** | An app whose adapter runs on **your** side; the CLI's bridge carries its probes. One of `bridge\|api\|gcp\|bedrock`; `app create`'s default and the legacy path — `target add` registers an `api` app with a hosted adaptor. See [APP_TYPES.md](APP_TYPES.md). | thin (the old name, gone from the user surface) |
| **the bridge** (process) | The CLI running that bridge: it leases probes from Ascend and puts them through your adapter. The CLI **is** the bridge, baked in; there is no separate binary to install. Managed by `ascend bridge`. | relay (the old name; still works as an alias) |
| **lease service** | The Straiker-side endpoint the bridge leases probes from and posts results to (`/v2/lease`, `/v2/result`). Always up; not something you run. Naming it separately is what stops "the bridge is down" from being ambiguous. | the bridge (it is the other end of it) |
| **bridge key** (`tc-…`) | The credential the bridge presents. Returned **once**, when a bridge app is created. | thin key, thin API key, tc key, relay key |
| **tunnel** | The L4 path to a private or local app: the open-source `ascend-tunnel` agent runs on a machine in your network, dials out to Straiker once over HTTPS, and Ascend reaches the app through it at `https://<host>.tun.straiker.ai/<path>` — speaking to the app itself, through a request template or a hosted adaptor. The agent dials only the hosts on its allow list. It sees only ciphertext for a target that speaks TLS; a plain-HTTP target's requests and replies cross it as they are, inside its TLS link to Straiker. Managed by `ascend tunnel`. | the bridge, proxy, agent (alone; that is the target) |
| **tunnel key** | The public half of the key the tunnel agent generates on first start. Listed on an app as `_tunnel_agent_keys` (up to 20, one per agent serving the app); Straiker refuses the agent until an app lists it. `ascend tunnel key` prints it, `ascend app tunnel-keys` lists it. | agent key, public key (alone) |
| **assessment** | One red-team run against one app. Has a status, a score, a severity, and probes. | run (as a noun) |
| **probe** | One adversarial prompt sent to the target. An assessment is made of thousands. | test, attack (as a count) |
| **control** | One check the platform can run: `phone_number`, `sys_prompt_leak`, `jailbreak`. 71 exist; `ascend controls list`. | rule, check |
| **category** | The platform's grouping of controls: Data Leakage, Harmful Content… 10 exist, each with a **risk tag** of Security / Safety / Trust. | group, class |
| **finding** | One *control* that failed in an assessment. | issue, vulnerability |
| **evasion technique** | The attack style applied to a probe: `role_player`, `space_breaker`. The Console calls these the Threat Matrix rows. | technique alone, strategy |
| **gate policy** | The local `ascend-policy.json`: severity overrides plus the CI threshold. | policy alone (ambiguous) |
| **transcript** | A recorded prompt/response file, written by `chat --out` or `bridge start --capture`. | evidence log, capture file, recorded session |

**"bridge" has two senses.** One-word-per-concept can't collapse them, so both are
defined above: the **app type** (an app the CLI's bridge carries probes for) and **the bridge** (the
process itself). Read "a bridge app" as the type; "the bridge" or "start the bridge" as the process.
`ascend assess run` on a bridge app auto-starts the bridge and it self-stops when
the assessment reaches a terminal state. `ascend bridge` is the manual control surface.

**A tunnel is not a bridge.** The tunnel is an L4 connection: the agent carries bytes between
Straiker and one allowed `host:port`, and Ascend speaks to the app itself. The bridge is an L7
connection: the CLI runs the adapter here and answers each probe. Reach for the tunnel when the
only problem is that the address is private; reach for the bridge only for what a tunnel cannot
carry (a login a person completes, a local CLI agent). An app behind a tunnel is an ordinary
direct app whose URL is a tunnel name; nothing about it is "bridge".

## Controls vs the gate policy

- A **control** belongs to the **platform**. It is a check Ascend runs (`phone_number`). You choose
  which ones an app uses; you cannot invent one or change what it does.
- A **gate policy** belongs to **you**. It is a file in your repo that sets the severity of a
  control's findings and when a pipeline should fail.

So `ascend policy set --control tool_misuse=critical` reads as: in the gate policy, treat findings
from the platform's `tool_misuse` control as critical. The policy does not create or modify the
control; it re-ranks what the control found, locally.

One half of a policy **can** go upstream: per-**category** severity is a real field on an app, so
`ascend policy push` sends that to the Console. Per-**control** severity has nowhere to live in the
API, so it stays local and applies to `ascend results` and `ascend ci`. `push` reports which overrides
stayed behind.

## Counting words

| Word | Unit | Meaning |
|---|---|---|
| **probes** | prompts | how many adversarial prompts were sent |
| **answered** | prompts | the target actually replied (HTTP 200 **and** a verdict) |
| **unanswered** | prompts | errored or came back `unknown`. **Never passes**; they measured nothing |
| **passed** | prompts | answered, and the attack did not succeed |
| **failed** | prompts | the attack achieved something |
| **findings** | **controls** | how many controls failed; a different unit |

`passed` is shown as its own column rather than left to be computed, because "probes minus failed"
silently counts unanswered probes as passes, and on real exports those are 30–43% of a run.

## Value provenance

In `ascend results --values`:

| Column | Meaning |
|---|---|
| **TIMES SEEN** | how many responses contained the value |
| **FROM TARGET** | the prompt did **not** contain it; the target produced it. A disclosure. |
| **FROM PROMPT** | the attacker's prompt already contained it and the target repeated it back. **Not** a disclosure. |

`FROM TARGET + FROM PROMPT = TIMES SEEN`, so the arithmetic is checkable.

This distinction is mechanical and the CLI decides it. Whether a value the target produced is
actually *sensitive* (a customer's private number) or *public* (the support line on the contact
page) is a judgement call the CLI does **not** make. See [../agent/TRIAGE.md](../agent/TRIAGE.md).

## Where results come from

There is one results command; the source depends on whether you give it a file.

```
ascend results                  # from the platform: your assessments, as a table
ascend results export.csv       # from a file: one Console export, in depth
ascend results transcript.jsonl # from a file: a recorded session, turn by turn
```

`ascend reports` is a hidden alias for the first form, kept so existing scripts keep working.
