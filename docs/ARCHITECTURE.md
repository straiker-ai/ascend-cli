# Architecture

How Ascend CLI connects the Straiker Ascend assessment cloud to your AI agent —
what runs where, what data crosses which boundary, and what you have to operate.

> **Adapter reference:** the per-adapter configuration schemas live in
> [`ADAPTER_AUTHORING.md`](ADAPTER_AUTHORING.md) and the layer model in
> [`CAPABILITY_MATRIX.md`](CAPABILITY_MATRIX.md). For the product documentation on
> advanced adapters, see the Straiker documentation site
> (`https://docs.straiker.ai` → Ascend AI → advanced integrations).

---

## 1. The big picture

Straiker generates and scores the attacks. **You run a small bridge** that fetches
probes over plain HTTPS and delivers them to your agent however your agent expects to
be called. Your agent is never exposed to the internet, and Straiker never needs a
route into your network.

```mermaid
flowchart LR
    subgraph straiker["Straiker Ascend cloud"]
        ASCEND["Ascend AI<br/>generates attacks<br/>scores responses"]
        LEASE["lease service<br/>/v2/lease · /v2/result"]
        API["v3 API<br/>apps · assessments<br/>controls · findings"]
        ASCEND <--> LEASE
    end
    subgraph yours["Your network / laptop"]
        CLI["<b>ascend</b> CLI"]
        RELAY["bridge<br/><i>outbound HTTPS only</i>"]
        AD["adapter<br/>(1 of 15)"]
        TARGET(["your AI agent"])
        CLI -- "starts / stops" --> RELAY
        RELAY --> AD --> TARGET
    end
    RELAY -- "lease / result" --> LEASE
    CLI -- "PAT" --> API
```

Two different things get called "the bridge" in conversation, and keeping them apart is
the difference between a five-minute diagnosis and an hour: the **lease service** is
Straiker-side and always up; **the bridge** is the process on your machine that leases
probes and calls your agent (this repo also calls it the relay). When someone says "the
bridge dropped", they nearly always mean their own bridge process is not running —
`ascend bridge ls` says which.

**Boundary facts that matter for review:**

| Question | Answer |
|---|---|
| Does Straiker connect *into* my network? | **No.** The bridge makes **outbound** HTTPS calls only. No inbound firewall rule, no public exposure of the agent. |
| What leaves my network? | The probe prompt (authored by Straiker) and your agent's response, which Straiker scores. |
| Where do my credentials live? | Target credentials stay in your adapter config / environment and are used only by the bridge. Straiker never receives them. |
| Can I stop it instantly? | Yes — stopping the bridge stops delivery immediately. |
| What if the bridge dies mid-probe? | The probe is reclaimed server-side after ~90s and redelivered. Nothing is lost. |
| How long may my agent take to answer? | Each probe has a bounded window of roughly **110–120s**, and the clock starts when the probe is **queued**, not when your relay calls the agent. See §6. |

---

## 2. The probe lifecycle

```mermaid
sequenceDiagram
    autonumber
    participant I as Ascend AI (Straiker cloud)
    participant R as bridge (yours)
    participant A as adapter
    participant T as your agent

    R->>I: POST /v2/lease (long-poll ≤25s)
    Note over R,I: no persistent socket — nothing to drop
    I-->>R: probes[] (0..10)
    Note over I: the ~110–120s window started when<br/>the probe was QUEUED, not here
    loop each probe
        R->>A: prompt
            A->>T: your real contract (REST/SSE/WS/session/poll)
            T-->>A: reply
            A-->>R: {response, success, duration}
            R->>I: POST /v2/result (200)
    end
    R->>I: POST /v2/lease (repeat)
```

Failures are **submitted, never dropped** — a target error becomes an honest result, so
the assessment completes instead of hanging.

---

## 3. What you operate

```mermaid
flowchart TB
    subgraph shells["Shells — thin, no business logic"]
        CLI["<b>ascend</b> CLI<br/>--help and --json everywhere"]
        SK["skills<br/><i>agent workflows</i>"]
        MCP["MCP shim<br/><i>optional, shell-less hosts</i>"]
    end
    subgraph core["Core"]
        CTRL["control/<br/>v3 client<br/>created→pause→resume"]
        DISC["discovery/<br/>capture · classify<br/>compose · validate"]
        RT["runtime/<br/>lease · dispatch<br/>adapters"]
        ENT["reporting/<br/>SARIF · CI gate"]
    end
    AD["adapters (15)<br/>rest · sse · websocket · session · poll<br/>sentinel · browser · custom<br/>platform presets"]
    CLI --> core
    SK --> CLI
    MCP -.->|exec --json| CLI
    RT --> AD --> TGT(["your agent"])
    CTRL --> SAPI(["Straiker v3 API"])
    RT --> SBR(["/v2/lease · /v2/result"])
```

One core, three thin shells. The CLI is the deterministic substrate; skills and the
optional MCP shim call it rather than reimplementing anything.

---

## 4. Why pull mode

The legacy bridge held a persistent WebSocket that Straiker pushed probes onto. A
dropped socket produced `bad handshake` on reconnect and could **auto-pause a live
assessment**. v2 inverts the flow.

```mermaid
flowchart LR
    subgraph old["Legacy — push over a socket"]
        O1["persistent WebSocket"] --> O2["broken pipe"] --> O3["bad handshake"] --> O4["assessment auto-paused"]
    end
    subgraph new["v2 — pull over plain HTTPS"]
        N1["long-poll lease"] --> N2["network blip"] --> N3["retry next lease"] --> N4["run continues"]
    end
```

There is no long-lived connection, so that entire class of failure cannot occur.
Un-acked probes are reclaimed after ~90s; the bridge adds a QPM throttle and
session-aware concurrency the old bridge lacked.

---

## 5. Getting connected

Most integration effort is *learning your agent's contract*. You supply whatever evidence
of that contract you already have, and `target add` works out which kind it is — choosing
between mutually-exclusive source flags was a question people frequently could not answer,
while the artifact itself always knows what it is.

```mermaid
flowchart LR
    A["a URL<br/><i>https://your-bot/chat</i>"] --> D
    B["a request<br/><i>copy as cURL from devtools</i>"] --> D
    C["a browser session<br/><i>.har export</i>"] --> D
    E["a saved config<br/><i>mybot</i>"] --> D
    D{"<b>ascend target add</b><br/>detect · compose · validate"}
    D -- answered --> S(["registered target → assess run"])
    D -- did not --> R(["diagnosis + next command<br/><i>nothing written</i>"])
```

A config is only usable once it has produced a real answer from your live target, so
`target add` validates before it registers anything, and `target check` re-proves a target
later. That second step is not ceremony: a target that has drifted — auth expired, response
shape moved, endpoint relocated — still yields a clean-*looking* assessment that measured
nothing, and a false pass is the most expensive outcome this tool can produce.

`adapter build`, `map` and `discover` remain available underneath for the cases that need
them. See [`DISCOVERY.md`](DISCOVERY.md) for the capture pipeline and its limits.

---

## 6. Two limits worth knowing before you debug

**The per-probe window.** The platform gives each probe roughly **110–120s**, measured from
when it is *queued* — not from when your relay calls your agent. A probe that exceeds it comes
back as a synthetic timeout that looks exactly like your target failing, and enough of those
auto-pause the assessment. So a slow agent presents as a broken one. `adapter validate` and
`target check` time the call and say so plainly when a target is at or beyond the window.
Agents that think for two or three minutes are common; if yours does, lower concurrency or
raise QPM headroom rather than assuming the relay is at fault.

**Where configs are found.** Adapter configs are searched per *file*, in this order:
`$ASCEND_CONFIG_DIR`, then `./configs`, then `~/.ascend/configs`, then the bundled examples.
New configs are written to one directory (`ascend adapter configs` prints which). This is
worth knowing because the failure is misleading: a config that cannot be resolved makes
`runtime start` exit *before it ever leases*, and a relay that never starts is
indistinguishable from one that dropped — while `ascend keys` keeps working, since keys live
in `~/.ascend` and never depended on the working directory.
