# Tunnel Runtime Contract

`ascend tunnel` prefers the operator's `ascend-tunnel` on PATH. It neither replaces
that binary nor probes its version. `--runner binary` and `--runner docker` retain
their explicit selection semantics.

The Docker fallback uses the multi-architecture release index:

```text
ghcr.io/straiker-ai/ascend-tunnel:0.1.6@sha256:892b4aec63af03877b78bc1ca3208133451493c328c229e1efbca4e2cc6e8051
```

The [v0.1.6 release](https://github.com/straiker-ai/ascend-tunnel/releases/tag/v0.1.6)
and image provenance identify source commit
`dca071e23e442f8dece1a3fa8baba479d12e5dfa`. The index includes Linux amd64 and arm64.
Release archives also cover macOS and Windows on both architectures. macOS
binaries are signed and notarized; Windows archives are not Authenticode-signed.
Windows winget and Scoop packages are not published. Building from source uses
the upstream Go 1.27.3 toolchain; prebuilt archives need no Go or Python runtime.

The wrapper preserves `run`, `check`, and `key` arguments, explicit state paths,
Docker state/CA mounts, proxy variables passed by name, detached supervision and
Stop. The same state directory preserves the machine's identity across upgrades.
Published relay host keys and the staging endpoint follow the release's
`internal/config/config.go`. An explicit host key takes precedence; a custom
relay receives no unrelated built-in key.

Both earlier check output and the release's sectioned output are accepted.
`check` in v0.1.6 does not create a key. A connectivity pass with no verified
login is not evidence that an application lists the key. WAIT and FAIL rows
remain distinct, and a later section's PASS cannot erase an earlier failure.

The assessment bridge is a separate CLI runtime: supervision starts
`runtime/run.py`, which combines `TargetCaller` with `runtime/lease_client.py`.
Refreshing the tunnel does not replace that bridge, its authentication, result
acknowledgement, reconciliation or conversation policy. The experimental
`ascend-agent` binary in the tunnel release is a different cloud-tool host,
not a replacement for this assessment bridge or the Python Ascend Agent.

An embedding Agent must first qualify the CLI change and then pin the exact
reviewed CLI commit. Updating a vendored transport reference alone does not
update the running bridge.
