# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

# Gateway test plan

This document records the local checks used for the gateway handshake-cache
change. The goal is to verify three things:

1. the generic `cached-cell` crate behaves correctly;
2. existing gateway control-plane and WaveKV flows still work;
3. the proxy data path does not call blocking `wg show latest-handshakes` per
   request.

## Prerequisites

Run on Linux with:

- Rust toolchain;
- `sudo`, `ip`, `wg` / `wireguard-tools`;
- `curl`, `openssl`, `python3`;
- `wrk` for the performance test.

The integration script creates temporary WireGuard interfaces named
`wavekv-test1`, `wavekv-test2`, and `wavekv-test3`, so it needs root privileges.

## Unit and build checks

From the repository root:

```bash
cargo test -p cached-cell
cargo test --manifest-path gateway/Cargo.toml
cargo check --manifest-path gateway/Cargo.toml
cargo clippy -- \
  -D warnings \
  -D clippy::expect_used \
  -D clippy::unwrap_used \
  --allow unused_variables
```

Expected result: all commands pass.

## WaveKV / gateway integration test

Build the gateway binary first:

```bash
cargo build --release --manifest-path gateway/Cargo.toml
```

Then run the integration suite:

```bash
cd gateway/test-run
sudo -E GATEWAY_BIN="$(pwd)/../../target/release/dstack-gateway" ./test_suite.sh
```

The suite starts real gateway processes and exercises:

- CVM registration through `POST /prpc/RegisterCvm` on the debug service;
- admin RPCs such as `Admin.SetNodeUrl`, `Admin.SetNodeStatus`, and
  `Admin.WaveKvStatus`;
- WaveKV persistent and ephemeral sync between gateway nodes;
- node restart, network partition recovery, periodic persistence, and node
  up/down filtering.

Expected result:

```text
Tests passed: 19
```

Important request paths covered by this suite:

| Path | Purpose |
| --- | --- |
| `POST /prpc/RegisterCvm` | Register a CVM, allocate a WireGuard IP, update gateway state. |
| `POST /prpc/Debug.Info` | Verify the debug service is available. |
| `POST /prpc/Debug.GetSyncData` | Inspect peer/node/instance data synced through WaveKV. |
| `POST /prpc/GetProxyState` | Compare in-memory proxy state with WaveKV state. |
| `POST /prpc/Admin.SetNodeUrl` | Register peer gateway URLs. |
| `POST /prpc/Admin.SetNodeStatus` | Mark nodes up/down and verify registration filtering. |
| `POST /prpc/Admin.WaveKvStatus` | Inspect WaveKV store status. |
| `POST /wavekv/sync2/persistent` | Gateway-to-gateway persistent data sync. |
| `POST /wavekv/sync2/ephemeral` | Gateway-to-gateway last-seen/handshake/connection sync. |
| `POST /wavekv/push/persistent` | Opportunistic persistent-state propagation. |
| `POST /wavekv/push/ephemeral` | Opportunistic ephemeral-state propagation. |

## Real proxy data-path smoke test

The integration suite above validates registration and sync, but it does not
open a client connection through the gateway proxy. For the proxy data path, use
this shape:

1. Start one `dstack-gateway` with debug/admin enabled and `insecure_skip_attestation = true`.
2. Register a test CVM through the debug `RegisterCvm` RPC.
3. Bind a local HTTPS backend to the allocated CVM IP, for example
   `10.0.51.2:23143`.
4. Serve a local DNS TXT response:

   ```text
   _dstack-app-address.proxy-flow.local TXT "proxyflow:23143"
   ```

5. Allow the backend port with `Admin.SetInstancePortPolicy` so the proxy data
   path is not blocked by port-policy fail-close.
6. Send a request through the proxy:

   ```bash
   curl -skf \
     --connect-to proxy-flow.local:13114:127.0.0.1:13114 \
     https://proxy-flow.local:13114/proxy-e2e
   ```

Expected response from the backend:

```text
proxy-e2e-ok path=/proxy-e2e
```

Expected gateway log shape:

```text
got sni: proxy-flow.local
target address is proxyflow:23143
connecting to 10.0.51.2:23143
connected to 10.0.51.2:23143
```

This confirms the real data flow:

```text
client -> gateway proxy -> SNI parse -> DNS TXT lookup -> ProxyState selection -> backend TLS service
```

## Proxy performance / hot-path check

The performance test uses the same real proxy data flow as the smoke test, with
one extra control: put a temporary `wg` wrapper earlier in `PATH` for the gateway
process. The wrapper delegates normal commands to `/usr/bin/wg`, but for

```text
wg show <iface> latest-handshakes
```

it returns a fixed test public key and records the call. This verifies that the
proxy hot path does not execute blocking `wg show` for every request.

Use `wrk` for three measurements:

```bash
# Direct backend baseline.
wrk -t4 -c64 -d15s https://10.0.62.2:23243/bench

# Gateway proxy with keep-alive.
wrk -t4 -c64 -d15s https://proxy-perf.local:13214/bench

# Gateway proxy with new TLS connections.
wrk -t4 -c32 -d10s -H 'Connection: close' \
  https://proxy-perf.local:13214/bench-close
```

Reference result from the local PR run:

```text
direct backend keep-alive:        71507 req/s, avg latency 1.14ms
gateway proxy keep-alive:         33842 req/s, avg latency 8.83ms
gateway proxy connection-close:     874 req/s, avg latency 33.45ms
```

The same run handled more than 500k proxy keep-alive requests. The `wg` wrapper
recorded:

```text
wg show latest-handshakes: 7
wg syncconf: 3
```

The important assertion is the call count: `wg show latest-handshakes` is only
used by startup/preload and the periodic refresh task, not once per proxied
request.

## PR CI

Check GitHub Actions before merging:

```bash
gh pr checks <PR_NUMBER> --repo Dstack-TEE/dstack --watch=false
```

Expected result: all required checks pass, including `gateway`, `rust-checks`,
`prek`, `reuse-lint`, and CodeQL.

## Proxy data-path integration tests

`test_proxy.sh` runs a real gateway process and asserts on what reaches the
wire, across every combination of the two gated optimisations and both proxy
paths. It runs in CI (`.github/workflows/gateway-proxy-tests.yml`); unlike
`test_suite.sh` it needs no root for the gateway itself, only one `sudo ip link
add` for the link the gateway expects at startup.

```bash
cd gateway/test-run
./test_proxy.sh                                   # builds the gateway if needed
GATEWAY_BIN=../../target/release/dstack-gateway ./test_proxy.sh
BASE_PORT=39000 ./test_proxy.sh                   # if the default range is busy
KEEP_LOGS=1 ./test_proxy.sh                       # keep the work dir on success
```

What it covers:

| group | asserts |
|---|---|
| data path | payloads survive byte-for-byte on both paths, under and over each gate, and under concurrency |
| close | the app closing reaches the client as an orderly TLS shutdown, including after kTLS offload |
| `timeouts.idle` | the idle watchdog reaps on every relay path -- buffered, spliced, kTLS -- and `data_timeout_enabled = false` still opts out |
| kTLS engagement | offload happens, and only once the gate fires; no TLS decrypt errors |
| capability fallbacks | a kernel without the TLS ULP warns and keeps serving untruncated; an inert `connection_rebalance` warns |
| runtime modes | every `thread_per_core` / `connection_rebalance` combination serves traffic |
| half-close | a client that finishes its request still gets the reply, on both paths and every arm |
| Status RPC | the accel counters reflect the traffic that ran |

The suite adapts to the host: groups that need a capability the kernel or the
privileges do not provide are reported as `SKIP` with the reason, never silently
passed.

Half-close needs a TLS client that can send `close_notify` without waiting for
the peer's, which `ssl.SSLSocket` cannot express: its only shutdown is
bidirectional, and dropping to `shutdown(SHUT_WR)` sends a bare FIN, which
mid-TLS is a truncation the peer is right to reject. `proxy/tlsclient.py`
drives the TLS state machine over memory BIOs to do it properly.
