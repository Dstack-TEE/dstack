# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

# Gateway integration tests

Three suites, all under docker compose, all driven from the host. None of them
needs root on the machine running them, and none of them leaves anything behind.

| Suite | Covers | Run it |
| --- | --- | --- |
| `e2e/` | certbot, ACME, DNS-01 and `dns-persist-01` | `e2e/run-e2e.sh` |
| `cluster/` | WaveKV replication, node identity, partition recovery, admin RPCs | `cluster/run-cluster-tests.sh` |
| `proxy-e2e/` | the proxy data path: splice, kTLS, half-close, idle reaping | `proxy-e2e/run-proxy-tests.sh` |

Each has a `--skip-build` flag that reuses the `dstack-gateway` binary already
staged next to its compose file, and a `down` subcommand that tears everything
down.

## Attestation is on

No suite turns the checks off. The gateways obtain their
RPC certificates from the guest agent simulator, which signs quotes under trust
anchors derived from `attestation/tee-simulator.json`; the mock collateral
service reconstructs the matching public roots from the same seed, and the
gateways verify each other through the normal production path.

That is the point of the arrangement rather than a detail of it: the cluster's
mTLS is what `cluster/` exists to exercise, and a suite that switched the checks
off would be testing the switch.

## One fixture, one seed

`attestation/fixture.yml` runs as its own long-lived compose project, started by
whichever suite you run. The suites reference its network and volumes rather
than each building a copy, so there is one simulator, one collateral service and
one seed. Two copies would drift apart, and every peer quote would then fail to
verify with nothing saying why.

## One project per test

The cluster suite gives each test a throwaway compose project of its own. Its
containers, its logs and its data directory are empty when it starts because
they are new -- not because something cleaned them up.

That is the point rather than a detail. The version before it shared three
containers across all 28 tests and cleaned between them, which needed a wipe
helper, a time window on `docker logs`, and a lock to stop two runs from
clearing each other's state. Each of those three was the direct cause of a bug
during development, and each stops being possible here.

## Unit and build checks

From `dstack/`:

```bash
cargo test -p cached-cell
cargo test --manifest-path gateway/Cargo.toml
cargo clippy -- -D warnings -D clippy::expect_used -D clippy::unwrap_used \
  --allow unused_variables
```

## What runs in CI

| Workflow | Suite |
| --- | --- |
| `.github/workflows/gateway-e2e-tests.yml` | `e2e/` |
| `.github/workflows/gateway-cluster-tests.yml` | `cluster/` |
| `.github/workflows/gateway-proxy-tests.yml` | `proxy-e2e/` |

```bash
gh pr checks <PR_NUMBER> --repo Dstack-TEE/dstack --watch=false
```

## The kTLS fallback arm

One arm of the proxy suite asserts that a gateway configured for kTLS on a
kernel without the TLS ULP falls back to userspace instead of truncating a gated
transfer at the gate. It runs in its own container, because the condition is
produced by a seccomp profile -- `setsockopt(IPPROTO_TCP, TCP_ULP)` returns
`ENOPROTOOPT` -- and a seccomp profile is fixed when a container is created.

See `proxy-e2e/README.md` for why that replaced taking the module away from the
host with `rmmod`.

## Proxy performance / hot-path check

Not part of any suite, and not reproducible from this tree: the `wg` wrapper and
the `/bench` endpoints it describes were never checked in. The numbers below are
kept as the record of one manual run made for the handshake-cache change, and
the claim they support -- that the proxy hot path does not shell out to
`wg show latest-handshakes` per request -- is what the assertion in
`test_proxy.sh` (`test_accel_status`) covers on every run.

```text
direct backend keep-alive:        71507 req/s, avg latency 1.14ms
gateway proxy keep-alive:         33842 req/s, avg latency 8.83ms
gateway proxy connection-close:     874 req/s, avg latency 33.45ms

wg show latest-handshakes: 7   (over 500k proxied keep-alive requests)
wg syncconf: 3
```
