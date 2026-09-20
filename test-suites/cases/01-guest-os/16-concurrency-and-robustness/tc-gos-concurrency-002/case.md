<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-gos-concurrency-002"></a>
# TC-GOS-CONCURRENCY-002: Head-of-line blocking on the quote path

## Metadata

- Priority: P0
- Type: Robustness, Performance, Availability, Security
- Minimum environment: HARDWARE
- Automation: Yes
- Requirements: [req-gos-concurrency-002](../../../../catalog/feature-audit.md#req-gos-concurrency-002)
- Risks: [risk-gos-concurrency-002](../../../../catalog/feature-audit.md#risk-gos-concurrency-002)
- Source: `dstack/tdx-attest/src/linux.rs`, `dstack/guest-agent/src/rpc_service.rs`, `dstack/guest-agent/src/rpc_service_v1.rs`, `dstack/guest-agent/dstack.toml`

## Prepared execution knowledge

- Read and obey [`shared/automation/execution-guide.md`](../../../../shared/automation/execution-guide.md) before executing Step 1.
- The harness is [`shared/automation/guest-agent-robustness-case.py`](../../../../shared/automation/guest-agent-robustness-case.py).
- Every probe uses its own connection. A probe that shared a connection with the
  load would queue behind its own earlier request and measure the agent's
  pipelining, not its scheduling.
- The harness measures the cost of one quote before it saturates anything, and
  reports **BLOCKED** rather than PASS when that cost is below 50 ms. See
  "Why a simulator run cannot confirm this" below.

## Objective

Verify that a method which does no work stays answerable while the agent's
slowest attestation method saturates its runtime.

`get_quote` in `dstack/tdx-attest/src/linux.rs` takes a process-global
`std::sync::Mutex` and then blocks — on configfs/TSM, or on a vsock connection
to the host's QGS opened with no connect, read or write timeout. Exactly one
call site treats that as blocking work: `attest` in
`dstack/guest-agent/src/rpc_service_v1.rs`, whose comment names the problem
precisely — *"takes a global mutex and then blocks in an ioctl. On the async
executor that parks a worker thread for the duration and stalls every other
connection this agent is serving."*

Every other path into the same function runs it directly on the executor:
`DstackGuest.GetQuote` and `DstackGuest.Attest`, `Tappd.TdxQuote` and
`Tappd.RawQuote`, `Worker.GetAttestationForAppKey`, `issue_cert`, and
`get_info` — which is the body of `DstackGuest.Info`, `Tappd.Info`, the
external `Worker.Info`, the `/` dashboard and the vsock `GuestApi.Info`, and
which calls `info_attestation()` on every call. The agent is configured with
`workers = 8` (`dstack/guest-agent/dstack.toml`), so eight concurrent callers on
any of those paths is the whole runtime.

The v1 identity cache (`AppIdentity` and `IDENTITY_RETRY_INTERVAL` in
`rpc_service.rs`) exists to stop exactly this, and its own comment says the
surface it protects is *"anonymous calls to the public `/prpc/v1/Info`"* — but
only `info_response` in `rpc_service_v1.rs` reads the cache. `get_info` does
not. This case measures the consequence rather than restating the code.

## Preconditions

1. A lease-owned guest on supported physical Intel TDX hardware, with the
   candidate guest agent serving its internal listener.
2. The host's QGS is reachable from the guest, so a quote costs what a quote
   costs in production. A fixture where quote generation is free cannot exhibit
   the behavior under test.
3. No other tenant is driving the same agent: a busy neighbour would be
   indistinguishable from the load this case applies.

## Test Data

- 20 unloaded `Version` samples, as the baseline.
- 3 `GetQuote` calls, as the measured cost of one unit of blocking work.
- 24 saturating threads — three times `workers = 8` — issuing `GetQuote` with
  fresh random `report_data` for 20 s.
- `Version` sampled every 100 ms on a fresh connection throughout, after a 1 s
  settle so the first sample does not measure an agent that is not yet loaded.
- Stated bound: `Version` p95 under load must stay at or below **1.0 s**.

## Steps

<a id="tc-gos-concurrency-002-step-01"></a>
### Step 1: Confirm the listener before the load

Resolve the lease-owned `DstackGuest` listener and call `Version`.

**Expected results:**

- The listener answers.

<a id="tc-gos-concurrency-002-step-02"></a>
### Step 2: Saturate the quote path and poll a trivial method

Measure the unloaded `Version` latency and the cost of a single `GetQuote`,
then hold 24 concurrent `GetQuote` calls in flight for 20 s while sampling
`Version`.

**Expected results:**

- One `GetQuote` costs at least 50 ms. Below that the load is not a load, the
  behavior under test cannot occur, and the result is BLOCKED — never PASS.
- Every saturating `GetQuote` is answered with HTTP 200, so the load was real
  work and not a queue of rejections.
- Every `Version` probe is answered.
- `Version` p95 under load is at most **1.0 s**. A p95 that tracks the quote
  cost instead is head-of-line blocking: the trivial method is waiting behind
  the global quote mutex and the parked worker threads, and the artifact's
  loaded-versus-baseline distribution is the evidence.

<a id="tc-gos-concurrency-002-step-03"></a>
### Step 3: Confirm the listener after the load

Call `Version` once more after every saturating call has returned.

**Expected results:**

- The listener answers. An agent that stopped answering did not merely slow
  down; it wedged.

## Why a simulator run cannot confirm this

The property under test is a *cost*: how long the global quote mutex is held
and how long the thread that holds it is unavailable. Under the `no-tee-dev`
simulator the platform backend answers `GetQuote` from a recorded fixture
attestation with its `report_data` patched in — measured at 0.6 ms on the
development host. Twenty-four concurrent calls at 0.6 ms never overlap enough
to park eight workers, so a simulated run would show a flat `Version` latency
and report PASS while proving nothing at all about the code path that blocks.

That is why this case declares `hardware_required: true` and
`simulation_allowed: false`, and why the harness treats a sub-50 ms quote as
BLOCKED. A simulated execution of this case must be reported as unconfirmed,
never as a pass.

## What this case does not prove

- It does not prove the absence of head-of-line blocking on the other
  unwrapped call sites. It measures `GetQuote` on the internal listener, the
  cheapest path to saturate. `Worker.Info`, the `/` dashboard and the vsock
  `GuestApi.Info` reach the same blocking function through `get_info`, and each
  has its own reachability and its own anonymous-caller exposure.
- It does not prove a bound under an adversarial caller. 24 threads is a load,
  not an attack; a caller that can route to the CVM is not limited to 24.
- It does not distinguish *why* a probe was slow. A p95 breach says the trivial
  method waited; the artifact's quote cost and worker count are what turn that
  into a diagnosis.

## Postconditions

The case creates nothing. Retain the baseline and loaded latency distributions
and the measured quote cost: a bound is only meaningful next to the cost of the
work it was measured against.
