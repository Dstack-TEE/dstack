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
- Source: `dstack/tdx-attest/src/linux.rs`, `dstack/guest-agent/src/rpc_service.rs`, `dstack/guest-agent/src/server.rs`

## Prepared execution knowledge

- Read and obey [`shared/automation/execution-guide.md`](../../../../shared/automation/execution-guide.md) before executing Step 1.
- The harness is [`shared/automation/guest-agent-robustness-case.py`](../../../../shared/automation/guest-agent-robustness-case.py).
- Every call uses its own connection.
- The simulator answers a quote in under a millisecond, so nothing blocks. The
  harness reports **BLOCKED**, never PASS, when one quote costs less than 50 ms.

## Objective

Verify that a trivial method stays answerable while concurrent quotes saturate
the agent, and that the agent is not restarted by its own watchdog.
`tdx_attest::get_quote` holds a global mutex while it blocks on the host QGS.
The watchdog heartbeat is a `Worker.Version` call to the agent itself, so a
runtime parked on quotes gets the agent SIGABRTed (fixed in #1256).

## Preconditions

1. A lease-owned guest on physical Intel TDX hardware with a reachable host
   QGS, and no other load on the agent.

## Test Data

- 20 unloaded `Version` samples and 3 single `GetQuote` calls, as baselines.
- 24 threads issuing `GetQuote` with random `report_data` for 20 s, while
  `Version` is sampled every 100 ms.
- Bound: loaded `Version` p95 at most **1.0 s**.
- The in-guest agent's (PID, start time) before and after, read over the
  fixture's `ssh_argv` when it publishes one.

## Steps

<a id="tc-gos-concurrency-002-step-01"></a>
### Step 1: Confirm the listener before the load

Call `Version` on the `DstackGuest` listener.

**Expected results:**

- The listener answers.

<a id="tc-gos-concurrency-002-step-02"></a>
### Step 2: Saturate the quote path and poll a trivial method

Measure the baselines, then hold 24 concurrent `GetQuote` calls for 20 s while
sampling `Version`.

**Expected results:**

- One `GetQuote` costs at least 50 ms; otherwise the result is BLOCKED.
- The agent's (PID, start time) is unchanged.
- Every `GetQuote` and every `Version` probe returns HTTP 200.
- Loaded `Version` p95 is at most 1.0 s.

<a id="tc-gos-concurrency-002-step-03"></a>
### Step 3: Confirm the listener after the load

Call `Version` again.

**Expected results:**

- The listener answers.

## Postconditions

Nothing is created. Keep the baseline and loaded latency distributions and the
measured quote cost.
