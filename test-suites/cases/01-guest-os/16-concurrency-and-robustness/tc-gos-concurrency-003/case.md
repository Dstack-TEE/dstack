<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-gos-concurrency-003"></a>
# TC-GOS-CONCURRENCY-003: Agent survival and process identity after concurrent load

## Metadata

- Priority: P0
- Type: Robustness, Availability, Regression
- Minimum environment: SIMULATOR
- Automation: Yes
- Requirements: [req-gos-concurrency-003](../../../../catalog/feature-audit.md#req-gos-concurrency-003)
- Risks: [risk-gos-concurrency-003](../../../../catalog/feature-audit.md#risk-gos-concurrency-003)
- Source: `dstack/guest-agent/src/server.rs`, `dstack/guest-agent/src/rpc_service.rs`, `dstack/guest-agent/src/guest_api_service.rs`

## Prepared execution knowledge

- Read and obey [`shared/automation/execution-guide.md`](../../../../shared/automation/execution-guide.md) before executing Step 1.
- The harness is [`shared/automation/guest-agent-robustness-case.py`](../../../../shared/automation/guest-agent-robustness-case.py).
- Process identity is (PID, start time from `/proc/<pid>/stat`). Release
  builds use `panic = "abort"` and the agent is supervised, so a socket that
  answers after the load may belong to a restarted process.

## Objective

Verify that the agent answers every concurrent request on all four listeners
and is still the same process afterwards.

## Preconditions

1. The internal `DstackGuest`, legacy `Tappd`, external `Worker` and
   `GuestApi` listeners are reachable.
2. The case manifest publishes the agent's PID and `/proc/<pid>` is readable;
   otherwise the case is BLOCKED.

## Test Data

Eleven methods, six times each, all in flight at once (66 calls):

| listener | methods |
|---|---|
| `DstackGuest` | `GetKey`, `GetQuote`, `Info`, `Version`, `GetTlsKey` |
| `Tappd` | `TdxQuote`, `Info` |
| `Worker` | `Info`, `Version` |
| `GuestApi` | `Info`, `SysInfo` |

## Steps

<a id="tc-gos-concurrency-003-step-01"></a>
### Step 1: Confirm all four listeners before the load

Call a trivial method on each listener.

**Expected results:**

- All four answer.

<a id="tc-gos-concurrency-003-step-02"></a>
### Step 2: Drive 66 concurrent calls across the four listeners

Record the agent's identity and counters, issue the whole table concurrently,
then send one `GetKey` and re-read the counters.

**Expected results:**

- Every call returns HTTP 200, and so does the `GetKey` probe.
- The agent's (PID, start time) is unchanged.
- The agent holds at most `workers` more open descriptors than before, when
  `/proc/<pid>/fd` is readable.

<a id="tc-gos-concurrency-003-step-03"></a>
### Step 3: Confirm all four listeners after the load

Call a trivial method on each listener again.

**Expected results:**

- All four answer.

## Postconditions

Nothing is created outside the lease. Keep the before/after counters and the
identity pair.
