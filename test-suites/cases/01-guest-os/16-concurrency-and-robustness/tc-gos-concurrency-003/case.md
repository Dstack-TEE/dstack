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
- Process identity is the pair (PID, start time from field 22 of
  `/proc/<pid>/stat`). A PID alone is not identity: a supervised agent can be
  restarted and handed the same number back.
- The `no-tee-dev` fixture publishes the lease-owned agent's PID, which is what
  makes the `/proc` observations possible from the control host.

## Objective

Verify that the guest agent answers every concurrent request across all four of
its listeners, answers a valid request afterwards, and is still the process it
started as.

The last clause is the one that makes the rest mean anything. `dstack-guest-agent`
is a supervised service, and the workspace builds release binaries with
`panic = "abort"`: a reachable panic on any handler is a process abort, and a
restart would put a fresh agent behind the same socket within a second. A case
that only re-probed the socket would see a healthy answer and call that
survival. Comparing the process identity across the load is what distinguishes
"the agent survived" from "something replaced it".

## Preconditions

1. The shared plan prerequisites are healthy and all four lease-owned listeners
   — internal `DstackGuest`, legacy `Tappd`, external `Worker` and the
   `GuestApi` surface — are reachable.
2. The case manifest publishes the agent's PID and `/proc/<pid>` is readable
   from the control host. Without it the identity check is not possible and the
   case is BLOCKED rather than downgraded to a socket probe.

## Test Data

Eleven methods spanning every listener and both the cheap and expensive paths,
repeated six times each and issued concurrently — 66 calls in flight, against
`workers = 8`:

| listener | methods |
|---|---|
| `DstackGuest` | `GetKey`, `GetQuote`, `Info`, `Version`, `GetTlsKey` |
| `Tappd` | `TdxQuote`, `Info` |
| `Worker` | `Info`, `Version` |
| `GuestApi` | `Info`, `SysInfo` |

`GetTlsKey` and `TdxQuote` are in the table deliberately: certificate issuance
and quote generation are the two most expensive things the agent does, and
`Info` on three of the four listeners reaches `info_attestation()` on every
call.

## Steps

<a id="tc-gos-concurrency-003-step-01"></a>
### Step 1: Confirm all four listeners before the load

Call a trivial method on each of the four lease-owned listeners.

**Expected results:**

- All four answer.

<a id="tc-gos-concurrency-003-step-02"></a>
### Step 2: Drive 66 concurrent calls across the four listeners

Record the agent's process identity and its descriptor, thread and
resident-memory counters, issue the whole table concurrently, then probe with
one valid request and re-read the counters.

**Expected results:**

- Every call receives an HTTP answer. A dropped connection or a reset is a
  failure: a malformed request may be refused, but a well-formed one on a
  listener that serves it may not go unanswered.
- Every call is answered with HTTP 200. Each method in the table is one that
  listener implements, so a non-200 is the agent refusing work it accepted
  before the load.
- The post-load `GetKey` probe is answered.
- The agent's (PID, start time) pair is unchanged. A change means the agent
  aborted or was restarted, and every other observation in this step describes
  a different process than the one that took the load.
- The agent holds at most `workers` more open descriptors than before. Every
  connection is closed by the time the counters are re-read, so a descriptor
  still held per call is a leak rather than work in flight.

<a id="tc-gos-concurrency-003-step-03"></a>
### Step 3: Confirm all four listeners after the load

Call a trivial method on each listener again.

**Expected results:**

- All four answer.

## What this case does not prove

- It does not bound resident memory. The artifact records the delta, and on the
  development host 66 concurrent calls including six certificate issuances grew
  the simulator by about 100 MB — allocator retention, not a leak, and not a
  figure this case is willing to turn into a threshold without a longer series
  to justify one. Descriptors are asserted because they have an unambiguous
  balance point; memory does not.
- It does not prove the agent is *fast* under load. Latency under saturation is
  [tc-gos-concurrency-002](../tc-gos-concurrency-002/case.md#tc-gos-concurrency-002).
- On the `no-tee-dev` fixture the agent is a simulator process on the control
  host, so the identity check observes that process. On a guest fixture the
  equivalent observation is the agent's PID inside the CVM, which this case
  does not reach.

## Postconditions

The case creates nothing outside the lease. Retain the before/after counter
table and the process identity pair.
