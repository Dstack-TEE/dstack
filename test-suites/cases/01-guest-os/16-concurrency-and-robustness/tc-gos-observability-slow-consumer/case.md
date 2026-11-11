<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-gos-observability-slow-consumer"></a>
# TC-GOS-OBSERVABILITY-SLOW-CONSUMER: Log streaming backpressure with a stalled consumer

## Metadata

- Priority: P1
- Type: Robustness, Availability, Observability
- Minimum environment: SIMULATOR
- Automation: Yes
- Requirements: [req-gos-observability-slow-consumer](../../../../catalog/feature-audit.md#req-gos-observability-slow-consumer)
- Risks: [risk-gos-observability-slow-consumer](../../../../catalog/feature-audit.md#risk-gos-observability-slow-consumer)
- Source: `dstack/guest-agent/src/http_routes.rs`

## Prepared execution knowledge

- Read and obey [`shared/automation/execution-guide.md`](../../../../shared/automation/execution-guide.md) before executing Step 1.
- The harness is [`shared/automation/guest-agent-robustness-case.py`](../../../../shared/automation/guest-agent-robustness-case.py).
- `/logs/<container>` is served on the external listener when `public_logs`
  is set. The case starts a run-scoped `dstack-robustness-*` container as its
  log source and removes it on every exit. Without a reachable Docker daemon
  the case is BLOCKED.

## Objective

Verify that a log reader that stops draining a `follow` stream does not make
the agent buffer the stream in memory or park its runtime.

## Preconditions

1. The agent's external and internal listeners are reachable, and the booted
   compose sets `public_logs`.
2. A container runtime is reachable.
3. The case manifest publishes the agent's PID.

## Test Data

- A container writing about 3.3 MB/s of log lines, with a 32 MiB log cap.
- A 30 s stall window sampled every 2 s. Bound: resident memory grows at most
  **32 MiB**.
- 10 simultaneously stalled readers, two more than `workers = 8`.

## Steps

<a id="tc-gos-observability-slow-consumer-step-01"></a>
### Step 1: Confirm the listeners and the container runtime

Call a trivial method on both listeners and query the container runtime.

**Expected results:**

- Both listeners answer and the runtime reports its version.

<a id="tc-gos-observability-slow-consumer-step-02"></a>
### Step 2: Stall one reader, then ten

Open `/logs/<container>?follow=true`, read only the response head, and stop
reading for 30 s while sampling the agent. Resume reading. Then open ten
streams, leave them stalled and call `Version` on the internal listener.

**Expected results:**

- The stream starts with `HTTP/1.1 200`.
- Resident memory grows by at most 32 MiB across the window.
- Resuming the reader returns pending data.
- `Version` is answered while the ten readers are stalled.

<a id="tc-gos-observability-slow-consumer-step-03"></a>
### Step 3: Confirm the listeners after the streams closed

Call a trivial method on both listeners again.

**Expected results:**

- Both answer.

## Postconditions

Remove the run-scoped container. Keep the resident-memory and thread series.
