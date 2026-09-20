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
- The `/logs/<container>` route is mounted on the **external** listener and only
  when `public_logs` is set in the compose. It is not on the internal socket.
- This case owns its log sources. It starts two run-scoped containers named
  `dstack-robustness-*` and removes both in cleanup, including on failure. A
  fixture with no reachable container runtime makes the behavior impossible to
  observe, and the harness reports BLOCKED with the probe output rather than
  passing on an empty stream.
- Step 3 waits out a 600 s product timeout. That is the case's cost, and it is
  why the declared timeout is 900 s.

## Objective

Verify that an HTTP client which opens `/logs/<container>?follow=true` and then
stops reading does not become the agent's problem: that the agent does not
buffer the stream without bound, that stalled readers do not park the runtime,
and that an idle `follow` stream is eventually closed by the per-chunk timeout
rather than held open forever.

`get_logs` in `dstack/guest-agent/src/http_routes.rs` serves logs as a Rocket
`TextStream!`, a generator polled by the response writer, wrapping each
`stream.next()` in `tokio::time::timeout(Duration::from_secs(600), ...)`.
Backpressure is therefore structural — a consumer that stops reading stops the
generator being polled, which stops bollard pulling from Docker — but nothing
in the suite asserts it. A future refactor that spawns the log pump into its own
task and buffers into a channel would keep every existing test green while
turning one stalled reader into unbounded growth in a CVM with a fixed memory
size.

## Preconditions

1. The shared plan prerequisites are healthy and the lease-owned agent's
   external listener is reachable over its unix socket.
2. The compose the agent booted with sets `public_logs`, so the route is
   mounted.
3. A container runtime is reachable, so the case can own a log source. If it is
   not, the case is BLOCKED and records the probe that showed it.
4. The case manifest publishes the agent's PID, so resident memory and thread
   count can be sampled from the control host.

## Test Data

- One *chatty* run-scoped container emitting roughly 30 000 100-byte lines per
  second, measured at about 3.3 MB/s, as the source that would accumulate if the
  agent buffered. Its log file is capped at 32 MiB with one rotation, so the
  source cannot fill the host's disk.
- One *idle* run-scoped container that sleeps and writes nothing, as the source
  for the timeout.
- A 30 s stall window sampled every 2 s.
- Stated bound: the agent's resident memory may grow at most **32 MiB** across
  the stall window. That covers the kernel socket buffer and the agent's own
  write buffer. The source is deliberately faster than the bound: an agent that
  buffered the stream instead of pushing back would pass 32 MiB about ten
  seconds into the thirty-second window, so the bound is a detector rather than
  a formality.
- 10 simultaneously stalled readers — two more than `workers = 8`.
- The per-chunk timeout: **600 s**, with a 45 s tolerance.

## Steps

<a id="tc-gos-observability-slow-consumer-step-01"></a>
### Step 1: Confirm the listeners and the container runtime

Call a trivial method on the external and internal listeners, and confirm a
container runtime is reachable to host the case's log sources.

**Expected results:**

- Both listeners answer and the runtime reports its version. A runtime that is
  not reachable ends the case BLOCKED here, before anything is created.

<a id="tc-gos-observability-slow-consumer-step-02"></a>
### Step 2: Stall one reader, then ten

Start the run-scoped chatty container, open `/logs/<chatty>?follow=true`, read
only the response head, and stop.
Sample the agent for 30 s, then resume reading. Then open ten streams at once
and leave all of them stalled while probing a different listener.

**Expected results:**

- The stream starts: the response head is `HTTP/1.1 200`. Reading the head
  first is what makes the stall meaningful — it proves the agent accepted the
  request and began producing before the reader stopped.
- The agent's resident memory grows by at most 32 MiB across the window, and its
  thread count does not climb. A generator that is not being polled is not
  reading from Docker; growth here means the stream was decoupled from the
  consumer.
- Resuming the reader recovers data immediately. A window in which nothing was
  pending was not a stalled live stream and proves nothing, so a zero-byte
  resume fails the step.
- With ten stalled readers open — more than the agent has workers — a `Version`
  call on the internal listener is still answered. A stalled write that parked a
  worker would show up here.

<a id="tc-gos-observability-slow-consumer-step-03"></a>
### Step 3: Let the per-chunk timeout fire

Open `/logs/<idle>?follow=true` against the silent container and read
continuously.

**Expected results:**

- The stream ends on its own after 600 s ± 45 s, matching the per-chunk timeout
  in `get_logs`. The connection is not held open indefinitely by a log source
  that has nothing to say.

<a id="tc-gos-observability-slow-consumer-step-04"></a>
### Step 4: Confirm the listeners after the streams closed

Call a trivial method on both listeners again.

**Expected results:**

- Both answer.

## What this case does not prove

- It does not prove the timeout can be reached while a consumer is stalled. The
  timeout lives inside the same generator the consumer drives, so a reader that
  stops reading also stops the timeout advancing. Step 3 measures the timeout
  with an active reader and a silent source, which is the configuration in which
  it can fire; the stalled-reader case in Step 2 is bounded by the client
  closing the connection, not by this timeout.
- It does not prove anything about the Docker daemon's own log retention or
  rotation. The run-scoped containers cap their log files; what happens to log
  data the agent never read is Docker's business, not the agent's.
- On the `no-tee-dev` fixture the log source is a container on the control host
  rather than a workload inside a CVM. The route, the stream and the timeout are
  the same product code; the workload's isolation is not what this case
  measures.
- It does not bound the number of concurrent log streams the agent will accept.
  Ten is more than the worker count, not a limit probe.

## Postconditions

Remove both run-scoped containers. Retain the resident-memory and thread series
across the stall window, the bytes recovered on resume, and the measured
timeout: the series is what a reviewer compares across runs, and the assertion
alone does not show whether the margin was 1 MiB or 31.
