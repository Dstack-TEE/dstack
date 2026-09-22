# RegisterCvm performance comparison

Date: 2026-09-20 UTC (2026-09-19 America/Los_Angeles).

## Revisions and conditions

- Before: `548ad0dad278c7e2af68607d0e3f7d01580d5685`, the existing committed
  routing-lock optimization. The unfinished local worker edits were not a
  buildable baseline. After: the working-tree changes accompanying this report.
- Both gateway binaries: Rust 1.92.0, `cargo build --release -p dstack-gateway`,
  default release optimization and `panic=abort`. Exact binary SHA-256 hashes,
  individual measurements, and machine settings are in
  [register-load-results.json](register-load-results.json).
- Shared cloud Linux host: Xeon Gold 6530, 32 physical cores / 64 threads,
  125 GiB RAM, kernel `6.8.0-1028-intel`. Gateway pinned to CPUs 0–7; independent
  load and probe processes to 8–15; origin to 16–19; simulator to 20–23.
  Affinity is not exclusive reservation. No agent-launched builds or other
  benchmarks overlapped these measurements.
- Isolated network namespace; actual kernel WireGuard interface `gwreg0` and
  successful real `wg syncconf`. Single gateway, 64 instances, `/25` client pool.
  Cluster sync, recycle, and authorization webhook disabled. WAL sync window
  remained the repository default, 5 seconds. The simulator supplied gateway
  identity; no real CVMs or tunnel data traffic were involved.
- Configured four RPC workers and four proxy workers; thread-per-core and
  connection rebalance enabled. The actual RPC runtime worker count was not
  verified: #1260 identifies that `#[rocket::main]` initializes the runtime before
  service-specific worker settings load. Both arms used identical CPU affinity. TCP splice and kTLS disabled. Disposable P-256 CA/client certificates,
  real AppInfo mTLS authentication on the normal `RegisterCvm` API. Proxy TLS 1.2.
- Registration: persistent connections, one outstanding request per client,
  no think time, concurrency 1/16/64. `repeat` keeps the same public key;
  `churn` changes it on every request. Health gating is off and an unrestricted
  port policy is explicitly supplied, excluding guest-agent prewarm traffic.
- `Info` and proxy probes use independent Python processes, a fresh TLS
  connection per request, and a sequential maximum rate of 50 requests/s each.
  Proxy SNI is `localhost-38404.gwtest.local`; `/bytes/1024` is checked byte-for-byte.
  This shortcut still takes the routing lock for its port-policy check, but
  bypasses real CVM selection and tunnel transport.
- Five conditions per run, 15 seconds requested per condition, three repetitions
  per binary. All 64 peers reset before each condition, followed by one second
  settling; apply counters include one second of post-load drain. Gateway
  restarted between runs; order: before/after, after/before, before/after.
  Data directories are separate per arm. Rates include final response/probe
  completion time. Values below are **medians of three per-run measurements**,
  not percentiles pooled across runs.

The scripts and reproduction steps are in [register-load.md](register-load.md).

## Registration throughput

| Condition / concurrency | Before, requests/s | After, requests/s | Ratio |
| --- | ---: | ---: | ---: |
| repeat / 1 | 147.5 | 1351.4 | 9.2x |
| repeat / 16 | 178.4 | 4055.4 | 22.7x |
| repeat / 64 | 176.9 | 3349.9 | 18.9x |
| churn / 64 | 132.8 | 4208.9 | 31.7x |

These are achieved rates of this closed-loop harness, not a maximum capacity
claim. In particular, the Python load generator can limit the optimized arm.

## Interference with other services

All latencies below include connection establishment and TLS handshake.

| Condition / concurrency | Info p99 before, ms | Info p99 after, ms | Proxy p99 before, ms | Proxy p99 after, ms |
| --- | ---: | ---: | ---: | ---: |
| idle / 0 | 8.23 | 6.90 | 10.91 | 7.32 |
| repeat / 1 | 21.47 | 7.22 | 18.53 | 7.49 |
| repeat / 16 | 350.67 | 9.13 | 186.37 | 8.01 |
| repeat / 64 | 1140.32 | 7.64 | 191.79 | 8.03 |
| churn / 64 | 1480.88 | 7.14 | 324.15 | 7.77 |

At concurrency 64 with unchanged keys, Info p99 fell **99.33%** and proxy p99
fell **95.81%**. With key churn, the reductions were **99.52%** and **97.60%**.

The probe counts matter: before, the unchanged-key concurrency-64 condition
completed only 23–27 Info probes and 154–188 proxy probes per run; after, it
completed 716–720 and 720–722, respectively. Before, a sequential probe was
unable to issue its next request while blocked. Consequently these p99 values
are **not open-loop latency guarantees**, and the baseline tails have relatively
few samples. The full data include counts, p50/p95/p99/max, durations, and errors.

Observed variation across the three runs, not statistical confidence intervals:

| Arm / condition / concurrency | Registration requests/s range | Info p99 range, ms |
| --- | ---: | ---: |
| before / repeat / 64 | 169.9–196.5 | 1026.33–1454.51 |
| before / churn / 64 | 126.3–140.4 | 1387.25–1998.58 |
| after / repeat / 64 | 3299.4–4185.7 | 7.42–14.92 |
| after / churn / 64 | 3867.5–4501.2 | 6.91–7.47 |

## Apply amplification and convergence

Median actual apply attempts per condition, including the post-load drain:

| Condition / concurrency | Before applies | After applies |
| --- | ---: | ---: |
| repeat / 1 | 2219 | 0 |
| repeat / 16 | 2487 | 0 |
| repeat / 64 | 2517 | 0 |
| churn / 64 | 2169 | 356 |

No-op registrations no longer rewrite the configuration or execute `wg`.
Under key churn, batching reduced absolute apply attempts by 83.6%, despite
handling 31.7 times as many registrations per second.

All 30 conditions passed final kernel peer-set verification: no acknowledged
last update was lost. The largest observed post-load convergence check was
54.36 ms, including invocation of `wg show`. This is **not per-registration
readiness latency**, and request/probe draining can hide convergence that
already occurred before the check.

There were **618,820 successful measured registrations, 15,461 successful Info
probes, and 16,611 verified proxy responses; zero request errors and zero apply
failures** in the performance runs. Warm-up/reset registrations are excluded.

## Why the old path interfered with service

1. **The routing mutex remained held during apply.** In the baseline,
   `self.lock().generate_wg_config().and_then(...)` retains its temporary
   `MutexGuard` until the complete statement ends. The closure therefore runs
   configuration file write/rename/fsync and `wg syncconf` fork/exec/wait while
   still holding the lock used by Info and proxy policy/routing lookup.
   The change puts rendering in a separate statement. A regression test pauses
   inside the apply callback and verifies that the routing lock is available.
2. **Repeated registrations repeated unnecessary full applies.** Even an
   unchanged instance/key requested rendering and application. The baseline's
   dirty flag only merges overlapping calls; it does not identify identical
   desired configurations. The counters above directly measure this
   amplification. The change skips unchanged registration peers, remembers only
   successfully applied configurations, and batches real changes using a
   capacity-one queue and a fixed 25 ms window.
3. **Synchronous work occupied RPC executor threads.** Awaiting neither the
   apply mutex nor the routing/KV work meant an async handler could block a
   Tokio worker. Merely moving the OS apply outside the routing lock does not
   fix executor starvation. The change executes registration state/KV work via
   `spawn_blocking`, gated by one asynchronously acquired semaphore permit.
   Additional registrations wait without parking RPC threads or submitting
   unbounded blocking jobs. The permit stays with a running job on cancellation.
4. **The dirty loop had no sustained-load bound or autonomous failure retry.**
   It could keep applying while callers dirtied it, and `wg syncconf` errors
   were logged as successful returns. Each new worker pass now applies one
   latest snapshot; updates during a pass retain a wakeup. Failed applies clear
   the success cache and retry after one second without requiring a new request.

These mechanisms are supported by code inspection, deterministic regression
tests, apply counters, and end-to-end measurements. This was not a factorial
ablation experiment; it does not assign an exact percentage of the gain to
fsync versus fork/exec or to each individual change.

## Regression and failure recovery

- `cargo test -p dstack-gateway --bin dstack-gateway`: **316 passed**, zero failed.
  Added coverage includes routing-lock release, deduplication, failed apply
  caching, burst coalescing, updates arriving during apply, retry without new
  requests, worker shutdown, removal retry, and registration cancellation.
- Separate real-kernel failure test, optimized binary, same namespace and 64
  peers: remove `gwreg0`, acknowledge one changed-key registration while it is
  missing, leave it missing for 1.2 seconds, then recreate it. Without another
  registration, all 64 expected peers recovered in **854.51 ms** after
  recreation. These deliberately failed applies are not included in the
  performance-run failure count.
- Rust formatting/diff checks and Python syntax checks pass.

## Behavioral tradeoffs and remaining limits

New/changed peers converge asynchronously: the registration response acknowledges
local state, not kernel readiness. The 25 ms batch window is not a hard readiness
bound. An immediate first WireGuard handshake can race the update and then wait
for the client's retransmission timer; this was not measured with a real CVM.
Startup and explicit operator removal still wait for one apply and propagate
errors. Apply failures are counted once and retried by the background worker.

The config cache does not detect external/manual edits to the kernel interface.
An unchanged registration will not repair such edits; restart or a changed
desired configuration causes reapplication. Interface loss followed by an
actual apply failure is covered by the recovery test above.

Routing-state rendering and KV work still take the routing mutex. There is no
claim of constant latency for much larger fleets, slow disks, enabled external
authorization, multi-node synchronization, or unlimited inbound requests.

## Supplemental synchronous-time attribution

A separate timing-instrumented release build of baseline `548ad0dad2` preserved
the original lock scopes and measured the synchronous `do_register_cvm` core.
Same host, affinity, gateway configuration and 64 initialized peers as above;
unchanged keys, concurrency 1 and 64, three 15-second runs each, **no probes**.
Percentages are shares of summed monotonic core wall time (including waits),
not CPU time or end-to-end RPC latency; instrumentation overhead is not subtracted.
There were 4,090 profiled requests at concurrency 1 and 6,088 at concurrency 64.

| Operation | Concurrency 1 | Concurrency 64 |
| --- | ---: | ---: |
| wg syncconf (spawn/exec/wait) | 61.53% | 9.10% |
| Config write/rename/fsync | 36.86% | 4.83% |
| State/KV work and rendering | 1.29% | 0.20% |
| Routing/apply mutex waits | 0.29% | 85.81% |
| Other/unclassified | 0.03% | 0.07% |

Excluding mutex waits, subprocess and config I/O together account for 98.1%
of the measured core wall time at concurrency 64. Raw spans and aggregation
are recorded under `synchronous_profile` in the companion JSON. These samples
are separate from the original before/after throughput experiment.
