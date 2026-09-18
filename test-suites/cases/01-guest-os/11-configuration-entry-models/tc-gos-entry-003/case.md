<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-gos-entry-003"></a>
# TC-GOS-ENTRY-003: Dashboard and metrics model escaping and units

## Metadata

- Priority: P1
- Type: Functional, Security, Regression
- Minimum environment: SIMULATOR
- Automation: Yes
- Requirements: [req-gos-entry-003](../../../../catalog/feature-audit.md#req-gos-entry-003)
- Risks: [risk-gos-entry-003](../../../../catalog/feature-audit.md#risk-gos-entry-003)
- Source: `dstack/guest-agent/src/models.rs`

## Prepared execution knowledge

- Read and obey [`shared/automation/execution-guide.md`](../../../../shared/automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.

## Objective

Verify dashboard and metrics model escaping and units exactly matches the source-defined behavior across normal, boundary, concurrent, failure, and restart paths.

## Preconditions

1. Use the checked-in deterministic render harness against the exact candidate `models.rs`, `dashboard.html`, and `metrics.tpl` files.
2. Do not retain rendered hostile text; retain only assertion booleans, lengths, and hashes.

## Test Data

Use HTML metacharacters, Prometheus label quotes/backslashes/newlines, Unicode, empty optional container names, 0/1023/1024/maximum integer values, and 256 disk records.

## Steps

<a id="tc-gos-entry-003-step-01"></a>
### Step 1: Record effective inputs and baseline

Copy the exact candidate model source and templates into an isolated temporary probe crate.

**Expected results:**

- The probe uses the candidate `guest-api` types and exact candidate templates without changing the component workspace.

<a id="tc-gos-entry-003-step-02"></a>
### Step 2: Exercise behavior and boundaries

Render dashboard and metrics with the deterministic hostile strings, boundary counters, optional names, and high-cardinality disk list.

**Expected results:**

- HTML text and attribute contexts are escaped, Prometheus label quotes/backslashes/newlines are escaped, hex and optional names render correctly, numeric metrics remain exact, human-readable sizes cross 1024 correctly, and every bounded synthetic disk record renders.

<a id="tc-gos-entry-003-step-03"></a>
### Step 3: Inject failure and concurrency

Render the immutable presentation model concurrently and compare successful completion and stable output characteristics, then remove the temporary probe.

**Expected results:**

- Concurrent renders complete without panic or shared-state corruption, and the temporary probe is removed automatically.

<a id="tc-gos-entry-003-step-04"></a>
## Post-baseline regression coverage (commits 7894bb5e25, 85cc6bef92, b6efabe754, 955add3057, and 9f299d3e7e)

The render probe in `shared/automation/dashboard-model-case.py` now passes `gpu_info` to both templates and requires:

- `load_average_unscaled`: `loadavg_*` values 40/100/1234 render as `0.40`/`1.00`/`12.34` in `dstack_guest_load*` and the deprecated `system_load_average_*` series, and the dashboard shows `1min: 0.40, 5min: 1.00, 15min: 12.34` without a `%` suffix.
- `uptime_units`: uptime 90061 renders `1d 1h 1m 1s` on the dashboard while `dstack_guest_uptime_seconds` keeps the raw `90061`.
- `gpu_labels_escaped`: a hostile GPU UUID is escaped in `dstack_gpu_*` labels and the full UUID and PCI bus ID are kept in metrics.
- `gpu_optional_series`: an unset optional GPU field emits no series while `Some(0)` emits `0`; `dstack_gpu_cc_enabled` is emitted only when set, `dstack_gpu_cc_ready` is absent when unset, and a 60 s sample yields `dstack_gpu_sample_age_seconds 60`.
- `gpu_errors_counted`: `dstack_gpu_query_errors` counts list entries, so an error message containing `; ` still counts once.
- `gpu_dashboard_rows`: the dashboard renders power as `70.1 W`, drops only a zero PCI domain (`01:00.0`, but `00010000:02:00.0` kept), shows unset CC state as `unknown`, shows the sample age as `60.0 s`, and does not render the UUID.
- `gpu_absent_and_failed_states`: the no-GPU response renders `No NVIDIA GPUs` and `dstack_gpu_nvml_up 1` with no device series; an error response renders the escaped error instead of the table and `dstack_gpu_nvml_up 0`.

## Postconditions

The temporary probe is removed and the report retains no raw hostile rendered page or credential material.
