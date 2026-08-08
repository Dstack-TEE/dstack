<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-gos-observabil-001"></a>
# TC-GOS-OBSERVABIL-001: Dashboard metrics and container log filtering

## Metadata

- Priority: P1
- Type: Functional, Security, Regression
- Minimum environment: SIMULATOR
- Automation: Yes
- Requirements: [req-gos-observabil-001](../../../feature-audit.md#req-gos-observabil-001)
- Risks: [risk-gos-observabil-001](../../../feature-audit.md#risk-gos-observabil-001)
- Source: `dstack/guest-agent/src/http_routes.rs`

## Prepared execution knowledge

- Read and obey [`automation/execution-guide.md`](../../../automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Before creating the timestamped log fixture, require the bootstrap-prepared `ubuntu:latest` image and probe its `sh` entrypoint. Do not reuse the first running service image: current service images may intentionally be shell-free.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.
- The external HTTP listener exposes `GET /` unconditionally. It exposes
  `GET /metrics` only when `app_compose.public_sysinfo=true`, and exposes
  `GET /logs/<container_name>` only when `app_compose.public_logs=true`.
  Its repository default is TCP `0.0.0.0:8090`; obtain an override from the
  effective guest-agent configuration. `/run/dstack.sock` is the internal
  DstackGuest pRPC listener and must not be used for dashboard, metrics, or log
  HTTP probes (a `GET /` there can legitimately return Rocket HTTP 422).
- The log query fields are `since`, `until`, `follow`, `text`, `timestamps`,
  `bare`, `tail`, and `ansi`. `since`/`until` accept an absolute decimal Unix
  timestamp, an empty value for zero, or a relative unsigned value ending in
  `s`, `m`, `h`, or `d`; malformed values return a JSON error line. The default
  tail is `1000`. Unless `text=true`, message data is Base64. With
  `bare=true,text=true,ansi=false`, ANSI escapes are removed; `ansi=true`
  preserves them. Non-bare output is newline-delimited JSON containing
  `channel` and `message`.
- A positive log-filtering matrix requires an isolated container whose stdout
  and stderr contain run-unique timestamped plain-text and ANSI fixtures. An
  already-running shared container without those known fixtures cannot confirm
  exact since/until/tail/channel boundaries and is not a substitute.
- Respect `destructive_actions_allowed` from the runtime manifest. When it is
  false, do not run `docker run`, `docker rm`, or create temporary files inside
  that shared guest. If no separate case-scoped guest/container fixture is
  declared, retain one bounded baseline observation and report the positive log
  matrix BLOCKED. The presence of a cached container image does not grant
  permission to mutate a shared guest.

## Objective

Verify dashboard metrics and container log filtering across success, boundary, failure, security, and recovery conditions.

## Preconditions

1. The shared plan prerequisites are healthy and the target listener is reachable.
2. Commands use isolated test data and preserve native request and response output.

## Test Data

Use a unique run-scoped identifier and non-production credentials.

## Steps

<a id="tc-gos-observabil-001-step-01"></a>
### Step 1: Inspect the effective prerequisite

Query the relevant health, configuration, and baseline state for dashboard metrics and container log filtering.

**Expected results:**

- The target component is healthy, the intended listener and policy are effective, and the baseline contains no run-scoped test object.

<a id="tc-gos-observabil-001-step-02"></a>
### Step 2: Exercise the behavior

Query dashboard, metrics, and logs with since/until/follow/tail/text/timestamps/bare/ANSI combinations.

**Expected results:**

- Metrics reflect live resources; log filtering and streaming boundaries are exact and container-name traversal is rejected.

<a id="tc-gos-observabil-001-step-03"></a>
### Step 3: Verify state, isolation, and diagnostics

Re-query the public status/state interfaces, inspect component and peer logs, and repeat the request with one invalid or unauthorized input appropriate to this interface.

**Expected results:**

- Repeated observations match the method’s documented persistence, determinism, and idempotency semantics and remain scoped to the caller or run-scoped object; invalid or unauthorized input is rejected without secret disclosure, partial mutation, or loss of service availability.

## Postconditions

Remove run-scoped objects and restore changed configuration. Preserve logs and responses in the result artifacts.
