<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-gos-boot-and-i-004"></a>
# TC-GOS-BOOT-AND-I-004: Stable app, instance, device, and compose identity

## Metadata

- Priority: P0
- Type: Functional, Security, Regression
- Minimum environment: HARDWARE
- Automation: Yes
- Requirements: [req-gos-boot-and-i-004](../../../../catalog/feature-audit.md#req-gos-boot-and-i-004)
- Risks: [risk-gos-boot-and-i-004](../../../../catalog/feature-audit.md#risk-gos-boot-and-i-004)
- Sources: `dstack/dstack-util/src/system_setup.rs:2538-2637`,
  `dstack/guest-agent/src/guest_api_service.rs:37-51`

## Prepared execution knowledge

- Read and obey [`shared/automation/execution-guide.md`](../../../../shared/automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the manifest's case-scoped `identity_matrix` guests and their
  `vmm_vm_id` values. The matrix must include two identical-input guests plus
  one guest for each independently changed compose, image, and instance input.
  A single shared candidate guest can prove only the read-only stability
  subset; without the full matrix this case is BLOCKED, not failed. The VMM proxy
  call is JSON pRPC `POST <component_endpoints.vmm_guest_api>/Info` with
  `{"id":"<vmm_vm_id>"}`. The `Id.id` value is the VMM VM UUID, not the
  cryptographic instance ID returned by the guest.
- Invoke `Info` twice for each matrix member. Persist only `version`, the public `app_id`,
  `instance_id`, and `device_id`, plus SHA-256 hashes and lengths of
  `app_cert`/`tcb_info`; do not save the full certificate, quote, event log, or
  application configuration. Require the two redacted projections to be
  identical and each returned instance ID to match its manifest-recorded public
  `instance_id`. Transiently parse `tcb_info` to compare its image, compose, and
  device identity fields, but persist only the redacted whole-document hash and
  the resulting relation booleans. The whole `tcb_info` document is
  instance-bound through its event log, so it is not expected to be byte-equal
  across distinct VM instances. Compare the complete matrix against its
  recorded expected identity/measurement relations; repeated calls to one VM
  do not substitute for the changed-input rows.
- Use a unique nonexistent UUID for the negative request and require a
  structured non-2xx `vm not found` response. Re-query the valid VM afterward
  to prove rejection did not mutate identity or availability. This case is
  read-only; do not restart or shut down the guest.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.

## Objective

Verify stable app, instance, device, and compose identity across success, boundary, failure, security, and recovery conditions.

## Preconditions

1. The runtime manifest contains a dedicated `identity_matrix` with two
   identical-input guests and independently changed compose, image, and
   instance rows. All rows use non-production credentials and are already
   booted, so testing them requires no lifecycle action on a shared guest.
2. The candidate VMM proxy is healthy and every matrix VM ID resolves to its
   intended guest. If the matrix is absent or incomplete, report BLOCKED.
3. Commands use isolated test data and preserve native request and response output.

## Test Data

Use a unique run-scoped identifier and non-production credentials.

## Steps

<a id="tc-gos-boot-and-i-004-step-01"></a>
### Step 1: Inspect the effective prerequisite

Query the relevant health, configuration, and baseline state for stable app, instance, device, and compose identity.

**Expected results:**

- The target component is healthy, the intended listener and policy are effective, and the baseline contains no run-scoped test object.

<a id="tc-gos-boot-and-i-004-step-02"></a>
### Step 2: Exercise the behavior

Boot identical and changed compose/image/instance combinations.

**Expected results:**

- Stable inputs reproduce their identifiers; changing each bound input changes only the identifiers and measurements defined by the identity model.

<a id="tc-gos-boot-and-i-004-step-03"></a>
### Step 3: Verify state, isolation, and diagnostics

Re-query the public status/state interfaces, inspect component and peer logs, and repeat the request with one invalid or unauthorized input appropriate to this interface.

**Expected results:**

- Repeated observations match the method’s documented persistence, determinism, and idempotency semantics and remain scoped to the caller or run-scoped object; invalid or unauthorized input is rejected without secret disclosure, partial mutation, or loss of service availability.

## Postconditions

Remove run-scoped objects and restore changed configuration. Preserve logs and responses in the result artifacts.
