<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-gw-proxy-prot-001"></a>
# TC-GW-PROXY-PROT-001: Inbound Proxy Protocol v1/v2 parsing

## Metadata

- Priority: P1
- Type: Functional, Security, Regression
- Minimum environment: INTEGRATION
- Automation: Yes
- Requirements: [req-gw-proxy-prot-001](../../../../catalog/feature-audit.md#req-gw-proxy-prot-001)
- Risks: [risk-gw-proxy-prot-001](../../../../catalog/feature-audit.md#risk-gw-proxy-prot-001)
- Source: `dstack/gateway/src/pp.rs`

## Prepared execution knowledge

- Read and obey [`shared/automation/execution-guide.md`](../../../../shared/automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.

## Objective

Verify inbound proxy protocol v1/v2 parsing across success, boundary, failure, security, and recovery conditions.

## Preconditions

1. The shared plan prerequisites are healthy and the target listener is reachable.
2. Commands use isolated test data and preserve native request and response output.

## Test Data

Use a unique run-scoped identifier and non-production credentials.

## Steps

<a id="tc-gw-proxy-prot-001-step-01"></a>
### Step 1: Inspect the effective prerequisite

Query the relevant health, configuration, and baseline state for inbound proxy protocol v1/v2 parsing.

**Expected results:**

- The target component is healthy, the intended listener and policy are effective, and the baseline contains no run-scoped test object.

<a id="tc-gw-proxy-prot-001-step-02"></a>
### Step 2: Exercise the behavior

Send valid IPv4/IPv6/UNKNOWN v1/v2 and truncated, oversized, slow, spoofed, and absent headers.

**Expected results:**

- Configured listeners preserve the authenticated source/destination; invalid headers fail within limits and untrusted paths cannot spoof identity.

<a id="tc-gw-proxy-prot-001-step-03"></a>
### Step 3: Verify state, isolation, and diagnostics

Re-query the public status/state interfaces, inspect component and peer logs, and repeat the request with one invalid or unauthorized input appropriate to this interface.

**Expected results:**

- Repeated observations match the method’s documented persistence, determinism, and idempotency semantics and remain scoped to the caller or run-scoped object; invalid or unauthorized input is rejected without secret disclosure, partial mutation, or loss of service availability.

## Post-baseline regression coverage (PR #1278)

- The `pp::tests` matrix has nine tests and must report `pp::tests::representative_v2_header_lengths_do_not_abort` and `pp::tests::a_v1_header_ending_on_a_bare_cr_does_not_abort` as passed by name: every v2 address family at lengths on both sides of the fixed-buffer cutoff, with the body absent, truncated and complete, and a v1 header ending on a bare CR, return an answer instead of reaching an unchecked advance that aborts a release build.

## Postconditions

Remove run-scoped objects and restore changed configuration. Preserve logs and responses in the result artifacts.
