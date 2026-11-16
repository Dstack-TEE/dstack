<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-gos-concurrency-001"></a>
# TC-GOS-CONCURRENCY-001: Concurrent derivation determinism and per-call quote binding

## Metadata

- Priority: P0
- Type: Functional, Security, Robustness, Regression
- Minimum environment: SIMULATOR
- Automation: Yes
- Requirements: [req-gos-concurrency-001](../../../../catalog/feature-audit.md#req-gos-concurrency-001)
- Risks: [risk-gos-concurrency-001](../../../../catalog/feature-audit.md#risk-gos-concurrency-001)
- Source: `dstack/guest-agent/src/rpc_service.rs`, `dstack/guest-agent/src/rpc_service_v1.rs`, `dstack/dstack-attest/src/attestation.rs`

## Prepared execution knowledge

- Read and obey [`shared/automation/execution-guide.md`](../../../../shared/automation/execution-guide.md) before executing Step 1.
- The harness is [`shared/automation/guest-agent-robustness-case.py`](../../../../shared/automation/guest-agent-robustness-case.py).
- Keys are compared by SHA-256 digest; only digests reach the artifacts.

## Objective

Verify that concurrent identical derivations return identical keys and that
concurrent quotes each bind their own `report_data`. The per-method cases only
send one request at a time.

## Preconditions

1. The lease-owned agent's internal (`DstackGuest`) and legacy (`Tappd`)
   listeners are reachable.

## Test Data

- 24 concurrent calls per method (three times `workers = 8`), each on its own
  connection.
- A second derivation path and `DeriveKey` with `random_seed = true`, as
  controls that the comparison can tell keys apart.
- 24 distinct 64-byte `report_data` values.

## Steps

<a id="tc-gos-concurrency-001-step-01"></a>
### Step 1: Confirm the listeners before any load

Call `Version` on both listeners.

**Expected results:**

- Both listeners answer.

<a id="tc-gos-concurrency-001-step-02"></a>
### Step 2: Derive the same key from 24 connections at once

Send 24 concurrent identical `DstackGuest.GetKey`, `Tappd.DeriveK256Key` and
`Tappd.DeriveKey` (`random_seed = false`) requests, then the two controls.

**Expected results:**

- Every call returns HTTP 200.
- Each method's 24 responses carry one key digest. `GetKey` also carries one
  signature-chain digest. `DeriveKey` certificate chains are freshly issued and
  are not compared.
- A different path returns a different key, and 24 `random_seed = true`
  derivations return 24 distinct keys.

<a id="tc-gos-concurrency-001-step-03"></a>
### Step 3: Quote 24 distinct report-data values at once

Send 24 concurrent `DstackGuest.GetQuote` requests, each with its own
`report_data`.

**Expected results:**

- Every call returns HTTP 200.
- Each response echoes its own `report_data` and carries it at quote bytes
  568..632 (`TDX_QUOTE_REPORT_DATA_RANGE`).

## Postconditions

Nothing is created outside the lease. Keep the per-call digest table.
