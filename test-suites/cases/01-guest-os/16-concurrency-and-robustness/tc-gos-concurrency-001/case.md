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
  It reads the lease-owned listeners out of the case manifest and never
  hard-codes a socket path.
- Key material never leaves the agent: every equality this case asserts is
  asserted over a SHA-256 digest, and only digests reach the artifacts.
- `TDX_QUOTE_REPORT_DATA_RANGE` in `dstack/dstack-attest/src/attestation.rs` is
  `568..632`. That offset, not a substring search, is where the quote's report
  data is read from.

## Objective

Verify that the guest agent's derivation and quote surfaces are pure functions
of their arguments when many callers arrive at once: that N concurrent
identical `GetKey`, `DeriveK256Key` and `DeriveKey` calls return byte-identical
key material, and that N concurrent `GetQuote` calls each bind the caller's own
`report_data` rather than another caller's.

The existing per-method cases send one request at a time, and the chapter's
only concurrency coverage is in-process Rust thread pools over parsers plus one
concurrent-startup case. Nothing drives the live agent with more than one
request in flight, so a shared buffer, a reused report-data slot or a
derivation that quietly depends on request order would be invisible to the
suite. Derived keys are the root of every application secret and `report_data`
is the whole content of a quote's binding, so both are worth asserting
directly.

## Preconditions

1. The shared plan prerequisites are healthy and the lease-owned guest agent's
   internal (`DstackGuest`) and legacy (`Tappd`) listeners are reachable.
2. The fixture is lease-owned. The case derives under run-scoped paths only and
   creates no external object.

## Test Data

- 24 concurrent calls per method — three times the agent's `workers = 8`
  (`dstack/guest-agent/dstack.toml`), so the load exceeds the runtime's width.
- One identical request body per method, replayed by every thread on its own
  connection.
- A second derivation path, as the control that "identical" is not "constant".
- `DeriveKey` with `random_seed = true`, as the control that the harness can
  tell distinct keys apart at all.
- 24 distinct 64-byte `report_data` values, each prefixed with its own index.

## Steps

<a id="tc-gos-concurrency-001-step-01"></a>
### Step 1: Confirm the listeners before any load

Resolve the lease-owned `DstackGuest` and `Tappd` listeners and call `Version`
on each.

**Expected results:**

- Both listeners answer. A later failure is then a consequence of the load and
  not of a fixture that was never healthy.

<a id="tc-gos-concurrency-001-step-02"></a>
### Step 2: Derive the same key from 24 connections at once

Send 24 concurrent identical `DstackGuest.GetKey` requests, then 24 concurrent
identical `Tappd.DeriveK256Key` requests, then 24 concurrent identical
`Tappd.DeriveKey` requests with `random_seed = false`. Follow them with the two
controls.

**Expected results:**

- Every call is answered with HTTP 200.
- The 24 `GetKey` responses carry one distinct key digest and one distinct
  signature-chain digest between them.
- The 24 `DeriveK256Key` responses carry one distinct key digest.
- The 24 `DeriveKey` responses carry one distinct key digest. Their certificate
  chains are **not** asserted identical and are expected to differ: `derive_key`
  in `rpc_service.rs` derives the P-256 key from the app root key and the path,
  then issues a fresh certificate over it. Only the key is a pure function of
  the request.
- A different derivation path returns a different key, so the equalities above
  are not satisfied by a constant answer.
- 24 concurrent `random_seed = true` derivations return 24 distinct keys, so the
  harness demonstrably distinguishes keys it is asked to distinguish.

<a id="tc-gos-concurrency-001-step-03"></a>
### Step 3: Quote 24 distinct report-data values at once

Send 24 concurrent `DstackGuest.GetQuote` requests, each with its own 64-byte
`report_data`.

**Expected results:**

- Every call is answered with HTTP 200.
- Each response's `report_data` field equals the value that request sent.
- Each response's quote carries that same value at bytes 568..632.
- No two responses share a quote, so the agent is not serving one cached quote
  to every caller.

## What this case does not prove

- It does not prove the quote is hardware evidence. Under the `no-tee-dev`
  fixture the platform backend patches a recorded fixture attestation, so this
  case proves the agent binds the caller's report data into the response it
  builds — not that a TDX module signed it. Quote authenticity is the
  attestation chapter's subject.
- It does not prove the derived key is the key the KMS would hand out. It
  proves the agent's derivation is stable under concurrency.
- It says nothing about latency or fairness; that is
  [tc-gos-concurrency-002](../tc-gos-concurrency-002/case.md#tc-gos-concurrency-002).

## Postconditions

Nothing run-scoped is created outside the lease. Retain the per-call digest
table: it is the evidence that 24 calls really were compared, and a reviewer
comparing runs reads it rather than the assertion.
