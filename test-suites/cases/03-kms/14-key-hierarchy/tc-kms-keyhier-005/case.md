<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-kms-keyhier-005"></a>
# TC-KMS-KEYHIER-005: Concurrent GetAppKey for one attested identity

## Metadata

- Priority: P0
- Type: Functional, Security, Concurrency, Regression
- Minimum environment: INTEGRATION
- Automation: Yes
- Requirements: [req-kms-keyhier-005](../../../../catalog/feature-audit.md#req-kms-keyhier-005)
- Risks: [risk-kms-keyhier-005](../../../../catalog/feature-audit.md#risk-kms-keyhier-005)
- Source: `dstack/kms/src/main_service.rs:356` (`get_app_key`)

## Prepared execution knowledge

- Read and obey [`shared/automation/execution-guide.md`](../../../../shared/automation/execution-guide.md) before executing Step 1.
- Every existing `GetAppKey` case issues one request at a time. A KMS serving
  many CVMs answers them in parallel, and `get_app_key` runs a full attestation
  verification, three key derivations and a signature per request.
- The calls are released from a barrier so they are actually in flight at the
  same time rather than merely issued in a loop.

## Objective

Verify that eight concurrent `KMS.GetAppKey` calls from one attested identity
return byte-identical derived material, matching the material a sequential call
returns.

Determinism proven one request at a time is not determinism under load. A
cache keyed on the wrong thing, a shared buffer, or a derivation reading
mutable state would show up here and nowhere else — and the failure mode is an
application receiving another request's key, which no client can detect.

## Preconditions

1. The shared plan prerequisites are healthy and the lease-owned KMS answers
   `KMS.GetMeta`.
2. The fixture declares an attested client identity.

## Test Data

One sequential baseline response, then eight concurrent requests carrying the
identical `api_version` and `vm_config`.

## Steps

<a id="tc-kms-keyhier-005-step-01"></a>
### Step 1: Self-test the primitives and the listener

Check the harness's primitives against their golden vectors and read
`KMS.GetMeta`.

**Expected results:**

- Every golden vector matches and the KMS answers with its public identity.

<a id="tc-kms-keyhier-005-step-02"></a>
### Step 2: Take a baseline, then release eight calls at once

Call `KMS.GetAppKey` once, then issue eight identical calls released together
from a barrier.

**Expected results:**

- Every call returns HTTP 200. None times out, is refused, or returns a
  transport error: a service that serialises badly under concurrency fails
  here before any comparison happens.

<a id="tc-kms-keyhier-005-step-03"></a>
### Step 3: Compare every response

Compare each concurrent response with the sequential baseline, field by field,
and hash the whole response bodies.

**Expected results:**

- `disk_crypt_key`, `env_crypt_key`, `k256_key`, `k256_signature` and
  `os_image_hash` match the baseline in every response.
- `ca_cert` matches the baseline in every response.
- All eight response bodies hash to a single value, so no response differed in
  any field at all.

## Postconditions

No state is created. The artifacts record the single response digest, the
per-call latencies and SHA-256 digests of the derived secrets.

What this case does **not** establish:

- Eight concurrent requests is a correctness probe, not a load test. It does
  not characterise throughput, queueing or resource exhaustion; those belong to
  the integration failure and backpressure cases.
- It uses one attested identity, so it cannot detect cross-*identity*
  contamination. That needs the second attested identity the fixture does not
  provide; see the separation matrix in
  [tc-kms-keyhier-002](../tc-kms-keyhier-002/case.md#tc-kms-keyhier-002).
  [tc-kms-keyhier-006](../tc-kms-keyhier-006/case.md#tc-kms-keyhier-006)
  covers the one request-scoped input that *can* be varied per call.
