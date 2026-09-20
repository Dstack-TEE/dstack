<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-kms-keyhier-006"></a>
# TC-KMS-KEYHIER-006: Concurrent GetAppKey across distinct image hashes

## Metadata

- Priority: P0
- Type: Functional, Security, Concurrency, Regression
- Minimum environment: INTEGRATION
- Automation: Yes
- Requirements: [req-kms-keyhier-006](../../../../catalog/feature-audit.md#req-kms-keyhier-006)
- Risks: [risk-kms-keyhier-006](../../../../catalog/feature-audit.md#risk-kms-keyhier-006)
- Source: `dstack/kms/src/main_service.rs:356` (`get_app_key`), `dstack/dstack-attest/src/attestation.rs:918` (`decode_app_info_ex`)

## Prepared execution knowledge

- Read and obey [`shared/automation/execution-guide.md`](../../../../shared/automation/execution-guide.md) before executing Step 1.
- `os_image_hash` is the one field of `GetAppKeyRequest.vm_config` that is
  per-request and caller-supplied: `decode_app_info_ex` reads it from the
  external `vm_config` and it flows into `BootInfo` and back out in
  `AppKeyResponse.os_image_hash`. It is not one of the derivation inputs.
- The lease's KMS runs with `[core.image] verify = false`, which the fixture
  provider sets in `write_kms_config`. Read the Postconditions before quoting
  this case as evidence about image verification.

## Objective

Verify that eight concurrent `KMS.GetAppKey` calls carrying eight distinct,
never-before-seen `os_image_hash` values each receive an answer for their own
image hash, and that the derived key material does not vary with it.

Two failures hide here and nowhere else. A response routed to the wrong
concurrent caller would hand one CVM another CVM's answer. And a per-request
value leaking into a derivation — or into a cache key shared across
requests — would make a key depend on something outside its documented
context, which is the same class of defect as a non-deterministic derivation,
only harder to reproduce.

## Preconditions

1. The shared plan prerequisites are healthy and the lease-owned KMS answers
   `KMS.GetMeta`.
2. The fixture declares an attested client identity whose `vm_config` contains
   an `os_image_hash`.

## Test Data

Eight copies of the fixture's `vm_config` with `os_image_hash` replaced by
`sha256("dstack-test-keyhier-image-<n>")` for `n` in 0..7. The other fields are
left untouched, so the only thing that varies between the concurrent requests
is the one field under test.

## Steps

<a id="tc-kms-keyhier-006-step-01"></a>
### Step 1: Self-test the primitives and the listener

Check the harness's primitives against their golden vectors and read
`KMS.GetMeta`.

**Expected results:**

- Every golden vector matches and the KMS answers with its public identity.

<a id="tc-kms-keyhier-006-step-02"></a>
### Step 2: Release eight calls with eight distinct image hashes

Build the eight request bodies, confirm the eight hashes are distinct, and
release the calls together from a barrier.

**Expected results:**

- Every call returns HTTP 200. An uncached image hash produces no spurious
  measurement or authorization failure, and eight of them arriving at once
  produce none either.

<a id="tc-kms-keyhier-006-step-03"></a>
### Step 3: Check each answer belongs to its own request

Compare each response's `os_image_hash` with the value its own request
carried, and compare the derived material across all eight.

**Expected results:**

- Every response echoes exactly the `os_image_hash` its own request carried, so
  no response was served to the wrong concurrent caller.
- `disk_crypt_key`, `env_crypt_key` and `k256_key` are identical across all
  eight responses: the derivation contexts are `app_id`, `instance_id` and the
  fixed domain strings, and the image hash is not among them.

## Postconditions

No state is created. The artifacts record the requested and echoed image
hashes and SHA-256 digests of the derived material.

What this case does **not** establish:

- **It does not exercise image verification.** The lease's KMS sets
  `[core.image] verify = false`, so `verify_os_image_hash` returns early and no
  image archive is downloaded or measured. The case proves request/response
  isolation and that the derivation ignores the image hash; it does not prove
  anything about the verifier path, its cache, or its behaviour on an unknown
  image. A case for that needs a fixture whose KMS runs with `verify = true`
  and a reachable image download source.
- The lease's authorization backend is `[core.auth_api] type = "dev"`, which
  allows every boot. Whether a *whitelist* accepts an unknown image hash is an
  authorization-implementation case, not this one.
- Eight concurrent requests is a correctness probe, not a load test.
