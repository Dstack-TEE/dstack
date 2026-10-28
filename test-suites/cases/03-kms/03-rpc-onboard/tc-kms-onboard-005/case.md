<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-kms-onboard-005"></a>
# TC-KMS-ONBOARD-005: Admin-listener KMS key handover

## Metadata

- Priority: P1
- Type: Functional, API, Security, Regression
- Minimum environment: INTEGRATION
- Automation: Yes
- Requirements: [req-kms-onboard-005](../../../../catalog/feature-audit.md#req-kms-onboard-005)
- Risks: [risk-kms-onboard-005](../../../../catalog/feature-audit.md#risk-kms-onboard-005)
- Source: `dstack/kms/rpc/proto/kms_rpc.proto:138`, `dstack/kms/src/admin_service.rs`, `dstack/kms/src/main_service.rs`, `dstack/kms/src/onboard_service.rs`

## Prepared execution knowledge

- Read and obey [`shared/automation/execution-guide.md`](../../../../shared/automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- The `kms-onboard` fixture provides a bootstrapped source KMS (`values.kms`, with its admin listener and token file), an attested simulator client (`values.kms_attested_client`), and a clean onboarding target whose configuration is the template for a third, case-owned target on the unused substrate ports `verifier` (RPC), `aux4` (onboarding), and `vmm` (admin).
- PR #1307 added `Admin.GetKmsKey`, optional `[core.admin.tls]` (which makes the admin listener accept RA-TLS client certificates), `core.onboard.public_key_handover` (default `true`), and `OnboardRequest.source_token`, which the onboarding client sends as `Authorization: Bearer`.
- With `source_token`, the target mints a self-issued RA-TLS client certificate and calls `Admin.GetKmsKey` with the bearer token; it does not call `GetTempCaCert`. Before PR #1406, onboarding with a token failed with `Service not found: GetTempCaCert`.
- Keep key responses in memory. Record status codes, bounded redacted errors, and fingerprint or public-key equality only.

## Objective

Verify that root-key handover can be moved to the admin listener: `Admin.GetKmsKey` requires both the admin bearer token and an attested client certificate, other admin RPCs do not require a client certificate, `public_key_handover = false` refuses the public `KMS.GetKmsKey`, and a new KMS onboards through the admin listener with `source_token`.

## Preconditions

1. The `kms-onboard` fixture is healthy and its source KMS serves the public and admin listeners.
2. The case may restart the lease-owned source KMS and start one more lease-owned target.

## Test Data

A run-scoped onboarding domain `<lease>.admin-onboard.test`, the fixture admin token, and the simulator-attested client identity and `vm_config`.

## Steps

<a id="tc-kms-onboard-005-step-01"></a>
### Step 1: Record the default public handover

With the fixture configuration (no `public_key_handover` key), call `KMS.GetKmsKey` on the public listener with the attested client, and read `KMS.GetMeta.k256_pubkey`.

**Expected results:**

- HTTP 200 with exactly one key entry; its fingerprint is the baseline root key. The default keeps public handover on for rolling upgrades.

<a id="tc-kms-onboard-005-step-02"></a>
### Step 2: Move handover to the admin listener

Restart the source with `[core.onboard] public_key_handover = false` and `[core.admin.tls]` using its own RPC key and certificate. Call `KMS.GetKmsKey` on the public listener, then `Admin.GetKmsKey` over HTTPS with the token and client certificate, with the token only, and with the certificate only. Call `Admin.ClearImageCache` with the token and no client certificate.

**Expected results:**

- Public `KMS.GetKmsKey` fails with `public KMS key handover is disabled; use the admin listener`.
- `Admin.GetKmsKey` with token and certificate returns HTTP 200 and the same root-key fingerprint as Step 1.
- Without a client certificate it fails; without the token it returns HTTP 401.
- `Admin.ClearImageCache` succeeds without a client certificate.

<a id="tc-kms-onboard-005-step-03"></a>
### Step 3: Onboard a new KMS through the admin listener

Start a third target in onboarding mode. Call `Onboard.Onboard` with the public source URL, then with the admin source URL and no `source_token`, then with the admin source URL and the admin token as `source_token`.

**Expected results:**

- The first two requests fail and the target writes no root key.
- The third returns HTTP 200 with `k256_pubkey` equal to the source's `GetMeta.k256_pubkey`, and the target holds both root keys.
- The admin token does not appear in either KMS log.

## Postconditions

Stop the restarted source and the third target, and restore the source configuration file. The fixture destroys the remaining lease state.
