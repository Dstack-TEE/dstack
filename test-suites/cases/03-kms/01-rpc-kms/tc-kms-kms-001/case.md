<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-kms-kms-001"></a>
# TC-KMS-KMS-001: KMS.GetAppKey

## Metadata

- Priority: P0
- Type: Functional, API, Security, Regression
- Minimum environment: INTEGRATION
- Automation: Yes
- Requirements: [req-kms-kms-001](../../../../catalog/feature-audit.md#req-kms-kms-001)
- Risks: [risk-kms-kms-001](../../../../catalog/feature-audit.md#risk-kms-kms-001)
- Source: `dstack/kms/rpc/proto/kms_rpc.proto:97`

## Prepared execution knowledge

- Read and obey [`shared/automation/execution-guide.md`](../../../../shared/automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Prepared RPC contract: `KMS.GetAppKey` takes `GetAppKeyRequest` (`api_version: uint32`, `vm_config: string`) and returns `AppKeyResponse` (`ca_cert: string`, `disk_crypt_key: bytes`, `env_crypt_key: bytes`, `k256_key: bytes`, `k256_signature: bytes`, `tproxy_app_id: string`, `gateway_app_id: string`, `os_image_hash: bytes`). The authoritative field matrix is the matching entry in [`api-inventory.json`](../../../../catalog/api-inventory.json); do not reconstruct it from implementation source.
- For the candidate guest-agent target, use `shared/automation/start-simulator.sh` and the recorded service socket/route, then `shared/automation/stop-simulator.sh`. Do not compile or design another simulator launcher.
- Exercise the case-prescribed absent/default/valid/boundary-invalid/unknown-field and JSON/protobuf representations with a checked-in helper when available. Keep secret response material in memory and record only structural checks, public material, and hashes.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.

- Positive protected-RPC rows require a client certificate carrying a cryptographically verifiable attestation bound to that certificate key. A simulator certificate with only the app-info extension is not an authenticated positive path, and rewriting a captured quote report-data field invalidates its signature. If the declared fixture exposes neither a hardware-attested client nor a mock-attestation client plus its matching explicitly enabled test trust anchors and collateral, record the positive rows as capability `BLOCKED` with the verifier error; do not grade that missing capability as product `FAIL`.

## Objective

Verify the complete request, response, authorization, state transition, and error contract of `KMS.GetAppKey`.

## Preconditions

1. The shared plan prerequisites are healthy and the target listener is reachable.
2. Commands use isolated test data and preserve native request and response output.

## Test Data

The `KMS.GetAppKey` entry in [`api-inventory.json`](../../../../catalog/api-inventory.json) is mandatory test data. Exercise every request field and every recursively referenced message field as absent/default, valid, boundary-invalid and combined with an unknown field; validate every response field, nested message field, and presence bit.

Use a unique run-scoped identifier and non-production credentials.

## Steps

<a id="tc-kms-kms-001-step-01"></a>
### Step 1: Inspect the effective prerequisite

Query the relevant health, configuration, and baseline state for kms.getappkey.

**Expected results:**

- The target component is healthy, the intended listener and policy are effective, and the baseline contains no run-scoped test object.

<a id="tc-kms-kms-001-step-02"></a>
### Step 2: Exercise the behavior

Invoke `KMS.GetAppKey` with a valid `GetAppKeyRequest` request using valid service-specific authentication and attestation context; capture the binary and JSON pRPC representations. Then send a schema-invalid request and, where protected, omit the credential.

**Expected results:**

- The valid call returns `AppKeyResponse` with every documented field and exhibits the documented `GetAppKey` state and side effects; invalid framing or fields return a structured error, and protected calls reject missing credentials.

<a id="tc-kms-kms-001-step-03"></a>
### Step 3: Verify state, isolation, and diagnostics

Re-query the public status/state interfaces, inspect component and peer logs, and repeat the request with one invalid or unauthorized input appropriate to this interface.

**Expected results:**

- Repeated observations match the method’s documented persistence, determinism, and idempotency semantics and remain scoped to the caller or run-scoped object; invalid or unauthorized input is rejected without secret disclosure, partial mutation, or loss of service availability.

## Postconditions

Remove run-scoped objects and restore changed configuration. Preserve logs and responses in the result artifacts.
