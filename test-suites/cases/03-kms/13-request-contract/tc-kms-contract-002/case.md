<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-kms-contract-002"></a>
# TC-KMS-CONTRACT-002: Onboard request-contract matrix

## Metadata

- Priority: P0
- Type: Functional, API, Security, Robustness, Regression
- Minimum environment: INTEGRATION
- Automation: Yes
- Requirements: [req-kms-contract-002](../../../../catalog/feature-audit.md#req-kms-contract-002)
- Risks: [risk-kms-contract-002](../../../../catalog/feature-audit.md#risk-kms-contract-002)
- Source: [`catalog/api-inventory.json`](../../../../catalog/api-inventory.json), [`shared/automation/api-contract-matrix-policy.json`](../../../../shared/automation/api-contract-matrix-policy.json)

## Prepared execution knowledge

- Read and obey [`shared/automation/execution-guide.md`](../../../../shared/automation/execution-guide.md) before executing Step 1.
- Methods, request fields and field types come from `api-inventory.json`, not
  from implementation source.
- `api-contract-matrix-policy.json` sets how far each method is driven: `full`
  (effect confined to the lease), `rejection-only` (only inputs refused before
  dispatch) or `skip` (a valid call ends the process or consumes an external
  resource). A method without a policy fails the case.

## Objective

Verify that every `Onboard` method handles absent, valid, boundary-invalid,
wrong-typed, unknown-field and malformed-framing input, in JSON and protobuf,
without breaking the invariants below.

## Preconditions

1. The KMS onboarding listener is reachable on a lease-owned fixture. The matrix drives
   mutating methods with run-scoped identifiers, so it must never target a
   shared deployment.

## Test Data

The `kms` entries in `api-inventory.json` whose `service` is `Onboard`,
and the per-field, per-representation and per-method vectors in
[`api_contract_matrix.py`](../../../../shared/automation/api_contract_matrix.py) and
[`api-contract-matrix-case.py`](../../../../shared/automation/api-contract-matrix-case.py).

## Steps

<a id="tc-kms-contract-002-step-01"></a>
### Step 1: Resolve the listener and the indexed contract

Resolve the listener from the fixture and load the `Onboard` inventory entries.

**Expected results:**

- The listener is reachable and every declared method has a policy.

<a id="tc-kms-contract-002-step-02"></a>
### Step 2: Drive the matrix

Send every vector the policy allows, recording status, content type, body size
and elapsed time of each call.

**Expected results:**

- **L1** No request produces a 5xx, a dropped connection or a transport
  failure. Release builds use `panic = "abort"`, so a reachable panic aborts
  the process.
- **L2** A rejected JSON request gets a JSON `error` string; a rejected
  protobuf request gets a decodable `ProtoError`.
- **L4** No rejection echoes the unknown-field marker or grows with the size
  of the field it refused.
- **L5** No request exceeds the per-call deadline.
- **L6** A rejection's `Content-Type` matches the request's representation.

<a id="tc-kms-contract-002-step-03"></a>
### Step 3: Verify the listener survived

Send one valid request after the matrix.

**Expected results:**

- **L3** The listener answers it.

## Postconditions

Remove run-scoped objects the `full` policy created. Keep the per-call
observation table in the result artifacts.
