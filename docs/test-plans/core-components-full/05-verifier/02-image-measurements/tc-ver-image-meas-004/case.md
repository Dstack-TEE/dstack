<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-ver-image-meas-004"></a>
# TC-INT-IMAGE-MEAS-004: Artifact manifest and image hash binding

## Metadata

- Priority: P1
- Type: Functional, Security, Regression
- Minimum environment: UNIT
- Automation: Yes
- Requirements: [req-ver-image-meas-004](../../../feature-audit.md#req-ver-image-meas-004)
- Risks: [risk-ver-image-meas-004](../../../feature-audit.md#risk-ver-image-meas-004)
- Source: `os/spec/artifact-manifest.schema.json`

## Objective

Verify artifact manifest and image hash binding across success, boundary, failure, security, and recovery conditions.

## Preconditions

1. The shared plan prerequisites are healthy and the target listener is reachable.
2. Commands use isolated test data and preserve native request and response output.

## Test Data

Use a unique run-scoped identifier and non-production credentials.

## Steps

<a id="tc-ver-image-meas-004-step-01"></a>
### Step 1: Inspect the effective prerequisite

Query the relevant health, configuration, and baseline state for artifact manifest and image hash binding.

**Expected results:**

- The target component is healthy, the intended listener and policy are effective, and the baseline contains no run-scoped test object.

<a id="tc-ver-image-meas-004-step-02"></a>
### Step 2: Exercise the behavior

Verify artifact manifest schema, component digests, authenticode hash, image hash, and missing/extra artifacts.

**Expected results:**

- Only schema-valid complete manifests whose component and aggregate hashes match are accepted.

<a id="tc-ver-image-meas-004-step-03"></a>
### Step 3: Verify state, isolation, and diagnostics

Re-query the public status/state interfaces, inspect component and peer logs, and repeat the request with one invalid or unauthorized input appropriate to this interface.

**Expected results:**

- Repeated observations match the method’s documented persistence, determinism, and idempotency semantics and remain scoped to the caller or run-scoped object; invalid or unauthorized input is rejected without secret disclosure, partial mutation, or loss of service availability.

## Postconditions

Remove run-scoped objects and restore changed configuration. Preserve logs and responses in the result artifacts.
