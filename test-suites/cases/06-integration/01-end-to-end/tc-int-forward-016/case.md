<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-int-forward-016"></a>
# TC-INT-FORWARD-016: Forward interval product regression matrix

## Objective

Exercise the non-rotation product changes between the #841 fork point and #1534: NUMA and extra-root-device measurement, VM annotations, passt/QMP behavior, guest route and container-name validation, RA-TLS key possession, verifier parsing, TPM response bounds, and SDK compose-hash parity.

## Expected results

Every selected package and test filter passes. Invalid routes, names, topology, parser input, and TPM responses fail closed; valid annotations, layouts, passt/QMP behavior, attestation fields, and SDK hashes remain compatible. A zero-test result is a failure.

## Scope

The case is a deterministic regression matrix. Live TDX deployment, GPU hardware, and external auth services are covered by the existing physical and integration cases and are not substituted by this matrix.
