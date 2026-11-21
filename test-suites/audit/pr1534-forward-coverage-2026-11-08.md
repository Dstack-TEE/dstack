<!-- SPDX-License-Identifier: Apache-2.0 -->
# Forward coverage audit for #841 onto #1534

The product interval starts at `0fb3b24bbd` and ends at #1534. It contains 261 commits and changes across KMS, auth backends, guest OS, VMM, SDKs, RA-TLS, verifier, build images, and test infrastructure.

The acceptance suite maps the interval as follows:

- KMS key lifecycle: `tc-kms-rotation-013` covers Rust keyring, registration, activation, handover, restart, historical epochs, disk epoch migration, authorization selection, and SealedEnv binding.
- On-chain lifecycle: `tc-kms-rotation-014` covers root/app epoch rows, chain hashes, activation boundaries, pending removal, evidence, owner checks, stale selectors, and upgrade compatibility.
- Auth backends: `tc-kms-rotation-015` runs auth-simple, auth-mock, auth-eth-bun, and auth-eth test suites for operation- and epoch-scoped decisions.
- Existing KMS upgrade, onboarding, mixed-version, attestation, and authorization cases remain in the plan and are reviewed against the new epoch semantics.
- Existing VMM, guest, SDK, RA-TLS, verifier, and integration cases remain the coverage for their corresponding interval changes; cases whose source contracts changed are updated through the #1534 rebase and registry validation.

The rotation group is promoted only after the focused matrix passes. Unit and contract rows must be complemented by a physical tdxlab run of the rotation cases before claiming end-to-end deployment coverage.
