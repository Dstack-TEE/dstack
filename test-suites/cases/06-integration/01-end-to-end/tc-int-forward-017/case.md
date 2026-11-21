<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-int-forward-017"></a>
# TC-INT-FORWARD-017: Forward interval product regression matrix (#1555-#1589)

## Objective

Run the unit and integration tests that the product changes between the #841 base `9b87d9f9a6` and #1587 added for behavior an acceptance case cannot cheaply drive:

- launch tickets (#1577): the domain-separated ticket hash, the KMS denial that names a missing ticket, tickets sent to the auth API only as hashes, the dstack-auth ticket requirement, onboarding pinned to the root CA keys the auth API registers (HTTPS only, nothing sent to a source that fails the pin), the VMM work dir restricted to its owner, and `vmm-cli` sending and removing a ticket;
- the TDX lite OS check moved into `dstack-mr`, and `dstack-verifier-wasm` (#1555);
- the SEV-SNP hardware key provider (#1526): sealing policy, TCB comparison, disk initialization, metadata encoding, the CLI provider selection, and the VMM refusing the provider without SNP hardware;
- the PROXY protocol header reader (#1582) and the refusal of the old KMS and gateway listener settings (#1585, #1587).

## Expected results

Every row runs at least one test and none fails. A row whose filter matches no test fails the case, so a renamed or moved test is caught.

## Scope

Live behavior of these changes is covered by `tc-kms-kms-007` (KMS listeners, PROXY protocol, audit lines), `tc-gw-internal-009` (gateway listeners, PROXY protocol, admin audit and access lines) and `tc-kms-upgrade-008` (onboarding pinned to the registered root CA). Launch-ticket deployment on TDX hardware and SEV-SNP sealing on AMD hardware are not substituted by this matrix.
