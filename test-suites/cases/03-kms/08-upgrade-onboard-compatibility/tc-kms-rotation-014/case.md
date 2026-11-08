<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-kms-rotation-014"></a>
# TC-KMS-ROTATION-014: On-chain root and app epoch rotation matrix

## Objective

Exercise the complete contract-side rotation boundary: append-only root epochs and chain hashes, one-step activation, pending removal, evidence updates, current `kmsInfo`, independent app epochs, operation-scoped authorization, legacy compatibility, owner boundaries, malformed keys, stale epochs, and revoked rows.

## Execution

Run the complete offline Foundry suite for `DstackKms.t.sol`, `DstackApp.t.sol`, and upgrade tests. The result must include the epoch, authorization, and upgrade rows; a partial match or zero-test result is a failure.

## Expected results

Every contract test passes. Epoch rows are independent, activation cannot skip or fork the chain, stale/unregistered requests fail closed, app and root epochs cannot be confused, and unauthorized callers cannot mutate rotation state. No private key is emitted.
