<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-kms-rotation-015"></a>
# TC-KMS-ROTATION-015: Epoch-scoped authorization across auth backends

## Objective

Verify dstack-auth and auth-eth preserve operation names and root/app epoch selectors, reject stale or mismatched epochs, and keep legacy epoch-zero behavior compatible.

## Execution and expected results

Run each backend's test suite with its declared lockfile. Every backend passes its complete test suite; authorization decisions remain operation- and epoch-scoped, and malformed or stale selectors fail closed.
