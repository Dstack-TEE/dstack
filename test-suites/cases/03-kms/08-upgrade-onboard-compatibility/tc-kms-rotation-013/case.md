<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-kms-rotation-013"></a>
# TC-KMS-ROTATION-013: Root and app key rotation lifecycle matrix

## Metadata

- Priority: P0
- Type: Functional, Compatibility, Security, Regression
- Minimum environment: INTEGRATION
- Automation: Yes
- Requirements: [req-kms-rotation-013](../../../../catalog/feature-audit.md#req-kms-rotation-013)
- Risks: [risk-kms-rotation-013](../../../../catalog/feature-audit.md#risk-kms-rotation-013)
- Source: `dstack/kms/src/onboard_service.rs`, `dstack/kms/src/main_service.rs`, `dstack/dstack-util/src/system_setup/luks.rs`, `dstack/dstack-util/src/system_setup/sealed_env.rs`

## Objective

Verify root and app key rotation as one lifecycle: registration, chain-hash binding, activation, historical-key serving, onboarding handover, restart recovery, disk epoch migration, SealedEnv epoch derivation, authorization epoch selection, and rejection of stale, forked, incomplete, or unauthorized state.

## Steps

### Step 1: Run the candidate rotation matrix

Run every focused unit row for keyring import, next-epoch generation, current-epoch serving, onboarding validation, chain-hash binding, historical key selection, authorization epoch selection, disk header migration, and SealedEnv derivation.

**Expected results:** every row passes; no private key or plaintext secret is emitted.

### Step 2: Check boundaries and recovery

Repeat after restart and exercise epoch zero, multiple historical epochs, stale current epoch, mismatched chain hash, incomplete handover, missing certificate, failed disk migration, and app/root epoch mismatch.

**Expected results:** stale or forked state fails closed, interrupted operations recover without losing the source epoch, and historical material is available only for explicitly authorized migration.

### Step 3: Check compatibility

Verify old epoch zero behavior, current epoch behavior, app epoch separation, KMS and app operation separation, and all supported auth backends.

**Expected results:** legacy clients remain compatible at epoch zero; new operations cannot use a stale root/app epoch or cross an authorization scope.

## Postconditions

Remove temporary state and retain only test counts, coverage labels, durations, and output hashes.
