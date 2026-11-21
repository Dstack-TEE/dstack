<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-int-compatibil-009"></a>
# TC-INT-COMPATIBIL-009: SealedEnv epochs across a KMS root rotation

## Objective

Verify on physical TDX how the guest handles the epochs a SealedEnv envelope is labeled with:

1. An envelope sealed at a retained epoch is unsealed with the historical key once, then resealed to the current epoch; later boots fetch no historical key.
2. An envelope labeled above the current epoch is rejected before any historical key is requested.
3. An envelope whose epoch label was changed makes the guest fetch the historical key it names, and decryption then fails.

## Steps

### Step 1: Seal at epoch 0

Boot a candidate KMS at root epoch 0 behind the KMS endpoint proxy, and deploy a candidate app with a secret in its encrypted environment.

**Expected results:** the VMM stores a SealedEnv labeled root 0, app 0, and the app observes the secret.

### Step 2: Rotate and migrate

Onboard a second candidate KMS from the first with `rotate = true`, point the proxy at it, and restart the app twice.

**Expected results:** the rotated KMS serves root epoch 1. The first restart requests exactly one historical app key (`root 0 app 0`, read from the KMS audit log), the app still observes the secret, and the stored envelope is relabeled root 1, app 0 with new ciphertext. The second restart leaves the envelope unchanged and requests no historical key.

### Step 3: Reject bad labels

Stop the app and relabel the stored envelope to root epoch 2, then to root epoch 0, restarting after each change.

**Expected results:** root epoch 2 fails boot with `exceeds current epoch` and requests no historical key. Root epoch 0 requests the `root 0 app 0` key and then fails decryption. Restoring the resealed envelope boots the app again.

## Evidence

Record epoch labels, the historical key requests from the KMS audit log, redacted boot errors, and the secret's SHA-256 as reported by the app. Never retain the secret, private keys, or envelope ciphertext.
