// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

import { keccak_256 } from "@noble/hashes/sha3";
import { secp256k1 } from "@noble/curves/secp256k1";

/** Default maximum age for timestamp verification (5 minutes) */
const DEFAULT_MAX_AGE_SECONDS = 300;

/**
 * Options for verifying env encrypt public key
 */
export interface VerifyOptions {
  /**
   * Maximum age of the response in seconds.
   * If the timestamp is older than this, verification fails.
   * Default: 300 (5 minutes)
   */
  maxAgeSeconds?: number;
}

/**
 * Verify the signature of a public key with timestamp validation.
 *
 * @param publicKey - The public key bytes to verify (32 bytes)
 * @param signature - The signature bytes (65 bytes)
 * @param appId - The application ID
 * @param timestamp - Unix timestamp in seconds when the response was generated
 * @param options - Optional verification options
 * @returns The compressed public key if valid, null otherwise
 *
 * @example
 * ```typescript
 * const publicKey = new Uint8Array(Buffer.from('e33a1832c6562067ff8f844a61e51ad051f1180b66ec2551fb0251735f3ee90a', 'hex'));
 * const signature = new Uint8Array(Buffer.from('...', 'hex'));
 * const appId = '00'.repeat(20);
 * const timestamp = 1700000000n;
 * const compressedPubkey = verifyEnvEncryptPublicKey(publicKey, signature, appId, timestamp);
 * ```
 */
export function verifyEnvEncryptPublicKey(
  publicKey: Uint8Array,
  signature: Uint8Array,
  appId: string,
  timestamp: bigint | number,
  options?: VerifyOptions
): string | null {
  if (signature.length !== 65) {
    return null;
  }

  // Convert timestamp to bigint for consistent handling
  const ts = typeof timestamp === 'bigint' ? timestamp : BigInt(timestamp);

  // Validate timestamp freshness
  const maxAge = options?.maxAgeSeconds ?? DEFAULT_MAX_AGE_SECONDS;
  const now = BigInt(Math.floor(Date.now() / 1000));
  const age = now - ts;

  if (age < 0n) {
    // Timestamp is in the future - allow small clock skew (60 seconds)
    if (age < -60n) {
      console.error('timestamp is too far in the future');
      return null;
    }
  } else if (age > BigInt(maxAge)) {
    console.error(`timestamp is too old: ${age}s > ${maxAge}s`);
    return null;
  }

  // Create the message to verify
  const prefix = Buffer.from("dstack-env-encrypt-pubkey", "utf8");

  // Remove 0x prefix if present
  let cleanAppId = appId;
  if (appId.startsWith("0x")) {
    cleanAppId = appId.slice(2);
  }

  const appIdBytes = Buffer.from(cleanAppId, "hex");
  const separator = Buffer.from(":", "utf8");

  // Convert timestamp to big-endian bytes (8 bytes)
  const timestampBytes = Buffer.alloc(8);
  timestampBytes.writeBigUInt64BE(ts);

  // Construct message: prefix + ":" + app_id + timestamp_be_bytes + public_key
  const message = Buffer.concat([prefix, separator, appIdBytes, timestampBytes, Buffer.from(publicKey)]);

  // Hash the message with Keccak-256
  const messageHash = keccak_256(message);

  try {
    // Extract r, s, v from signature (last byte is recovery id)
    const r = signature.slice(0, 32);
    const s = signature.slice(32, 64);
    const recovery = signature[64];

    // Create signature in DER format for secp256k1
    const sigBytes = new Uint8Array(64);
    sigBytes.set(r, 0);
    sigBytes.set(s, 32);

    // Recover the public key from the signature
    const recoveredPubKey = secp256k1.Signature.fromCompact(sigBytes)
      .addRecoveryBit(recovery)
      .recoverPublicKey(messageHash);

    // Return compressed public key with 0x prefix
    return '0x' + Buffer.from(recoveredPubKey.toRawBytes(true)).toString('hex');
  } catch (error) {
    console.error('signature verification failed:', error);
    return null;
  }
}

/**
 * @deprecated Use verifyEnvEncryptPublicKey with timestamp parameter instead.
 * This function is kept for backward compatibility but does not protect against replay attacks.
 */
export function verifyEnvEncryptPublicKeyLegacy(
  publicKey: Uint8Array,
  signature: Uint8Array,
  appId: string
): string | null {
  if (signature.length !== 65) {
    return null;
  }

  // Create the message to verify
  const prefix = Buffer.from("dstack-env-encrypt-pubkey", "utf8");

  // Remove 0x prefix if present
  let cleanAppId = appId;
  if (appId.startsWith("0x")) {
    cleanAppId = appId.slice(2);
  }

  const appIdBytes = Buffer.from(cleanAppId, "hex");
  const separator = Buffer.from(":", "utf8");

  // Construct message: prefix + ":" + app_id + public_key
  const message = Buffer.concat([prefix, separator, appIdBytes, Buffer.from(publicKey)]);

  // Hash the message with Keccak-256
  const messageHash = keccak_256(message);

  try {
    // Extract r, s, v from signature (last byte is recovery id)
    const r = signature.slice(0, 32);
    const s = signature.slice(32, 64);
    const recovery = signature[64];

    // Create signature in DER format for secp256k1
    const sigBytes = new Uint8Array(64);
    sigBytes.set(r, 0);
    sigBytes.set(s, 32);

    // Recover the public key from the signature
    const recoveredPubKey = secp256k1.Signature.fromCompact(sigBytes)
      .addRecoveryBit(recovery)
      .recoverPublicKey(messageHash);

    // Return compressed public key with 0x prefix
    return '0x' + Buffer.from(recoveredPubKey.toRawBytes(true)).toString('hex');
  } catch (error) {
    console.error('signature verification failed:', error);
    return null;
  }
}
