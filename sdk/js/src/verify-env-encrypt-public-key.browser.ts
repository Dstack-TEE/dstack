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
 * Convert a bigint to big-endian bytes
 */
function bigintToBeBytes(value: bigint, length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  for (let i = length - 1; i >= 0; i--) {
    bytes[i] = Number(value & 0xffn);
    value >>= 8n;
  }
  return bytes;
}

/**
 * Convert hex string to Uint8Array
 */
function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
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
 * const publicKey = new Uint8Array([...]);
 * const signature = new Uint8Array([...]);
 * const appId = '00'.repeat(20);
 * const timestamp = 1700000000n;
 * const compressedPubkey = await verifyEnvEncryptPublicKey(publicKey, signature, appId, timestamp);
 * ```
 */
export async function verifyEnvEncryptPublicKey(
  publicKey: Uint8Array,
  signature: Uint8Array,
  appId: string,
  timestamp: bigint | number,
  options?: VerifyOptions
): Promise<string | null> {
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
  const prefix = new TextEncoder().encode("dstack-env-encrypt-pubkey");

  // Remove 0x prefix if present
  let cleanAppId = appId;
  if (appId.startsWith("0x")) {
    cleanAppId = appId.slice(2);
  }

  const appIdBytes = hexToBytes(cleanAppId);
  const separator = new TextEncoder().encode(":");

  // Convert timestamp to big-endian bytes (8 bytes)
  const timestampBytes = bigintToBeBytes(ts, 8);

  // Construct message: prefix + ":" + app_id + timestamp_be_bytes + public_key
  const message = new Uint8Array(prefix.length + separator.length + appIdBytes.length + timestampBytes.length + publicKey.length);
  let offset = 0;
  message.set(prefix, offset); offset += prefix.length;
  message.set(separator, offset); offset += separator.length;
  message.set(appIdBytes, offset); offset += appIdBytes.length;
  message.set(timestampBytes, offset); offset += timestampBytes.length;
  message.set(publicKey, offset);

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
    const compressedBytes = recoveredPubKey.toRawBytes(true);
    return '0x' + Array.from(compressedBytes, b => b.toString(16).padStart(2, '0')).join('');
  } catch (error) {
    console.error('signature verification failed:', error);
    return null;
  }
}

/**
 * @deprecated Use verifyEnvEncryptPublicKey with timestamp parameter instead.
 * This function is kept for backward compatibility but does not protect against replay attacks.
 */
export async function verifyEnvEncryptPublicKeyLegacy(
  publicKey: Uint8Array,
  signature: Uint8Array,
  appId: string
): Promise<string | null> {
  if (signature.length !== 65) {
    return null;
  }

  // Create the message to verify
  const prefix = new TextEncoder().encode("dstack-env-encrypt-pubkey");

  // Remove 0x prefix if present
  let cleanAppId = appId;
  if (appId.startsWith("0x")) {
    cleanAppId = appId.slice(2);
  }

  const appIdBytes = hexToBytes(cleanAppId);
  const separator = new TextEncoder().encode(":");

  // Construct message: prefix + ":" + app_id + public_key
  const message = new Uint8Array(prefix.length + separator.length + appIdBytes.length + publicKey.length);
  message.set(prefix, 0);
  message.set(separator, prefix.length);
  message.set(appIdBytes, prefix.length + separator.length);
  message.set(publicKey, prefix.length + separator.length + appIdBytes.length);

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
    const compressedBytes = recoveredPubKey.toRawBytes(true);
    return '0x' + Array.from(compressedBytes, b => b.toString(16).padStart(2, '0')).join('');
  } catch (error) {
    console.error('signature verification failed:', error);
    return null;
  }
}
