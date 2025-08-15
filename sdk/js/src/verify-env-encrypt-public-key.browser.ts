// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

import { keccak_256 } from "@noble/hashes/sha3";
import { secp256k1 } from "@noble/curves/secp256k1";

/**
 * Verify the signature of a public key.
 * 
 * @param publicKey - The public key bytes to verify (32 bytes)
 * @param signature - The signature bytes (65 bytes)
 * @param appId - The application ID
 * @returns The compressed public key if valid, null otherwise
 * 
 * @example
 * ```typescript
 * const publicKey = new Uint8Array(Buffer.from('e33a1832c6562067ff8f844a61e51ad051f1180b66ec2551fb0251735f3ee90a', 'hex'));
 * const signature = new Uint8Array(Buffer.from('8542c49081fbf4e03f62034f13fbf70630bdf256a53032e38465a27c36fd6bed7a5e7111652004aef37f7fd92fbfc1285212c4ae6a6154203a48f5e16cad2cef00', 'hex'));
 * const appId = '00'.repeat(20);
 * const compressedPubkey = verifySignature(publicKey, signature, appId);
 * console.log(compressedPubkey); // 0x0217610d74cbd39b6143842c6d8bc310d79da1d82cc9d17f8876376221eda0c38f
 * ```
 */
export async function verifyEnvEncryptPublicKey(
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
  
  const appIdBytes = new Uint8Array(cleanAppId.length / 2);
  for (let i = 0; i < cleanAppId.length; i += 2) {
    appIdBytes[i / 2] = parseInt(cleanAppId.substr(i, 2), 16);
  }
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