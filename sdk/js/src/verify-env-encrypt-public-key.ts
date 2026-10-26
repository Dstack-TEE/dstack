// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

import { keccak_256 } from "@noble/hashes/sha3"
import { secp256k1 } from "@noble/curves/secp256k1"

const DEFAULT_MAX_AGE_SECONDS = 300

export interface VerifyOptions {
  /** Maximum age of the signed response in seconds. Default: 300 (5 minutes). */
  maxAgeSeconds?: number
}

function bigintToBeBytes(value: bigint, length: number): Uint8Array {
  const bytes = new Uint8Array(length)
  for (let i = length - 1; i >= 0; i--) {
    bytes[i] = Number(value & 0xffn)
    value >>= 8n
  }
  return bytes
}

function hexToBytes(hex: string): Uint8Array | null {
  if (hex.startsWith("0x") || hex.startsWith("0X")) hex = hex.slice(2)
  if (hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) return null
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16)
  }
  return bytes
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("")
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0)
  const out = new Uint8Array(total)
  let offset = 0
  for (const part of parts) {
    out.set(part, offset)
    offset += part.length
  }
  return out
}

function recoverSigner(
  messageHash: Uint8Array,
  signature: Uint8Array,
): string | null {
  try {
    const sigBytes = signature.slice(0, 64)
    const recovery = signature[64]
    const recoveredPubKey = secp256k1.Signature.fromCompact(sigBytes)
      .addRecoveryBit(recovery)
      .recoverPublicKey(messageHash)
    return "0x" + bytesToHex(recoveredPubKey.toRawBytes(true))
  } catch (error) {
    console.error("signature verification failed:", error)
    return null
  }
}

/**
 * Verify a timestamp-protected KMS env-encrypt public key signature.
 *
 * Returns the signer's compressed secp256k1 public key on success, or `null`
 * on failure (bad length, expired timestamp, invalid signature).
 */
export function verifyEnvEncryptPublicKey(
  publicKey: Uint8Array,
  signature: Uint8Array,
  appId: string,
  timestamp: bigint | number,
  options?: VerifyOptions,
): string | null {
  if (signature.length !== 65) return null

  const ts = typeof timestamp === "bigint" ? timestamp : BigInt(timestamp)
  const maxAge = options?.maxAgeSeconds ?? DEFAULT_MAX_AGE_SECONDS
  const now = BigInt(Math.floor(Date.now() / 1000))
  const age = now - ts
  if (age < -60n) {
    console.error("timestamp is too far in the future")
    return null
  }
  if (age > BigInt(maxAge)) {
    console.error(`timestamp is too old: ${age}s > ${maxAge}s`)
    return null
  }

  const appIdBytes = hexToBytes(appId)
  if (!appIdBytes) return null

  const prefix = new TextEncoder().encode("dstack-env-encrypt-pubkey")
  const separator = new TextEncoder().encode(":")
  const timestampBytes = bigintToBeBytes(ts, 8)
  const message = concat(
    prefix,
    separator,
    appIdBytes,
    timestampBytes,
    publicKey,
  )
  return recoverSigner(keccak_256(message), signature)
}

/**
 * @deprecated Use {@link verifyEnvEncryptPublicKey} with timestamp. Legacy
 * signatures do not protect against replay attacks.
 */
export function verifyEnvEncryptPublicKeyLegacy(
  publicKey: Uint8Array,
  signature: Uint8Array,
  appId: string,
): string | null {
  if (signature.length !== 65) return null

  const appIdBytes = hexToBytes(appId)
  if (!appIdBytes) return null

  const prefix = new TextEncoder().encode("dstack-env-encrypt-pubkey")
  const separator = new TextEncoder().encode(":")
  const message = concat(prefix, separator, appIdBytes, publicKey)
  return recoverSigner(keccak_256(message), signature)
}
