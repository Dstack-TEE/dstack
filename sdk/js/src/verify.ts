// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

/**
 * Local signature and signature-chain verification.
 *
 * Verification needs no key material and no attestation, so it does not belong
 * behind an RPC to the guest agent: the agent's answer arrives over the socket
 * unattested, which is no better than a caller checking the signature itself.
 * The `Verify` RPC these functions replace was removed in v0.6.0.
 *
 * Two levels are available:
 *
 * - {@link verifySignature} checks one signature against a public key you
 *   already have. It is the direct replacement for the old RPC and, on its own,
 *   proves only that whoever holds that key signed the data.
 * - {@link verifySignatureChain} walks the full chain from a `SignResponse`
 *   back to a KMS root key **you supply**, which is what actually establishes
 *   that the signer was a dstack app under that KMS.
 */

import { ed25519 } from "@noble/curves/ed25519"
import { secp256k1 } from "@noble/curves/secp256k1"
import { sha256 } from "@noble/hashes/sha256"
import { keccak_256 } from "@noble/hashes/sha3"

/** Domain-separation prefix the KMS signs app root keys under. */
const KMS_ISSUED_PREFIX = "dstack-kms-issued:"

/** `Sign` derives its key at this path with this purpose; both are fixed agent-side. */
export const SIGN_PATH = "vms"
export const SIGN_PURPOSE = "signing"

/** `k256` and `secp256k1` name the same thing; the agent normalized these too. */
function normalizeAlgorithm(algorithm: string): string {
  return algorithm === "k256" ? "secp256k1" : algorithm
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

function describe(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}

type K256Signature = ReturnType<typeof secp256k1.Signature.fromCompact>

function parseK256Signature(signature: Uint8Array): K256Signature {
  if (signature.length !== 64) {
    throw new Error(
      `invalid secp256k1 signature: expected 64 raw bytes (r || s), but received ${signature.length}`,
    )
  }
  let sig: K256Signature
  try {
    sig = secp256k1.Signature.fromCompact(signature)
  } catch (error) {
    throw new Error(`invalid secp256k1 signature: ${describe(error)}`)
  }
  // ECDSA is malleable: (r, n-s) verifies wherever (r, s) does. Rust's k256
  // rejects the high-S form, so we must too -- otherwise a signature stops
  // being a unique identifier for a signed message, and this SDK would disagree
  // with every other dstack component about whether a given blob is valid.
  // A high-S signature is a malformed encoding rather than a signature that
  // legitimately fails to match, so it throws instead of returning false.
  if (sig.hasHighS()) {
    throw new Error("non-canonical (high-S) secp256k1 signature")
  }
  return sig
}

/** Parses a SEC1 public key, compressed (33 bytes) or uncompressed (65 bytes). */
function parseK256PublicKey(publicKey: Uint8Array) {
  if (publicKey.length !== 33 && publicKey.length !== 65) {
    throw new Error(
      `invalid secp256k1 public key: expected 33 or 65 SEC1 bytes, but received ${publicKey.length}`,
    )
  }
  try {
    const point = secp256k1.ProjectivePoint.fromHex(publicKey)
    point.assertValidity()
    return point
  } catch (error) {
    throw new Error(`invalid secp256k1 public key: ${describe(error)}`)
  }
}

/**
 * Verifies one signature against `publicKey`.
 *
 * `algorithm` is `ed25519`, `secp256k1` (alias `k256`), or
 * `secp256k1_prehashed`, where `data` is already a 32-byte digest. Returns
 * `false` when the inputs are well-formed but the signature does not check out,
 * and throws when they are not well-formed at all (bad key encoding, wrong
 * signature length, unknown algorithm) -- a malformed input is a caller bug,
 * not a verdict.
 */
export function verifySignature(
  algorithm: string,
  data: Uint8Array,
  signature: Uint8Array,
  publicKey: Uint8Array,
): boolean {
  switch (normalizeAlgorithm(algorithm)) {
    case "ed25519": {
      if (publicKey.length !== 32) {
        throw new Error(
          `ed25519 public key must be 32 bytes, but received ${publicKey.length}`,
        )
      }
      if (signature.length !== 64) {
        throw new Error(
          `ed25519 signature must be 64 bytes, but received ${signature.length}`,
        )
      }
      try {
        ed25519.ExtendedPoint.fromHex(publicKey)
      } catch (error) {
        throw new Error(`invalid ed25519 public key: ${describe(error)}`)
      }
      try {
        return ed25519.verify(signature, data, publicKey)
      } catch {
        // Past the encoding checks above, anything left is a failed match.
        return false
      }
    }
    case "secp256k1": {
      const point = parseK256PublicKey(publicKey)
      const sig = parseK256Signature(signature)
      // The agent signs with k256's `sign`, which hashes with SHA-256, so
      // verification must hash the payload the same way.
      return verifyPrehashed(sha256(data), sig, point)
    }
    case "secp256k1_prehashed": {
      if (data.length !== 32) {
        throw new Error(
          `pre-hashed verification requires a 32-byte digest, but received ${data.length} bytes`,
        )
      }
      const point = parseK256PublicKey(publicKey)
      const sig = parseK256Signature(signature)
      return verifyPrehashed(data, sig, point)
    }
    default:
      throw new Error(`unsupported algorithm: ${algorithm}`)
  }
}

function verifyPrehashed(
  digest: Uint8Array,
  signature: K256Signature,
  publicKey: ReturnType<typeof parseK256PublicKey>,
): boolean {
  try {
    // `lowS` is noble's default today, but state it explicitly: a future change
    // to that default must not silently start accepting malleated signatures
    // that Rust's k256 rejects. High-S has already thrown by this point; this
    // keeps the two layers from drifting apart.
    return secp256k1.verify(
      signature.toCompactRawBytes(),
      digest,
      publicKey.toRawBytes(true),
      { lowS: true },
    )
  } catch {
    // Past the encoding checks above, anything left is a failed match.
    return false
  }
}

/**
 * Recovers the compressed public key that produced a 65-byte `r || s || recid`
 * signature over `keccak256(message)`.
 */
function recoverCompressed(
  message: Uint8Array,
  signature: Uint8Array,
): Uint8Array {
  if (signature.length !== 65) {
    throw new Error(
      `recoverable signature must be 65 bytes, but received ${signature.length}`,
    )
  }
  const sig = parseK256Signature(signature.slice(0, 64))
  const recid = signature[64]
  // Raw recovery ids, not the +27 form Ethereum wire formats use.
  if (recid > 3) {
    throw new Error(`invalid recovery id ${recid}`)
  }
  try {
    return sig
      .addRecoveryBit(recid)
      .recoverPublicKey(keccak_256(message))
      .toRawBytes(true)
  } catch (error) {
    throw new Error(`failed to recover public key: ${describe(error)}`)
  }
}

/**
 * Inputs to {@link verifySignatureChain}.
 *
 * An options object rather than a positional argument list so that adding an
 * input later does not break callers.
 */
export interface SignatureChainInput {
  /** Algorithm the payload was signed with. */
  algorithm: string
  /** The signed payload; a 32-byte digest for `secp256k1_prehashed`. */
  data: Uint8Array
  /** `SignResponse.public_key` -- the key that signed `data`. */
  publicKey: Uint8Array
  /** `SignResponse.signature_chain`, exactly 3 elements. */
  signatureChain: Uint8Array[]
  /**
   * The 20-byte app identity to hold the chain to.
   *
   * This must be the app id you *expect*, not merely whatever `InfoResponse`
   * echoed back -- that comes from the CVM being checked. Comparing a chain
   * against an app id the same CVM supplied proves only that it is
   * self-consistent.
   */
  appId: Uint8Array
  /**
   * The KMS root public key you already trust, compressed or uncompressed SEC1.
   *
   * Get it from the `DstackKms` contract (`kmsInfo().k256Pubkey`) or pin it.
   * Reading it from the KMS you are verifying against proves nothing.
   */
  kmsRootPubKey: Uint8Array
  /** Purpose bound into the app-root link. Always {@link SIGN_PURPOSE} for `Sign`. */
  purpose?: string
}

/**
 * Verifies a `Sign` signature chain end to end.
 *
 * Three links, all of which must hold:
 *
 * 1. `signatureChain[0]` is a signature over `data` by `publicKey`.
 * 2. `signatureChain[1]` is the app root key attesting `"{purpose}:{hex(publicKey)}"`.
 * 3. `signatureChain[2]` is `kmsRootPubKey` attesting that app root key for `appId`.
 *
 * Link 3 is the one that matters. Without comparing against a KMS root key you
 * independently trust, a chain is just three signatures an attacker could have
 * produced with their own keys.
 *
 * @returns the app root public key, compressed SEC1 (33 bytes), recovered from
 * the chain and confirmed to be the one this KMS root signed.
 * @throws if any link fails.
 */
export function verifySignatureChain(input: SignatureChainInput): Uint8Array {
  const {
    algorithm,
    data,
    publicKey,
    signatureChain,
    appId,
    kmsRootPubKey,
    purpose = SIGN_PURPOSE,
  } = input

  if (signatureChain.length !== 3) {
    throw new Error(
      `signature chain must have 3 elements, but received ${signatureChain.length}`,
    )
  }
  if (appId.length !== 20) {
    throw new Error(`appId must be 20 bytes, but received ${appId.length}`)
  }

  // Link 1: the payload signature. signatureChain[0] *is* that signature; what
  // matters is that it checks out under `publicKey`, which links 2 and 3 cover.
  if (!verifySignature(algorithm, data, signatureChain[0], publicKey)) {
    throw new Error("payload signature is not valid for the given public key")
  }

  // Link 2: recover the app root key that vouched for the signing key.
  const message = new TextEncoder().encode(
    `${purpose}:${bytesToHex(publicKey)}`,
  )
  const appRootPubKey = recoverCompressed(message, signatureChain[1])

  // Link 3: recover the KMS root key that vouched for the app root key, and
  // check it is the one we were told to trust.
  const kmsMessage = concat(
    new TextEncoder().encode(KMS_ISSUED_PREFIX),
    appId,
    appRootPubKey,
  )
  const recoveredKms = recoverCompressed(kmsMessage, signatureChain[2])

  // Normalize the expected key so callers may pass either SEC1 encoding.
  const expectedKms = parseK256PublicKey(kmsRootPubKey).toRawBytes(true)
  if (bytesToHex(recoveredKms) !== bytesToHex(expectedKms)) {
    throw new Error(
      "signature chain is not anchored at the expected KMS root key",
    )
  }

  return appRootPubKey
}
