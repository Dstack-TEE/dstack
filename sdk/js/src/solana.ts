// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

import { sha256 } from '@noble/hashes/sha256'
import { type GetKeyResponse, type GetTlsKeyResponse } from './client-v0'
import { Keypair } from '@solana/web3.js'

/**
 * @deprecated use toKeypairSecure instead. This method has security concerns.
 * A `GetTlsKeyResponse` is used without hashing; a `GetKeyResponse` gives the
 * same result as `toKeypairSecure`.
 */
export function toKeypair(keyResponse: GetTlsKeyResponse | GetKeyResponse) {
  // Keep legacy behavior for GetTlsKeyResponse, but with warning.
  if (keyResponse.__name__ === 'GetTlsKeyResponse') {
    console.warn('toKeypair: Please don\'t use `deriveKey` method to get key, use `getKey` instead.')
    // Restored original behavior: using first 32 bytes directly
    const bytes = keyResponse.asUint8Array(32)
    return Keypair.fromSeed(bytes)
  }
  return Keypair.fromSeed(keyResponse.key)
}

/**
 * Creates a Solana Keypair from a key response.
 *
 * A `GetTlsKeyResponse` is hashed with SHA256 before use. A `GetKeyResponse`
 * key is used as is: it is already a KMS-derived key specific to its path and
 * purpose, so it needs no further hashing. Derive wallet keys from a dedicated
 * path rather than reusing one key for several purposes.
 */
export function toKeypairSecure(keyResponse: GetTlsKeyResponse | GetKeyResponse) {
  // Keep legacy behavior for GetTlsKeyResponse, but with warning.
  if (keyResponse.__name__ === 'GetTlsKeyResponse') {
    console.warn('toKeypairSecure: Please don\'t use `deriveKey` method to get key, use `getKey` instead.')
    const buf = sha256(keyResponse.asUint8Array())
    return Keypair.fromSeed(buf)
  }
  return Keypair.fromSeed(keyResponse.key)
}
