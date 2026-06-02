// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

import { sha256 } from '@noble/hashes/sha256'
import { type GetKeyResponse, type GetTlsKeyResponse } from './index'
import { Keypair } from '@solana/web3.js'

/**
 * @deprecated use toKeypairSecure instead. This method has security concerns.
 * Current implementation uses raw key material without proper hashing.
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
 * Creates a Solana Keypair from DeriveKeyResponse using secure key derivation.
 * This method applies SHA256 hashing to the complete key material for enhanced security.
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
