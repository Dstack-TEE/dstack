import crypto from 'crypto'
import { Keypair } from '@solana/web3.js'

import { type DeriveKeyResponse } from './index'

/**
 * @deprecated use toKeypairSecure instead. This method has security concerns.
 * Current implementation uses raw key material without proper hashing.
 */
export function toKeypair(deriveKeyResponse: DeriveKeyResponse) {
  console.warn('[DEPRECATED] toKeypair: this method has security concerns. Please use toKeypairSecure instead.')
  // Restored original behavior: using first 32 bytes directly
  const bytes = deriveKeyResponse.asUint8Array(32)
  return Keypair.fromSeed(bytes)
}

/**
 * Creates a Solana Keypair from DeriveKeyResponse using secure key derivation.
 * This method applies SHA256 hashing to the complete key material for enhanced security.
 */
export function toKeypairSecure(deriveKeyResponse: DeriveKeyResponse) {
  try {
    // Get supported hash algorithm by `openssl list -digest-algorithms`, but it's not guaranteed to be supported by node.js
    const buf = crypto.createHash('sha256').update(deriveKeyResponse.asUint8Array()).digest()
    return Keypair.fromSeed(buf)
  } catch (err) {
    throw new Error('toKeypairSecure: missing sha256 support, please upgrade your openssl and node.js')
  }
}