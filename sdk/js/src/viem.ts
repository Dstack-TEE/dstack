import crypto from 'crypto'
import { privateKeyToAccount } from 'viem/accounts'

import { type DeriveKeyResponse } from './index'

/**
 * @deprecated use toViemAccountSecure instead. This method has security concerns.
 * Current implementation uses raw key material without proper hashing.
 */
export function toViemAccount(deriveKeyResponse: DeriveKeyResponse) {
  console.warn('[DEPRECATED] toViemAccount: this method has security concerns. Please use toViemAccountSecure instead.')
  // Restored original behavior: using first 32 bytes directly
  const hex = Array.from(deriveKeyResponse.asUint8Array(32)).map(b => b.toString(16).padStart(2, '0')).join('')
  return privateKeyToAccount(`0x${hex}`)
}

/**
 * Creates a Viem account from DeriveKeyResponse using secure key derivation.
 * This method applies SHA256 hashing to the complete key material for enhanced security.
 */
export function toViemAccountSecure(deriveKeyResponse: DeriveKeyResponse) {
  try {
    // Get supported hash algorithm by `openssl list -digest-algorithms`, but it's not guaranteed to be supported by node.js
    const hex = crypto.createHash('sha256').update(deriveKeyResponse.asUint8Array()).digest('hex')
    return privateKeyToAccount(`0x${hex}`)
  } catch (err) {
    throw new Error('toViemAccountSecure: missing sha256 support, please upgrade your openssl and node.js')
  }
}
