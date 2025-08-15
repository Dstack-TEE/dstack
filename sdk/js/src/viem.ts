// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

import crypto from 'crypto'
import { type GetKeyResponse, type GetTlsKeyResponse } from './index'
import { privateKeyToAccount } from 'viem/accounts'

/**
 * @deprecated use toViemAccountSecure instead. This method has security concerns.
 * Current implementation uses raw key material without proper hashing.
 */
export function toViemAccount(keyResponse: GetKeyResponse | GetTlsKeyResponse) {
  // Keep legacy behavior for GetTlsKeyResponse, but with warning.
  if (keyResponse.__name__ === 'GetTlsKeyResponse') {
    console.warn('toViemAccount: Please don\'t use `deriveKey` method to get key, use `getKey` instead.')
    const hex = Array.from(keyResponse.asUint8Array(32)).map(b => b.toString(16).padStart(2, '0')).join('')
    return privateKeyToAccount(`0x${hex}`)
  }
  const hex = Array.from(keyResponse.key).map(b => b.toString(16).padStart(2, '0')).join('')
  return privateKeyToAccount(`0x${hex}`)
}

/**
 * Creates a Viem account from DeriveKeyResponse using secure key derivation.
 * This method applies SHA256 hashing to the complete key material for enhanced security.
 */
export function toViemAccountSecure(keyResponse: GetKeyResponse | GetTlsKeyResponse) {
  // Keep legacy behavior for GetTlsKeyResponse, but with warning.
  if (keyResponse.__name__ === 'GetTlsKeyResponse') {
    console.warn('toViemAccountSecure: Please don\'t use `deriveKey` method to get key, use `getKey` instead.')
    try {
      // Get supported hash algorithm by `openssl list -digest-algorithms`, but it's not guaranteed to be supported by node.js
      const hex = crypto.createHash('sha256').update(keyResponse.asUint8Array()).digest('hex')
      return privateKeyToAccount(`0x${hex}`)
    } catch (err) {
      throw new Error('toViemAccountSecure: missing sha256 support, please upgrade your openssl and node.js')
    }
  }
  const hex = Array.from(keyResponse.key).map(b => b.toString(16).padStart(2, '0')).join('')
  return privateKeyToAccount(`0x${hex}`)
}