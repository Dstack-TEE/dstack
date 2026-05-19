// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

import { sha256 } from '@noble/hashes/sha256'
import { bytesToHex } from '@noble/hashes/utils'
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
    const hex = bytesToHex(sha256(keyResponse.asUint8Array()))
    return privateKeyToAccount(`0x${hex}`)
  }
  const hex = Array.from(keyResponse.key).map(b => b.toString(16).padStart(2, '0')).join('')
  return privateKeyToAccount(`0x${hex}`)
}