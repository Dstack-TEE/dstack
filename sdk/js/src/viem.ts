// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

import { type GetKeyResponse } from './client-v0'
import { privateKeyToAccount } from 'viem/accounts'

function rejectTlsKey(keyResponse: { readonly __name__: string }): void {
  if (keyResponse.__name__ === 'GetTlsKeyResponse') {
    throw new TypeError('TLS keys cannot be used to derive Viem accounts; use getKey()')
  }
}

/**
 * @deprecated use toViemAccountSecure instead.
 */
export function toViemAccount(keyResponse: GetKeyResponse) {
  rejectTlsKey(keyResponse)
  const hex = Array.from(keyResponse.key).map(b => b.toString(16).padStart(2, '0')).join('')
  return privateKeyToAccount(`0x${hex}`)
}

/** Creates a Viem account from a getKey() response. */
export function toViemAccountSecure(keyResponse: GetKeyResponse) {
  rejectTlsKey(keyResponse)
  const hex = Array.from(keyResponse.key).map(b => b.toString(16).padStart(2, '0')).join('')
  return privateKeyToAccount(`0x${hex}`)
}
