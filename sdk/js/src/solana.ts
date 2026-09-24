// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

import { type GetKeyResponse } from './client-v0'
import { Keypair } from '@solana/web3.js'

function rejectTlsKey(keyResponse: { readonly __name__: string }): void {
  if (keyResponse.__name__ === 'GetTlsKeyResponse') {
    throw new TypeError('TLS keys cannot be used to derive Solana keypairs; use getKey()')
  }
}

/**
 * @deprecated use toKeypairSecure instead.
 */
export function toKeypair(keyResponse: GetKeyResponse) {
  rejectTlsKey(keyResponse)
  return Keypair.fromSeed(keyResponse.key)
}

/** Creates a Solana keypair from a getKey() response. */
export function toKeypairSecure(keyResponse: GetKeyResponse) {
  rejectTlsKey(keyResponse)
  return Keypair.fromSeed(keyResponse.key)
}
