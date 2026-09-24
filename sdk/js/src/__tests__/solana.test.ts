// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

import { expect, describe, it } from 'vitest'
import { Keypair } from '@solana/web3.js'
import type { GetKeyResponse, GetTlsKeyResponse } from '../client-v0'
import { toKeypair, toKeypairSecure } from '../solana'

describe('solana support', () => {
  for (const [name, adapter] of [
    ['toKeypair', toKeypair],
    ['toKeypairSecure', toKeypairSecure],
  ] as const) {
    describe(name, () => {
      it('creates a keypair from getKey', async () => {
        const result: GetKeyResponse = {
          __name__: 'GetKeyResponse',
          key: new Uint8Array(32).fill(1),
          signature_chain: [],
        }
        const keypair = adapter(result)
        expect(keypair).toBeInstanceOf(Keypair)
        expect(keypair.secretKey.length).toBe(64)
      })

      it('rejects TLS keys', async () => {
        const result: GetTlsKeyResponse = {
          __name__: 'GetTlsKeyResponse',
          key: 'not used',
          certificate_chain: [],
          asUint8Array: () => new Uint8Array(),
        }
        expect(() => adapter(result as never)).toThrow(/TLS keys cannot be used/)
      })
    })
  }
})
