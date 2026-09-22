// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

import { expect, describe, it } from 'vitest'
import type { GetKeyResponse, GetTlsKeyResponse } from '../client-v0'
import { toViemAccount, toViemAccountSecure } from '../viem'

describe('viem support', () => {
  for (const [name, adapter] of [
    ['toViemAccount', toViemAccount],
    ['toViemAccountSecure', toViemAccountSecure],
  ] as const) {
    describe(name, () => {
      it('creates an account from getKey', async () => {
        const result: GetKeyResponse = {
          __name__: 'GetKeyResponse',
          key: new Uint8Array(32).fill(1),
          signature_chain: [],
        }
        const account = adapter(result)
        expect(account.source).toBe('privateKey')
        expect(typeof account.sign).toBe('function')
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
