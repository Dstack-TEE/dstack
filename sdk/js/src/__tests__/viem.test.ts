// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0


import { expect, describe, it, vi } from 'vitest'
import { DstackClientV0, TappdClient } from '../index'
import { toViemAccount, toViemAccountSecure } from '../viem'

describe('viem support', () => {
  describe('toViemAccount (legacy)', () => {
    it('should able to get account from getKey with DstackClientV0', async () => {
      const client = new DstackClientV0()
      const result = await client.getKey('/', 'test')
      const account = toViemAccount(result)

      expect(account.source).toBe('privateKey')
      expect(typeof account.sign).toBe('function')
      expect(typeof account.signMessage).toBe('function')
    })

    it('should able to get account from deriveKey with TappdClient', async () => {
      const client = new TappdClient()
      const consoleSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})

      const result = await client.deriveKey('/', 'test')
      const account = toViemAccount(result)

      expect(account.source).toBe('privateKey')
      expect(typeof account.sign).toBe('function')
      expect(typeof account.signMessage).toBe('function')
      expect(consoleSpy).toHaveBeenCalledWith('toViemAccount: Please don\'t use `deriveKey` method to get key, use `getKey` instead.')

      consoleSpy.mockRestore()
    })

    it('should able to get account from getTlsKey with DstackClientV0', async () => {
      const client = new DstackClientV0()
      const consoleSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})

      const result = await client.getTlsKey()
      const account = toViemAccount(result)

      expect(account.source).toBe('privateKey')
      expect(typeof account.sign).toBe('function')
      expect(typeof account.signMessage).toBe('function')
      expect(consoleSpy).toHaveBeenCalledWith('toViemAccount: Please don\'t use `deriveKey` method to get key, use `getKey` instead.')

      consoleSpy.mockRestore()
    })
  })

  describe('toViemAccountSecure', () => {
    it('should able to get account from getKey with DstackClientV0', async () => {
      const client = new DstackClientV0()
      const result = await client.getKey('/', 'test')
      const account = toViemAccountSecure(result)

      expect(account.source).toBe('privateKey')
      expect(typeof account.sign).toBe('function')
      expect(typeof account.signMessage).toBe('function')
    })

    it('should able to get account from deriveKey with TappdClient', async () => {
      const client = new TappdClient()
      const consoleSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})

      const result = await client.deriveKey('/', 'test')
      const account = toViemAccountSecure(result)

      expect(account.source).toBe('privateKey')
      expect(typeof account.sign).toBe('function')
      expect(typeof account.signMessage).toBe('function')
      expect(consoleSpy).toHaveBeenCalledWith('toViemAccountSecure: Please don\'t use `deriveKey` method to get key, use `getKey` instead.')

      consoleSpy.mockRestore()
    })

    it('should able to get account from getTlsKey with DstackClientV0', async () => {
      const client = new DstackClientV0()
      const consoleSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})

      const result = await client.getTlsKey()
      const account = toViemAccountSecure(result)

      expect(account.source).toBe('privateKey')
      expect(typeof account.sign).toBe('function')
      expect(typeof account.signMessage).toBe('function')
      expect(consoleSpy).toHaveBeenCalledWith('toViemAccountSecure: Please don\'t use `deriveKey` method to get key, use `getKey` instead.')

      consoleSpy.mockRestore()
    })

    it('should hash the full key material for GetKeyResponse (regression: previously fell through unhashed)', async () => {
      const client = new DstackClient()
      const result = await client.getKey('/', 'test')

      const legacyAccount = toViemAccount(result)
      const secureAccount = toViemAccountSecure(result)

      // toViemAccountSecure must apply SHA256 to the full key material, as its
      // docstring promises. If it silently falls through to the raw key (the
      // bug this test guards against), both addresses are identical.
      expect(secureAccount.address).not.toBe(legacyAccount.address)
    })
  })
})
