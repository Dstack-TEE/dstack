// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0


import { expect, describe, it, vi } from 'vitest'
import { Keypair } from '@solana/web3.js'

import { DstackClientV0, TappdClient } from '../index'
import { toKeypair, toKeypairSecure } from '../solana'

describe('solana support', () => {
  describe('toKeypair (legacy)', () => {
    it('should able to get keypair from getKey with DstackClientV0', async () => {
      const client = new DstackClientV0()
      const result = await client.getKey('/', 'test')
      const keypair = toKeypair(result)
      expect(keypair).toBeInstanceOf(Keypair)
      expect(keypair.secretKey.length).toBe(64)
    })

    it('should able to get keypair from deriveKey with TappdClient', async () => {
      const client = new TappdClient()
      const consoleSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})

      const result = await client.deriveKey('/', 'test')
      const keypair = toKeypair(result)
      expect(keypair).toBeInstanceOf(Keypair)
      expect(keypair.secretKey.length).toBe(64)
      expect(consoleSpy).toHaveBeenCalledWith('toKeypair: Please don\'t use `deriveKey` method to get key, use `getKey` instead.')

      consoleSpy.mockRestore()
    })

    it('should able to get keypair from getTlsKey with DstackClientV0', async () => {
      const client = new DstackClientV0()
      const consoleSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})

      const result = await client.getTlsKey()
      const keypair = toKeypair(result)
      expect(keypair).toBeInstanceOf(Keypair)
      expect(keypair.secretKey.length).toBe(64)
      expect(consoleSpy).toHaveBeenCalledWith('toKeypair: Please don\'t use `deriveKey` method to get key, use `getKey` instead.')

      consoleSpy.mockRestore()
    })
  })

  describe('toKeypairSecure', () => {
    it('should able to get keypair from getKey with DstackClientV0', async () => {
      const client = new DstackClientV0()
      const result = await client.getKey('/', 'test')
      const keypair = toKeypairSecure(result)
      expect(keypair).toBeInstanceOf(Keypair)
      expect(keypair.secretKey.length).toBe(64)
    })

    it('should able to get keypair from deriveKey with TappdClient', async () => {
      const client = new TappdClient()
      const consoleSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})

      const result = await client.deriveKey('/', 'test')
      const keypair = toKeypairSecure(result)
      expect(keypair).toBeInstanceOf(Keypair)
      expect(keypair.secretKey.length).toBe(64)
      expect(consoleSpy).toHaveBeenCalledWith('toKeypairSecure: Please don\'t use `deriveKey` method to get key, use `getKey` instead.')

      consoleSpy.mockRestore()
    })

    it('should able to get keypair from getTlsKey with DstackClientV0', async () => {
      const client = new DstackClientV0()
      const consoleSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})

      const result = await client.getTlsKey()
      const keypair = toKeypairSecure(result)
      expect(keypair).toBeInstanceOf(Keypair)
      expect(keypair.secretKey.length).toBe(64)
      expect(consoleSpy).toHaveBeenCalledWith('toKeypairSecure: Please don\'t use `deriveKey` method to get key, use `getKey` instead.')

      consoleSpy.mockRestore()
    })

    it('should hash the full key material for GetKeyResponse (regression: previously fell through unhashed)', async () => {
      const client = new DstackClient()
      const result = await client.getKey('/', 'test')

      const legacyKeypair = toKeypair(result)
      const secureKeypair = toKeypairSecure(result)

      // toKeypairSecure must apply SHA256 to the full key material, as its
      // docstring promises. If it silently falls through to the raw key (the
      // bug this test guards against), both public keys are identical.
      expect(secureKeypair.publicKey.toBase58()).not.toBe(legacyKeypair.publicKey.toBase58())
    })
  })
})
