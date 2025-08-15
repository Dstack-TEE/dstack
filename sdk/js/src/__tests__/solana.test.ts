// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

import crypto from 'crypto'
import { expect, describe, it, vi } from 'vitest'
import { Keypair } from '@solana/web3.js'

import { DstackClient, TappdClient } from '../index'
import { toKeypair, toKeypairSecure } from '../solana'

describe('solana support', () => {
  describe('toKeypair (legacy)', () => {
    it('should able to get keypair from getKey with DstackClient', async () => {
      const client = new DstackClient()
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

    it('should able to get keypair from getTlsKey with DstackClient', async () => {
      const client = new DstackClient()
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
    it('should able to get keypair from getKey with DstackClient', async () => {
      const client = new DstackClient()
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

    it('should able to get keypair from getTlsKey with DstackClient', async () => {
      const client = new DstackClient()
      const consoleSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})
      
      const result = await client.getTlsKey()
      const keypair = toKeypairSecure(result)
      expect(keypair).toBeInstanceOf(Keypair)
      expect(keypair.secretKey.length).toBe(64)
      expect(consoleSpy).toHaveBeenCalledWith('toKeypairSecure: Please don\'t use `deriveKey` method to get key, use `getKey` instead.')
      
      consoleSpy.mockRestore()
    })

    it('should throw error when sha256 is not supported', async () => {
      const client = new DstackClient()
      const result = await client.getTlsKey()
      
      // Mock crypto.createHash to simulate missing sha256 support
      const originalCreateHash = crypto.createHash
      crypto.createHash = () => {
        throw new Error('sha256 not supported')
      }
      
      expect(() => toKeypairSecure(result)).toThrow('toKeypairSecure: missing sha256 support')
      
      // Restore original createHash
      crypto.createHash = originalCreateHash
    })
  })
})