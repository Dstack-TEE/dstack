// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

import crypto from 'crypto'
import { expect, describe, it, vi } from 'vitest'
import { DstackClient, TappdClient } from '../index'
import { toViemAccount, toViemAccountSecure } from '../viem'

describe('viem support', () => {
  describe('toViemAccount (legacy)', () => {
    it('should able to get account from getKey with DstackClient', async () => {
      const client = new DstackClient()
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

    it('should able to get account from getTlsKey with DstackClient', async () => {
      const client = new DstackClient()
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
    it('should able to get account from getKey with DstackClient', async () => {
      const client = new DstackClient()
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

    it('should able to get account from getTlsKey with DstackClient', async () => {
      const client = new DstackClient()
      const consoleSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})
      
      const result = await client.getTlsKey()
      const account = toViemAccountSecure(result)
  
      expect(account.source).toBe('privateKey')
      expect(typeof account.sign).toBe('function')
      expect(typeof account.signMessage).toBe('function')
      expect(consoleSpy).toHaveBeenCalledWith('toViemAccountSecure: Please don\'t use `deriveKey` method to get key, use `getKey` instead.')
      
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
      
      expect(() => toViemAccountSecure(result)).toThrow('toViemAccountSecure: missing sha256 support')
      
      // Restore original createHash
      crypto.createHash = originalCreateHash
    })
  })
})
