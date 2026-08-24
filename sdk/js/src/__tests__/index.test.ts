// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

import { expect, describe, it, vi } from 'vitest'
import crypto from 'crypto' // Added for prehashed test
import { DstackClient, DstackClientV0, DstackClientV1, TappdClient } from '../index'

describe('DstackClientV0', () => {
  it('should only be reachable under its explicit name now', () => {
    expect(DstackClient).not.toBe(DstackClientV0)
    expect(new DstackClient()).not.toBeInstanceOf(DstackClientV0)
  })

  it('should stay the base of TappdClient even though the alias moved to v1', () => {
    expect(new TappdClient()).toBeInstanceOf(DstackClientV0)
    expect(new TappdClient()).not.toBeInstanceOf(DstackClientV1)
  })

  it('should able to derive key in TappdClient', async () => {
    const client = new TappdClient()
    const result = await client.deriveKey('/', 'test')
    expect(result).toHaveProperty('key')
    expect(result).toHaveProperty('certificate_chain')
  })

  it('should throws error in DstackClientV0', async () => {
    const client = new DstackClientV0()
    await expect(() => client.deriveKey('/', 'test')).rejects.toThrow('deriveKey is deprecated, please use getKey instead.')
  })

  it('should able to get key', async () => {
    const client = new DstackClientV0()
    const result = await client.getKey('/', 'test')
    expect(result).toHaveProperty('key')
    expect(result).toHaveProperty('signature_chain')
  })

  it('should able to get key with different algorithms', async () => {
    const client = new DstackClientV0()
    const resultSecp = await client.getKey('/secp', 'test', 'secp256k1')
    expect(resultSecp.key).toBeInstanceOf(Uint8Array)
    expect(resultSecp.key.length).toBe(32) // secp256k1 private key size

    const resultEd = await client.getKey('/ed', 'test', 'ed25519')
    expect(resultEd.key).toBeInstanceOf(Uint8Array)
    expect(resultEd.key.length).toBe(32) // ed25519 private key size (seed)
  })


  it('should able to request tdx quote', async () => {
    const client = new DstackClientV0()
    // You can put computation result as report data to tdxQuote. NOTE: it should serializable by JSON.stringify
    const result = await client.getQuote('some data or anything can be call by toJSON')
    expect(result).toHaveProperty('quote')
    expect(result).toHaveProperty('event_log')
    expect(result.event_log.substring(0, 1) === '{')
    expect(() => JSON.parse(result.event_log)).not.toThrowError()
  })

  it('should be able to attest', async () => {
    const client = new DstackClientV0()
    const result = await client.attest('test')
    expect(result).toHaveProperty('attestation')
    expect(result.attestation).not.toBe('')
  })

  it('should not carry the GPU methods, which this surface never served', () => {
    const client = new DstackClientV0() as any
    expect(client.attestGpu).toBeUndefined()
    expect(client.gpuInfo).toBeUndefined()
  })

  it('should able to get derive key result as uint8array', async () => {
    const client = new DstackClientV0()
    const result = await client.getKey('/', 'test')
    expect(result.key).toBeInstanceOf(Uint8Array)
  })

  it('should able to get derive key result as uint8array with specified length', async () => {
    const client = new DstackClientV0()
    const result = await client.getTlsKey()
    const full = result.asUint8Array()
    const key = result.asUint8Array(32)
    expect(full).toBeInstanceOf(Uint8Array)
    expect(key).toBeInstanceOf(Uint8Array)
    expect(key.length).toBe(32)
    expect(key.length).not.eq(full.length)
  })

  it('should be able to get quote', async () => {
    const client = new DstackClientV0()
    const result = await client.getQuote('pure string')
  })

  it('should throw error on report_data large then 64 characters', async () => {
    const client = new DstackClientV0()
    await expect(() => client.getQuote('0'.padEnd(65, 'x'))).rejects.toThrow()
  })

  it('should throw error on report_data large then 64 bytes', async () => {
    const client = new DstackClientV0()
    await expect(() => client.getQuote(Buffer.alloc(65))).rejects.toThrow()
  })

  it('should throw error on report_data large then 128 bytes', async () => {
    const client = new DstackClientV0()
    const input = new Uint8Array(65).fill(0)
    await expect(() => client.getQuote(input)).rejects.toThrow()
  })

  it('should throw error on attest report_data larger than 64 bytes', async () => {
    const client = new DstackClientV0()
    await expect(() => client.attest(Buffer.alloc(65))).rejects.toThrow()
  })

  it('should be able to get info', async () => {
    const client = new DstackClientV0()
    const result = await client.info()
    expect(result).toHaveProperty('app_id')
    expect(result).toHaveProperty('instance_id')
    expect(result).toHaveProperty('tcb_info')
    expect(result.app_id).not.toBe('')
    expect(result.instance_id).not.toBe('')
    expect(result.tcb_info).not.toBe('')
    expect(result.tcb_info).toHaveProperty('os_image_hash')
    expect(result.tcb_info).toHaveProperty('compose_hash')
    expect(result.tcb_info).toHaveProperty('device_id')
    expect(result.tcb_info).toHaveProperty('app_compose')
    expect(result.tcb_info).toHaveProperty('event_log')
  })

  it('should be able to decode tcb info', async () => {
    const client = new DstackClientV0()
    const result = await client.info()
    const tcbInfo = result.tcb_info
    expect(tcbInfo).toHaveProperty('rtmr0')
    expect(tcbInfo).toHaveProperty('rtmr1')
    expect(tcbInfo).toHaveProperty('rtmr2')
    expect(tcbInfo).toHaveProperty('rtmr3')
    expect(tcbInfo).toHaveProperty('event_log')
    expect(tcbInfo.rtmr0).not.toBe('')
    expect(tcbInfo.rtmr1).not.toBe('')
    expect(tcbInfo.rtmr2).not.toBe('')
    expect(tcbInfo.rtmr3).not.toBe('')
    expect(tcbInfo.event_log.length).toBeGreaterThan(0)
  })

  it('should be able to get TLS key with alt names', async () => {
    const client = new DstackClientV0()
    const altNames = ['localhost', '127.0.0.1']
    const result = await client.getTlsKey({
      subject: 'test-subject',
      altNames,
      usageRaTls: true,
      usageServerAuth: true,
      usageClientAuth: true,
    })
    expect(result).toHaveProperty('key')
    expect(result).toHaveProperty('certificate_chain')
    expect(result.key).not.toBe('')
    expect(result.certificate_chain.length).toBeGreaterThan(0)
  })

  it('should throw error when unix socket file does not exist', () => {
    // Temporarily remove environment variable to test file check
    const savedEnv = process.env.DSTACK_SIMULATOR_ENDPOINT
    delete process.env.DSTACK_SIMULATOR_ENDPOINT

    expect(() => new DstackClientV0('/non/existent/socket')).toThrow('Unix socket file /non/existent/socket does not exist')

    // Restore environment variable
    if (savedEnv) {
      process.env.DSTACK_SIMULATOR_ENDPOINT = savedEnv
    }
  })

  it('should not throw error for non-unix socket endpoints', () => {
    // Temporarily remove environment variable to test non-unix socket paths
    const savedEnv = process.env.DSTACK_SIMULATOR_ENDPOINT
    delete process.env.DSTACK_SIMULATOR_ENDPOINT

    expect(() => new DstackClientV0('http://localhost:8080')).not.toThrow()
    expect(() => new DstackClientV0('https://example.com')).not.toThrow()

    // Restore environment variable
    if (savedEnv) {
      process.env.DSTACK_SIMULATOR_ENDPOINT = savedEnv
    }
  })

  it('should be able to check if service is reachable', async () => {
    const client = new DstackClientV0()
    const isReachable = await client.isReachable()
    expect(typeof isReachable).toBe('boolean')
  })

  describe('Sign and Verify Methods', () => {
    const client = new DstackClientV0()
    const testData = 'Test message for signing'
    const badData = 'This is not the original message'

    it('should sign with ed25519 and verify', async () => {
      const algorithm = 'ed25519'
      const signResp = await client.sign(algorithm, testData)

      expect(signResp).toHaveProperty('signature')
      expect(signResp).toHaveProperty('signature_chain')
      expect(signResp).toHaveProperty('public_key')
      expect(signResp.signature).toBeInstanceOf(Uint8Array)
      expect(signResp.public_key).toBeInstanceOf(Uint8Array)
      expect(signResp.signature_chain.length).toBeGreaterThan(0) // Should have at least the signature itself
      expect(signResp.signature_chain[0]).toBeInstanceOf(Uint8Array)

      const verifyResp = await client.verify(algorithm, testData, signResp.signature, signResp.public_key)
      expect(verifyResp.valid).toBe(true)

      // Verify failure (bad data)
      const badResp = await client.verify(algorithm, badData, signResp.signature, signResp.public_key)
      expect(badResp.valid).toBe(false)
    })

    it('should sign with secp256k1 and verify', async () => {
      const algorithm = 'secp256k1'
      const signResp = await client.sign(algorithm, testData)

      expect(signResp.signature).toBeInstanceOf(Uint8Array)
      expect(signResp.public_key).toBeInstanceOf(Uint8Array)
      expect(signResp.signature_chain.length).toBeGreaterThan(0)

      expect((await client.verify(algorithm, testData, signResp.signature, signResp.public_key)).valid).toBe(true)
      expect((await client.verify(algorithm, badData, signResp.signature, signResp.public_key)).valid).toBe(false)
    })

    it('should sign with secp256k1_prehashed and verify', async () => {
      const algorithm = 'secp256k1_prehashed'
      const digest = new Uint8Array(crypto.createHash('sha256').update(testData).digest())
      expect(digest.length).toBe(32) // Ensure it's 32 bytes

      const signResp = await client.sign(algorithm, digest)

      expect(signResp.signature).toBeInstanceOf(Uint8Array)
      expect(signResp.public_key).toBeInstanceOf(Uint8Array)

      expect((await client.verify(algorithm, digest, signResp.signature, signResp.public_key)).valid).toBe(true)

      // Verify failure (bad digest)
      const badDigest = new Uint8Array(crypto.createHash('sha256').update(badData).digest())
      expect((await client.verify(algorithm, badDigest, signResp.signature, signResp.public_key)).valid).toBe(false)
    })

    it('should throw error when signing secp256k1_prehashed with incorrect data length', async () => {
      const algorithm = 'secp256k1_prehashed'
      const invalidData = 'This is not 32 bytes'
      await expect(() => client.sign(algorithm, invalidData)).rejects.toThrow('Pre-hashed signing requires a 32-byte digest')

      const invalidBuffer = Buffer.alloc(31) // Not 32 bytes
      await expect(() => client.sign(algorithm, invalidBuffer)).rejects.toThrow('Pre-hashed signing requires a 32-byte digest')
    })

    it('should throw error for unsupported sign algorithm', async () => {
      const algorithm = 'rsa'
      await expect(() => client.sign(algorithm, testData)).rejects.toThrow() // Specific error depends on server impl.
    })
  })

  describe('emitEvent', () => {
    it('should reject an empty event name before reaching the agent', async () => {
      const client = new DstackClientV0()
      await expect(() => client.emitEvent('', 'payload')).rejects.toThrow('Event name cannot be empty')
    })

    it('should surface the agent removal message instead of resolving silently', async () => {
      const client = new DstackClientV0()
      // The 0.6.0 agent always fails this. A caller that gets a resolved promise
      // would believe the event was measured, which is the one wrong answer here.
      await expect(() => client.emitEvent('test-event', 'payload')).rejects.toThrow(
        'EmitEvent was removed in dstack 0.6.0'
      )
    })
  })

  it('should be able to get version', async () => {
    const client = new DstackClientV0()
    const result = await client.version()
    expect(result).toHaveProperty('version')
    expect(result.version).not.toBe('')
  })

  it('should get key with k256 alias producing same result as secp256k1', async () => {
    const client = new DstackClientV0()
    const resultK256 = await client.getKey('/test', 'purpose', 'k256')
    const resultSecp = await client.getKey('/test', 'purpose', 'secp256k1')
    expect(resultK256.key).toEqual(resultSecp.key)
  })

  it('should reject secp256k1_prehashed in getKey', async () => {
    const client = new DstackClientV0()
    await expect(() => client.getKey('/test', 'purpose', 'secp256k1_prehashed')).rejects.toThrow()
  })

  describe('deprecated methods with TappdClient', () => {
    it('should support deprecated deriveKey method with warning', async () => {
      const client = new TappdClient()
      const consoleSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})

      const result = await client.deriveKey('/', 'test')
      expect(result).toHaveProperty('key')
      expect(result).toHaveProperty('certificate_chain')
      expect(consoleSpy).toHaveBeenCalledWith('deriveKey is deprecated, please use getKey instead')

      consoleSpy.mockRestore()
    })

    it('should support deprecated tdxQuote method with warning', async () => {
      const client = new TappdClient()
      const consoleSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})

      const result = await client.tdxQuote('test data')
      expect(result).toHaveProperty('quote')
      expect(result).toHaveProperty('event_log')
      expect(consoleSpy).toHaveBeenCalledWith('tdxQuote is deprecated, please use getQuote instead')

      consoleSpy.mockRestore()
    })

    it('should support tdxQuote with hash algorithm parameter', async () => {
      const client = new TappdClient()
      const consoleSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})

      const result = await client.tdxQuote('test data', 'sha256')
      expect(result).toHaveProperty('quote')
      expect(result).toHaveProperty('event_log')
      expect(consoleSpy).toHaveBeenCalledWith('tdxQuote is deprecated, please use getQuote instead')

      consoleSpy.mockRestore()
    })
  })

  describe('deprecated methods with DstackClientV0', () => {
    it('should throws error in deriveKey method', async () => {
      const client = new DstackClientV0()
      const consoleSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})

      await expect(() => client.deriveKey('/', 'test')).rejects.toThrow('deriveKey is deprecated, please use getKey instead.')

      consoleSpy.mockRestore()
    })

    it('should throws error in tdxQuote method without hash algorithm parameter', async () => {
      const client = new DstackClientV0()
      const consoleSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})

      await expect(() => client.tdxQuote('test data')).rejects.toThrow('tdxQuote only supports raw hash algorithm.')

      consoleSpy.mockRestore()
    })

    it("should throws error in tdxQuote method with hash algorithm parameter other than raw", async () => {
      const client = new DstackClientV0()
      const consoleSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})

      await expect(() => client.tdxQuote('test data', 'sha256')).rejects.toThrow('tdxQuote only supports raw hash algorithm.')

      consoleSpy.mockRestore()
    })

    it('should able to get quote with plain report_data in tdxQuote method with warning', async () => {
      const client = new DstackClientV0()
      const consoleSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})

      const result = await client.tdxQuote('test data', "raw")
      expect(result).toHaveProperty('quote')
      expect(result).toHaveProperty('event_log')
      expect(consoleSpy).toHaveBeenCalledWith('tdxQuote is deprecated, please use getQuote instead')

      consoleSpy.mockRestore()
    })

    it('should throws error in tdxQuote with hash algorithm parameter', async () => {
      const client = new DstackClientV0()
      const consoleSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})

      await expect(() => client.tdxQuote('test data', 'sha256')).rejects.toThrow('tdxQuote only supports raw hash algorithm.')

      consoleSpy.mockRestore()
    })
  })
})
