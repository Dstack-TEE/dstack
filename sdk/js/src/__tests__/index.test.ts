import { expect, describe, it } from 'vitest'
import { TappdClient } from '../index'

// Test PEM key for cross-platform validation
const TEST_PEM_KEY = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgsxWvvkVZix6DYyFP
aS1yz5RZLOSiiHLx8mp7axE6Whuha0QDQgAED/3OrGv33eegcOrd8WYJWLMbDJQc
TJaeKpGauQSXugPjuwnq4a2mCUE221wXaGWAXBtH4eiHiumFe2eFzeDACA==
-----END PRIVATE KEY-----`

describe('TappdClient', () => {
  it('should able to derive key', async () => {
    const client = new TappdClient()
    const result = await client.deriveKey('/', 'test')
    expect(result).toHaveProperty('key')
    expect(result).toHaveProperty('certificate_chain')
  })

  it('should able to request tdx quote', async () => {
    const client = new TappdClient()
    // You can put computation result as report data to tdxQuote. NOTE: it should serializable by JSON.stringify
    const result = await client.tdxQuote('some data or anything can be call by toJSON')
    expect(result).toHaveProperty('quote')
    expect(result).toHaveProperty('event_log')
    expect(result.quote.substring(0, 2)).toBe('0x')
    expect(result.event_log.substring(0, 1) === '{')
    expect(() => JSON.parse(result.event_log)).not.toThrowError()
    expect(result.replayRtmrs().length).toBe(4)
  })

  it('should able to get derive key result as uint8array', async () => {
    const client = new TappdClient()
    const result = await client.deriveKey('/', 'test')
    const key = result.asUint8Array()
    expect(key).toBeInstanceOf(Uint8Array)
  })

  it('should compare asUint8Array and asUint8Array with length', () => {
    const client = new TappdClient()
    const key = {
      key: TEST_PEM_KEY,
      certificate_chain: [],
      asUint8Array: (length?: number) => {
        const content = TEST_PEM_KEY.replace(/-----BEGIN PRIVATE KEY-----/, '')
          .replace(/-----END PRIVATE KEY-----/, '')
          .replace(/\n/g, '');
        const binaryDer = atob(content)
        const max_length = length || binaryDer.length
        const result = new Uint8Array(max_length)
        for (let i = 0; i < max_length; i++) {
          result[i] = binaryDer.charCodeAt(i)
        }
        return result
      }
    }

    const full = key.asUint8Array()
    const key32 = key.asUint8Array(32)
    expect(key32.length).toBe(32)
    expect(key32.length).not.eq(full.length)
  })

  it('should validate asUint8Array output with known PEM key', () => {
    // Create a mock DeriveKeyResponse with known PEM key
    const mockResult = {
      key: TEST_PEM_KEY,
      certificate_chain: [],
      asUint8Array: (length?: number) => {
        // Import the x509key_to_uint8array function logic
        const content = TEST_PEM_KEY.replace(/-----BEGIN PRIVATE KEY-----/, '')
          .replace(/-----END PRIVATE KEY-----/, '')
          .replace(/\n/g, '');
        const binaryDer = atob(content)
        const max_length = length || binaryDer.length
        const result = new Uint8Array(max_length)
        for (let i = 0; i < max_length; i++) {
          result[i] = binaryDer.charCodeAt(i)
        }
        return result
      }
    }

    // Test full length conversion
    const resultFull = mockResult.asUint8Array()
    expect(resultFull).toBeInstanceOf(Uint8Array)
    expect(resultFull.length).toBe(139)  // Expected length for this key

    // Test with specific length
    const result32 = mockResult.asUint8Array(32)
    expect(result32).toBeInstanceOf(Uint8Array)
    expect(result32.length).toBe(32)

    // Verify expected hex output (should match Python)
    const expectedPrefix = "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b02"
    const result32Hex = Array.from(result32).map(b => b.toString(16).padStart(2, '0')).join('')
    expect(result32Hex).toBe(expectedPrefix)

    // Test that longer result starts with the same prefix
    const resultFullPrefix = Array.from(resultFull.slice(0, 32)).map(b => b.toString(16).padStart(2, '0')).join('')
    expect(resultFullPrefix).toBe(expectedPrefix)

    // Expected full hex for this specific key (should match Python)
    const expectedFullHex = ("308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b02" +
                           "01010420b315afbe45598b1e8363214f692d72cf94592ce4a28872f1f26a7b6b11" +
                           "3a5a1ba16b44034200040ffdceac6bf7dde7a070eaddf1660958b31b0c941c4c96" +
                           "9e2a919ab90497ba03e3bb09eae1ada6094136db5c176865805c1b47e1e8878ae9" +
                           "857b6785cde0c008")
    const resultFullHex = Array.from(resultFull).map(b => b.toString(16).padStart(2, '0')).join('')
    expect(resultFullHex).toBe(expectedFullHex)
  })

  it('should validate deprecated vs secure API differences', async () => {
    // Import the functions for testing
    const { toKeypair, toKeypairSecure } = await import('../solana')
    const { toViemAccount, toViemAccountSecure } = await import('../viem')

    const mockResult = {
      key: TEST_PEM_KEY,
      certificate_chain: [],
      asUint8Array: (length?: number) => {
        const content = TEST_PEM_KEY.replace(/-----BEGIN PRIVATE KEY-----/, '')
          .replace(/-----END PRIVATE KEY-----/, '')
          .replace(/\n/g, '');
        const binaryDer = atob(content)
        const max_length = length || binaryDer.length
        const result = new Uint8Array(max_length)
        for (let i = 0; i < max_length; i++) {
          result[i] = binaryDer.charCodeAt(i)
        }
        return result
      }
    }

    // Test that deprecated APIs work as before (using first 32 bytes)
    const deprecatedSolanaKeypair = toKeypair(mockResult)
    const secureKeypair = toKeypairSecure(mockResult)
    
    // These should be different because deprecated uses first 32 bytes, secure uses SHA256 hash
    expect(deprecatedSolanaKeypair.publicKey.toString()).not.toBe(secureKeypair.publicKey.toString())

    const deprecatedViemAccount = toViemAccount(mockResult)
    const secureViemAccount = toViemAccountSecure(mockResult)
    
    // These should be different because deprecated uses first 32 bytes, secure uses SHA256 hash
    expect(deprecatedViemAccount.address).not.toBe(secureViemAccount.address)

    // Verify deprecated API actually uses first 32 bytes (original behavior)
    const first32Bytes = mockResult.asUint8Array(32)
    const expectedSolanaKeypair = require('@solana/web3.js').Keypair.fromSeed(first32Bytes)
    expect(deprecatedSolanaKeypair.publicKey.toString()).toBe(expectedSolanaKeypair.publicKey.toString())
  })

  it('should able set quote hash_algorithm', async () => {
    const client = new TappdClient()
    const result = await client.tdxQuote('pure string', 'raw')
    expect(result).toHaveProperty('quote')
    expect(result).toHaveProperty('replayRtmrs')
  })

  it('should able to request tdx quote', async () => {
    const client = new TappdClient()
    // You can put computation result as report data to tdxQuote. NOTE: it should serializable by JSON.stringify
    const result = await client.tdxQuote('some data or anything can be call by toJSON')
    expect(result).toHaveProperty('quote')
    expect(result).toHaveProperty('event_log')
    expect(result.quote.substring(0, 2)).toBe('0x')
    expect(result.event_log.substring(0, 1) === '{')
    expect(() => JSON.parse(result.event_log)).not.toThrowError()
    expect(result.replayRtmrs().length).toBe(4)
  })

  it('should able to get derive key result as uint8array', async () => {
    const client = new TappdClient()
    const result = await client.deriveKey('/', 'test')
    const key = result.asUint8Array()
    expect(key).toBeInstanceOf(Uint8Array)
  })

  it('should able to get derive key result as uint8array with specified length', async () => {
    const client = new TappdClient()
    const result = await client.deriveKey('/', 'test')
    const full = result.asUint8Array()
    const key = result.asUint8Array(32)
    expect(full).toBeInstanceOf(Uint8Array)
    expect(key).toBeInstanceOf(Uint8Array)
    expect(key.length).toBe(32)
    expect(key.length).not.eq(full.length)
  })

  it('should throw error on report_data large then 64 characters and using raw hash_algorithm', async () => {
    const client = new TappdClient()
    expect(() => client.tdxQuote('0'.padEnd(65, 'x'), 'raw')).rejects.toThrow()
  })

  it('should throw error on report_data large then 128 bytes and using raw hash_algorithm', async () => {
    const client = new TappdClient()
    expect(() => client.tdxQuote(Buffer.alloc(65), 'raw')).rejects.toThrow()
  })

  it('should throw error on report_data large then 128 bytes and using raw hash_algorithm', async () => {
    const client = new TappdClient()
    const input = new Uint8Array(65).fill(0)
    expect(() => client.tdxQuote(input, 'raw')).rejects.toThrow()
  })

  it('should verify secure APIs use SHA256 hash of complete key material', async () => {
    const { toKeypairSecure } = await import('../solana')
    const { toViemAccountSecure } = await import('../viem')
    const crypto = require('crypto')

    const mockResult = {
      key: TEST_PEM_KEY,
      certificate_chain: [],
      asUint8Array: (length?: number) => {
        const content = TEST_PEM_KEY.replace(/-----BEGIN PRIVATE KEY-----/, '')
          .replace(/-----END PRIVATE KEY-----/, '')
          .replace(/\n/g, '');
        const binaryDer = atob(content)
        const max_length = length || binaryDer.length
        const result = new Uint8Array(max_length)
        for (let i = 0; i < max_length; i++) {
          result[i] = binaryDer.charCodeAt(i)
        }
        return result
      }
    }

    // Test secure Solana API
    const secureKeypair = toKeypairSecure(mockResult)
    const expectedHash = crypto.createHash('sha256').update(mockResult.asUint8Array()).digest()
    const expectedSolanaKeypair = require('@solana/web3.js').Keypair.fromSeed(expectedHash)
    expect(secureKeypair.publicKey.toString()).toBe(expectedSolanaKeypair.publicKey.toString())

    // Test secure Viem API
    const secureViemAccount = toViemAccountSecure(mockResult)
    const expectedHex = crypto.createHash('sha256').update(mockResult.asUint8Array()).digest('hex')
    const { privateKeyToAccount } = require('viem/accounts')
    const expectedViemAccount = privateKeyToAccount(`0x${expectedHex}`)
    expect(secureViemAccount.address).toBe(expectedViemAccount.address)
  })
})
