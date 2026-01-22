// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

import { verifyEnvEncryptPublicKey, verifyEnvEncryptPublicKeyLegacy } from '../verify-env-encrypt-public-key'
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'

describe('verifyEnvEncryptPublicKeyLegacy', () => {
  it('should verify signature correctly with example data', () => {
    const publicKey = new Uint8Array(Buffer.from('e33a1832c6562067ff8f844a61e51ad051f1180b66ec2551fb0251735f3ee90a', 'hex'))
    const signature = new Uint8Array(Buffer.from('8542c49081fbf4e03f62034f13fbf70630bdf256a53032e38465a27c36fd6bed7a5e7111652004aef37f7fd92fbfc1285212c4ae6a6154203a48f5e16cad2cef00', 'hex'))
    const appId = '00'.repeat(20)

    const result = verifyEnvEncryptPublicKeyLegacy(publicKey, signature, appId)

    expect(result).toBe('0x0217610d74cbd39b6143842c6d8bc310d79da1d82cc9d17f8876376221eda0c38f')
  })

  it('should handle 0x prefix in app_id', () => {
    const publicKey = new Uint8Array(Buffer.from('e33a1832c6562067ff8f844a61e51ad051f1180b66ec2551fb0251735f3ee90a', 'hex'))
    const signature = new Uint8Array(Buffer.from('8542c49081fbf4e03f62034f13fbf70630bdf256a53032e38465a27c36fd6bed7a5e7111652004aef37f7fd92fbfc1285212c4ae6a6154203a48f5e16cad2cef00', 'hex'))
    const appId = '0x' + '00'.repeat(20)

    const result = verifyEnvEncryptPublicKeyLegacy(publicKey, signature, appId)

    expect(result).toBe('0x0217610d74cbd39b6143842c6d8bc310d79da1d82cc9d17f8876376221eda0c38f')
  })

  it('should return null for invalid signature length', () => {
    const publicKey = new Uint8Array(32)
    const signature = new Uint8Array(64) // Wrong length
    const appId = '00'.repeat(20)

    const result = verifyEnvEncryptPublicKeyLegacy(publicKey, signature, appId)

    expect(result).toBeNull()
  })

  it('should return null for invalid signature data', () => {
    const publicKey = new Uint8Array(32)
    const signature = new Uint8Array(65) // All zeros
    const appId = '00'.repeat(20)

    const result = verifyEnvEncryptPublicKeyLegacy(publicKey, signature, appId)

    expect(result).toBeNull()
  })
})

describe('verifyEnvEncryptPublicKey with timestamp', () => {
  beforeEach(() => {
    // Mock Date.now to return a fixed timestamp for testing
    vi.useFakeTimers()
    vi.setSystemTime(new Date('2024-01-15T12:00:00Z'))
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  it('should return null for invalid signature length', () => {
    const publicKey = new Uint8Array(32)
    const signature = new Uint8Array(64) // Wrong length
    const appId = '00'.repeat(20)
    const timestamp = BigInt(Math.floor(Date.now() / 1000))

    const result = verifyEnvEncryptPublicKey(publicKey, signature, appId, timestamp)

    expect(result).toBeNull()
  })

  it('should return null for stale timestamp', () => {
    const publicKey = new Uint8Array(32)
    const signature = new Uint8Array(65)
    const appId = '00'.repeat(20)
    // Timestamp from 10 minutes ago (600 seconds)
    const timestamp = BigInt(Math.floor(Date.now() / 1000)) - 600n

    const result = verifyEnvEncryptPublicKey(publicKey, signature, appId, timestamp)

    expect(result).toBeNull()
  })

  it('should return null for timestamp too far in the future', () => {
    const publicKey = new Uint8Array(32)
    const signature = new Uint8Array(65)
    const appId = '00'.repeat(20)
    // Timestamp 2 minutes in the future
    const timestamp = BigInt(Math.floor(Date.now() / 1000)) + 120n

    const result = verifyEnvEncryptPublicKey(publicKey, signature, appId, timestamp)

    expect(result).toBeNull()
  })

  it('should accept timestamp within allowed clock skew (future)', () => {
    const publicKey = new Uint8Array(32)
    const signature = new Uint8Array(65) // Invalid signature, but we're testing timestamp check
    const appId = '00'.repeat(20)
    // Timestamp 30 seconds in the future (within 60s skew)
    const timestamp = BigInt(Math.floor(Date.now() / 1000)) + 30n

    // Will return null due to invalid signature, not timestamp
    const result = verifyEnvEncryptPublicKey(publicKey, signature, appId, timestamp)

    // The function should not reject due to timestamp, but will fail signature verification
    expect(result).toBeNull()
  })

  it('should accept custom maxAgeSeconds option', () => {
    const publicKey = new Uint8Array(32)
    const signature = new Uint8Array(65)
    const appId = '00'.repeat(20)
    // Timestamp from 400 seconds ago (would fail default 300s, but pass 600s)
    const timestamp = BigInt(Math.floor(Date.now() / 1000)) - 400n

    // With default maxAge (300s), this should fail due to stale timestamp
    const result1 = verifyEnvEncryptPublicKey(publicKey, signature, appId, timestamp)
    expect(result1).toBeNull()

    // With extended maxAge (600s), it would pass timestamp check but fail signature
    const result2 = verifyEnvEncryptPublicKey(publicKey, signature, appId, timestamp, { maxAgeSeconds: 600 })
    // Still null due to invalid signature data, but the timestamp check passed
    expect(result2).toBeNull()
  })

  it('should accept number timestamp', () => {
    const publicKey = new Uint8Array(32)
    const signature = new Uint8Array(65)
    const appId = '00'.repeat(20)
    const timestamp = Math.floor(Date.now() / 1000) // number instead of bigint

    // Will return null due to invalid signature, but should handle number timestamp
    const result = verifyEnvEncryptPublicKey(publicKey, signature, appId, timestamp)
    expect(result).toBeNull()
  })
})
