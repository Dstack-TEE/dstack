// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

import { verifyEnvEncryptPublicKey } from '../verify-env-encrypt-public-key'
import { describe, it, expect } from 'vitest'

describe('verifySignature', () => {
  it('should verify signature correctly with example data', () => {
    const publicKey = new Uint8Array(Buffer.from('e33a1832c6562067ff8f844a61e51ad051f1180b66ec2551fb0251735f3ee90a', 'hex'))
    const signature = new Uint8Array(Buffer.from('8542c49081fbf4e03f62034f13fbf70630bdf256a53032e38465a27c36fd6bed7a5e7111652004aef37f7fd92fbfc1285212c4ae6a6154203a48f5e16cad2cef00', 'hex'))
    const appId = '00'.repeat(20)
    
    const result = verifyEnvEncryptPublicKey(publicKey, signature, appId)
    
    expect(result).toBe('0x0217610d74cbd39b6143842c6d8bc310d79da1d82cc9d17f8876376221eda0c38f')
  })

  it('should handle 0x prefix in app_id', () => {
    const publicKey = new Uint8Array(Buffer.from('e33a1832c6562067ff8f844a61e51ad051f1180b66ec2551fb0251735f3ee90a', 'hex'))
    const signature = new Uint8Array(Buffer.from('8542c49081fbf4e03f62034f13fbf70630bdf256a53032e38465a27c36fd6bed7a5e7111652004aef37f7fd92fbfc1285212c4ae6a6154203a48f5e16cad2cef00', 'hex'))
    const appId = '0x' + '00'.repeat(20)
    
    const result = verifyEnvEncryptPublicKey(publicKey, signature, appId)
    
    expect(result).toBe('0x0217610d74cbd39b6143842c6d8bc310d79da1d82cc9d17f8876376221eda0c38f')
  })

  it('should return null for invalid signature length', () => {
    const publicKey = new Uint8Array(32)
    const signature = new Uint8Array(64) // Wrong length
    const appId = '00'.repeat(20)
    
    const result = verifyEnvEncryptPublicKey(publicKey, signature, appId)
    
    expect(result).toBeNull()
  })

  it('should return null for invalid signature data', () => {
    const publicKey = new Uint8Array(32)
    const signature = new Uint8Array(65) // All zeros
    const appId = '00'.repeat(20)
    
    const result = verifyEnvEncryptPublicKey(publicKey, signature, appId)
    
    expect(result).toBeNull()
  })
}) 