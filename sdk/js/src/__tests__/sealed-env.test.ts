// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest'
import { Aes256Gcm, CipherSuite, HkdfSha256 } from '@hpke/core'
import { DhkemX25519HkdfSha256 } from '@hpke/dhkem-x25519'
import { secp256k1 } from '@noble/curves/secp256k1'
import { keccak_256 } from '@noble/hashes/sha3'
import { sealEnv } from '../seal-env'
import { verifySealedEnvPublicKey } from '../verify-env-encrypt-public-key'

describe('sealed env', () => {
  it('encrypts an HPKE envelope bound to the epoch', async () => {
    const suite = new CipherSuite({ kem: new DhkemX25519HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes256Gcm() })
    const keys = await suite.kem.generateKeyPair()
    const publicKey = Buffer.from(await suite.kem.serializePublicKey(keys.publicKey)).toString('hex')
    const env = [{ key: 'MESSAGE', value: 'hello 世界' }]
    const sealed = JSON.parse(await sealEnv(env, publicKey, 3))
    expect(sealed.version).toBe(1)
    expect(sealed.root_epoch).toBe(3)
    const params = { recipientKey: keys.privateKey, enc: Buffer.from(sealed.enc, 'base64'), info: new TextEncoder().encode('dstack-sealed-env-v1:3') }
    const ct = Buffer.from(sealed.ciphertext, 'base64')
    const plaintext = await suite.open(params, ct)
    expect(JSON.parse(new TextDecoder().decode(plaintext))).toEqual({ env })
    await expect(suite.open({ ...params, info: new TextEncoder().encode('dstack-sealed-env-v1:4') }, ct)).rejects.toThrow()
  })

  it('binds the public-key signature to app, epoch, key and timestamp', () => {
    const signer = new Uint8Array(32).fill(7)
    const app = Buffer.alloc(20, 1)
    const publicKey = Buffer.alloc(32, 2)
    const epoch = Buffer.alloc(4)
    epoch.writeUInt32BE(3)
    const timestamp = BigInt(Math.floor(Date.now() / 1000))
    const ts = Buffer.alloc(8)
    ts.writeBigUInt64BE(timestamp)
    const digest = keccak_256(Buffer.concat([Buffer.from('dstack-sealed-env-pubkey-v1:'), app, epoch, publicKey, ts]))
    const signed = secp256k1.sign(digest, signer)
    const signature = Uint8Array.from([...signed.toCompactRawBytes(), signed.recovery])
    const trusted = '0x' + Buffer.from(secp256k1.getPublicKey(signer, true)).toString('hex')
    expect(verifySealedEnvPublicKey(publicKey, signature, app.toString('hex'), 3, timestamp)).toBe(trusted)
    expect(verifySealedEnvPublicKey(publicKey, signature, app.toString('hex'), 4, timestamp)).not.toBe(trusted)
    expect(verifySealedEnvPublicKey(publicKey, signature, app.toString('hex'), 3, timestamp - 1000n)).toBeNull()
    expect(verifySealedEnvPublicKey(publicKey, signature, '01', 3, timestamp)).toBeNull()
  })

  it.each([-1, 2 ** 32, 0.5, NaN])('rejects invalid epoch %s', async (epoch) => {
    await expect(sealEnv([], '', epoch)).rejects.toThrow('uint32')
  })
})
