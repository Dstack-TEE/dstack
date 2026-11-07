// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

import { Aes256Gcm, CipherSuite, HkdfSha256 } from '@hpke/core'
import { DhkemX25519HkdfSha256 } from '@hpke/dhkem-x25519'
import type { EnvVar } from './encrypt-env-vars'

const suite = new CipherSuite({
  kem: new DhkemX25519HkdfSha256(),
  kdf: new HkdfSha256(),
  aead: new Aes256Gcm(),
})

function hexToBytes(hex: string): Uint8Array {
  const value = hex.replace(/^0x/i, '')
  if (!/^[0-9a-f]*$/i.test(value) || value.length % 2 !== 0) {
    throw new Error('invalid sealed env public key')
  }
  return Uint8Array.from(value.match(/../g) ?? [], (byte) => parseInt(byte, 16))
}

function base64(bytes: ArrayBuffer): string {
  return btoa(Array.from(new Uint8Array(bytes), (byte) => String.fromCharCode(byte)).join(''))
}

/** Encrypt environment variables into the versioned `.sealed-env` envelope. */
export async function sealEnv(
  envs: EnvVar[],
  publicKeyHex: string,
  rootEpoch: number,
  appEpoch = 0,
): Promise<string> {
  if (!Number.isInteger(rootEpoch) || rootEpoch < 0 || rootEpoch > 0xffffffff) {
    throw new Error('rootEpoch must be a uint32')
  }
  if (!Number.isInteger(appEpoch) || appEpoch < 0 || appEpoch > 0xffffffff) throw new Error('appEpoch must be a uint32')
  const publicKey = await suite.kem.deserializePublicKey(hexToBytes(publicKeyHex))
  const info = new TextEncoder().encode(`dstack-sealed-env-v1:${rootEpoch}:${appEpoch}`)
  const plaintext = new TextEncoder().encode(JSON.stringify({ env: envs }))
  const { enc, ct } = await suite.seal({ recipientPublicKey: publicKey, info }, plaintext)
  return JSON.stringify({
    version: 1,
    root_epoch: rootEpoch,
    app_epoch: appEpoch,
    enc: base64(enc),
    ciphertext: base64(ct),
  })
}
