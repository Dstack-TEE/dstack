import crypto from 'crypto'
import { Keypair } from '@solana/web3.js'

import { type DeriveKeyResponse } from './index'

export function toKeypair(deriveKeyResponse: DeriveKeyResponse) {
  try {
    // Get supported hash algorithm by `openssl list -digest-algorithms`, but it's not guaranteed to be supported by node.js
    const buf = crypto.createHash('sha256').update(deriveKeyResponse.asUint8Array()).digest()
    return Keypair.fromSeed(buf)
  } catch (err) {
    throw new Error('toKeypair: missing sha256 support, please upgrade your openssl and node.js')
  }
}