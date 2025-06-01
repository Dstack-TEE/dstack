import crypto from 'crypto'
import { privateKeyToAccount } from 'viem/accounts'

import { type DeriveKeyResponse } from './index'

export function toViemAccount(deriveKeyResponse: DeriveKeyResponse) {
  try {
    // Get supported hash algorithm by `openssl list -digest-algorithms`, but it's not guaranteed to be supported by node.js
    const hex = crypto.createHash('sha256').update(deriveKeyResponse.asUint8Array()).digest('hex')
    return privateKeyToAccount(`0x${hex}`)
  } catch (err) {
    throw new Error('toViemAccount: missing sha256 support, please upgrade your openssl and node.js')
  }
}
