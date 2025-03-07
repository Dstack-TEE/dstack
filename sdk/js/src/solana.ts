import { type DeriveKeyResponse } from './index'
import { Keypair } from '@solana/web3.js'

export function toKeypair(deriveKeyResponse: DeriveKeyResponse) {
  const bytes = deriveKeyResponse.asUint8Array(32)
  return Keypair.fromSeed(bytes)
}