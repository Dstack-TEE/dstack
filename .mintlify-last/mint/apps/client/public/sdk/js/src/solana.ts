import { type GetKeyResponse } from './index'
import { Keypair } from '@solana/web3.js'

export function toKeypair(keyResponse: GetKeyResponse) {
  return Keypair.fromSeed(keyResponse.key)
}