import { expect, describe, it } from 'vitest'
import { Keypair } from '@solana/web3.js'

import { DstackClient } from '../index'
import { toKeypair } from '../solana'

describe('solana support', () => {
  it('should able to get keypair from deriveKey', async () => {
    const client = new DstackClient()
    const result = await client.getKey('/', 'test')
    const keypair = toKeypair(result)
    expect(keypair).toBeInstanceOf(Keypair)
    console.log(keypair.publicKey.toBase58())
  })
})