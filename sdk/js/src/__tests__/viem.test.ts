import { expect, describe, it } from 'vitest'
import { TappdClient } from '../index'
import { toViemAccount } from '../viem'

describe('viem support', () => {
  it('should able to get account from deriveKey', async () => {
    const client = new TappdClient()
    const result = await client.deriveKey('/', 'test')
    const account =  toViemAccount(result)

    expect(account.source).toBe('privateKey')
    expect(typeof account.sign).toBe('function')
    expect(typeof account.signMessage).toBe('function')
  })
})
