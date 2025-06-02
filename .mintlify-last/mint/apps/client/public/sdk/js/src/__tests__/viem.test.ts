import { expect, describe, it } from 'vitest'
import { DstackClient } from '../index'
import { toViemAccount } from '../viem'

describe('viem support', () => {
  it('should able to get account from getKey', async () => {
    const client = new DstackClient()
    const result = await client.getKey('/', 'test')
    const account = toViemAccount(result)

    expect(account.source).toBe('privateKey')
    expect(typeof account.sign).toBe('function')
    expect(typeof account.signMessage).toBe('function')
  })
})
