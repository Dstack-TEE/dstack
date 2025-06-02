import { expect, describe, it } from 'vitest'
import { DstackClient } from '../index'

describe('DstackClient', () => {
  it('should able to derive key', async () => {
    const client = new DstackClient()
    const result = await client.getKey('/', 'test')
    expect(result).toHaveProperty('key')
    expect(result).toHaveProperty('signature_chain')
  })

  it('should able to request tdx quote', async () => {
    const client = new DstackClient()
    // You can put computation result as report data to tdxQuote. NOTE: it should serializable by JSON.stringify
    const result = await client.getQuote('some data or anything can be call by toJSON')
    expect(result).toHaveProperty('quote')
    expect(result).toHaveProperty('event_log')
    expect(result.event_log.substring(0, 1) === '{')
    expect(() => JSON.parse(result.event_log)).not.toThrowError()
    expect(result.replayRtmrs().length).toBe(4)
  })

  it('should able to get derive key result as uint8array', async () => {
    const client = new DstackClient()
    const result = await client.getKey('/', 'test')
    expect(result.key).toBeInstanceOf(Uint8Array)
  })

  it('should able to get derive key result as uint8array with specified length', async () => {
    const client = new DstackClient()
    const result = await client.getTlsKey()
    const full = result.asUint8Array()
    const key = result.asUint8Array(32)
    expect(full).toBeInstanceOf(Uint8Array)
    expect(key).toBeInstanceOf(Uint8Array)
    expect(key.length).toBe(32)
    expect(key.length).not.eq(full.length)
  })

  it('should be able to get quote', async () => {
    const client = new DstackClient()
    const result = await client.getQuote('pure string')
  })

  it('should throw error on report_data large then 64 characters', async () => {
    const client = new DstackClient()
    await expect(() => client.getQuote('0'.padEnd(65, 'x'))).rejects.toThrow()
  })

  it('should throw error on report_data large then 64 bytes', async () => {
    const client = new DstackClient()
    await expect(() => client.getQuote(Buffer.alloc(65))).rejects.toThrow()
  })

  it('should throw error on report_data large then 128 bytes', async () => {
    const client = new DstackClient()
    const input = new Uint8Array(65).fill(0)
    await expect(() => client.getQuote(input)).rejects.toThrow()
  })

  it('should be able to get info', async () => {
    const client = new DstackClient()
    const result = await client.info()
    expect(result).toHaveProperty('app_id')
    expect(result).toHaveProperty('instance_id')
    expect(result).toHaveProperty('tcb_info')
    expect(result.app_id).not.toBe('')
    expect(result.instance_id).not.toBe('')
    expect(result.tcb_info).not.toBe('')
  })

  it('should be able to decode tcb info', async () => {
    const client = new DstackClient()
    const result = await client.info()
    const tcbInfo = result.tcb_info
    expect(tcbInfo).toHaveProperty('rtmr0')
    expect(tcbInfo).toHaveProperty('rtmr1')
    expect(tcbInfo).toHaveProperty('rtmr2')
    expect(tcbInfo).toHaveProperty('rtmr3')
    expect(tcbInfo).toHaveProperty('event_log')
    expect(tcbInfo.rtmr0).not.toBe('')
    expect(tcbInfo.rtmr1).not.toBe('')
    expect(tcbInfo.rtmr2).not.toBe('')
    expect(tcbInfo.rtmr3).not.toBe('')
    expect(tcbInfo.event_log.length).toBeGreaterThan(0)
  })

  it('should be able to get TLS key with alt names', async () => {
    const client = new DstackClient()
    const altNames = ['localhost', '127.0.0.1']
    const result = await client.getTlsKey({
      subject: 'test-subject',
      altNames,
      usageRaTls: true,
      usageServerAuth: true,
      usageClientAuth: true,
    })
    expect(result).toHaveProperty('key')
    expect(result).toHaveProperty('certificate_chain')
    expect(result.key).not.toBe('')
    expect(result.certificate_chain.length).toBeGreaterThan(0)
  })
})
