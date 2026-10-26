// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

import http from 'http'
import type { AddressInfo } from 'net'
import { describe, expect, it } from 'vitest'
import { DstackClientV0 } from '../client-v0'

async function withAgentAnswering(body: unknown, fn: (client: DstackClientV0) => Promise<void>) {
  const server = http.createServer((_req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/json' })
    res.end(JSON.stringify(body))
  })
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', () => resolve()))
  try {
    const { port } = server.address() as AddressInfo
    await fn(new DstackClientV0(`http://127.0.0.1:${port}`))
  } finally {
    await new Promise<void>(resolve => server.close(() => resolve()))
  }
}

const KEY = '11'.repeat(32)
const CHAIN = ['aa'.repeat(64)]

describe('DstackClientV0.getKey', () => {
  it.each([
    ['valid prefix followed by junk', { key: KEY + 'GARBAGE', signature_chain: CHAIN }, /malformed key/],
    ['non-hex key', { key: 'zz'.repeat(32), signature_chain: CHAIN }, /malformed key/],
    ['odd-length key', { key: '0011222', signature_chain: CHAIN }, /malformed key/],
    ['absent key', { signature_chain: CHAIN }, /no key/],
    ['non-hex chain link', { key: KEY, signature_chain: ['aa', 'zz'] }, /signature_chain\[1\]/],
    ['null signature_chain', { key: KEY, signature_chain: null }, /signature_chain/],
    ['absent signature_chain', { key: KEY }, /signature_chain/],
  ])('rejects %s', async (_, body, error) => {
    await withAgentAnswering(body, client => expect(client.getKey('d')).rejects.toThrow(error))
  })

  it('accepts a well-formed response', async () => {
    await withAgentAnswering({ key: KEY, signature_chain: CHAIN }, async client => {
      const result = await client.getKey('d')
      expect(result.key).toEqual(new Uint8Array(Buffer.from(KEY, 'hex')))
      expect(result.signature_chain).toHaveLength(1)
    })
  })

  it('reads an empty key as zero bytes', async () => {
    await withAgentAnswering({ key: '', signature_chain: [] }, async client => {
      expect((await client.getKey('d')).key).toEqual(new Uint8Array(0))
    })
  })
})

describe('DstackClientV0.info', () => {
  const base = {
    app_id: 'aa'.repeat(32),
    instance_id: 'cc'.repeat(32),
    app_cert: 'x',
    app_name: 'demo',
    device_id: 'dd'.repeat(32),
    key_provider_info: '{}',
    compose_hash: 'bb'.repeat(32),
  }

  it.each([
    ['non-string tcb_info', { ...base, tcb_info: 42 }],
    ['absent tcb_info', base],
    ['unparseable tcb_info', { ...base, tcb_info: '{' }],
  ])('rejects %s', async (_, body) => {
    await withAgentAnswering(body, client => expect(client.info()).rejects.toThrow(/tcb_info/))
  })

  it('parses a well-formed tcb_info', async () => {
    await withAgentAnswering({ ...base, tcb_info: JSON.stringify({ mrtd: '00'.repeat(48) }) }, async client => {
      expect((await client.info()).tcb_info.mrtd).toBe('00'.repeat(48))
    })
  })
})
