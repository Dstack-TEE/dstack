// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

import http from 'http'
import type { AddressInfo } from 'net'
import { describe, expect, it } from 'vitest'
import { DstackClientV0, TappdClient } from '../client-v0'
import { DstackClient } from '../client-v1'
import { encryptEnvVars } from '../encrypt-env-vars'
import { send_rpc_request } from '../send-rpc-request'

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

describe('tappd routes and transport', () => {
  it('uses tappd routes and rejects unsupported methods without requests', async () => {
    const paths: string[] = []
    const server = http.createServer((req, res) => {
      paths.push(req.url!)
      res.end(JSON.stringify(req.url!.endsWith('Info') ? { tcb_info: '{}' } : { version: '1', rev: 'a' }))
    })
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
    try {
      const client = new TappdClient(`http://127.0.0.1:${(server.address() as AddressInfo).port}`)
      await client.info(); await client.version()
      for (const call of [() => client.getKey(), () => client.getQuote('x'), () => client.getTlsKey(), () => client.attest('x'), () => client.sign('x', 'x'), () => client.verify('x', 'x', 'x', 'x'), () => client.emitEvent('x', 'x')]) {
        await expect(call()).rejects.toThrow(/DstackClient.*dstack\.sock/)
      }
      expect(paths).toEqual(['/prpc/Tappd.Info', '/prpc/Tappd.Version'])
    } finally { await new Promise<void>(resolve => server.close(() => resolve())) }
  })

  it('rejects a truncated response promptly', async () => {
    const server = http.createServer((_req, res) => {
      res.writeHead(200, { 'Content-Length': '100' }); res.write('{'); setTimeout(() => res.socket?.destroy(), 20)
    })
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
    try {
      const start = Date.now()
      await expect(send_rpc_request(`http://127.0.0.1:${(server.address() as AddressInfo).port}`, '/', '{}', 2000)).rejects.toThrow()
      expect(Date.now() - start).toBeLessThan(1000)
    } finally { await new Promise<void>(resolve => server.close(() => resolve())) }
  })

  it('honors client timeouts', async () => {
    const server = http.createServer(() => {})
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
    try {
      const endpoint = `http://127.0.0.1:${(server.address() as AddressInfo).port}`
      for (const client of [new DstackClient(endpoint, { timeoutMs: 40 }), new TappdClient(endpoint, { timeoutMs: 40 })]) {
        const start = Date.now()
        await expect(client.version()).rejects.toThrow('request timed out')
        expect(Date.now() - start).toBeLessThan(1000)
      }
    } finally { server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())) }
  })

  it.each(['1', 'zz'.repeat(32), '11'.repeat(31) + '1g'])('rejects malformed hex %s', async hex => {
    await expect(encryptEnvVars([], hex)).rejects.toThrow(/hex/)
  })
})

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
